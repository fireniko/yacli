use std::collections::BTreeMap;
use std::fs;

use url::Url;

use crate::error::{Result, YacliError};
use crate::model::{AccountConfig, AccountsFile};
use crate::net_policy::{
    CALDAV_HOSTS, DISK_API_HOSTS, IMAP_HOSTS, IMAP_PORT, SMTP_HOSTS, SMTP_PORT,
    test_overrides_enabled, validate_https_url_strict, validate_mail_endpoint_strict,
};
use crate::paths::accounts_path;
use crate::persist::write_config_file;

#[derive(Clone, Debug)]
pub struct AccountStore {
    pub file: AccountsFile,
}

impl AccountStore {
    pub fn load() -> Result<Self> {
        let path = accounts_path()?;
        if !path.exists() {
            return Ok(Self {
                file: AccountsFile::default(),
            });
        }

        let content = fs::read_to_string(path)?;
        let file = toml::from_str::<AccountsFile>(&content)?;
        for (name, account) in &file.accounts {
            let errors = endpoint_errors(account, !test_overrides_enabled());
            if !errors.is_empty() {
                return Err(YacliError::Config(format!(
                    "account `{name}` uses endpoints outside the Yandex allow-list: {}",
                    errors.join("; ")
                )));
            }
        }
        Ok(Self { file })
    }

    pub fn save(&self) -> Result<()> {
        let path = accounts_path()?;
        let content = toml::to_string_pretty(&self.file)?;
        write_config_file(&path, &content)
    }

    pub fn add_account(&mut self, name: String, mut account: AccountConfig) -> Result<()> {
        if self.file.accounts.contains_key(&name) {
            return Err(YacliError::AccountExists(name));
        }
        if account.default || self.file.accounts.is_empty() {
            self.clear_default();
            account.default = true;
        }
        self.file.accounts.insert(name, account);
        Ok(())
    }

    pub fn set_current(&mut self, name: &str) -> Result<()> {
        if !self.file.accounts.contains_key(name) {
            return Err(YacliError::AccountNotFound(name.to_string()));
        }

        self.clear_default();
        if let Some(account) = self.file.accounts.get_mut(name) {
            account.default = true;
        }
        Ok(())
    }

    pub fn resolved_account_name(&self, requested: Option<&str>) -> Result<String> {
        if let Some(name) = requested {
            if self.file.accounts.contains_key(name) {
                return Ok(name.to_string());
            }
            return Err(YacliError::AccountNotFound(name.to_string()));
        }

        if let Some(name) = self
            .file
            .accounts
            .iter()
            .find_map(|(name, account)| account.default.then(|| name.clone()))
        {
            return Ok(name);
        }

        if self.file.accounts.len() == 1 {
            return Ok(self
                .file
                .accounts
                .keys()
                .next()
                .cloned()
                .expect("single account key exists"));
        }

        Err(YacliError::CurrentAccountMissing)
    }

    pub fn current_account_name(&self) -> Result<String> {
        self.resolved_account_name(None)
    }

    pub fn is_current_account(&self, name: &str) -> bool {
        self.current_account_name()
            .map(|current| current == name)
            .unwrap_or(false)
    }

    pub fn get_account(&self, name: &str) -> Result<&AccountConfig> {
        self.file
            .accounts
            .get(name)
            .ok_or_else(|| YacliError::AccountNotFound(name.to_string()))
    }

    pub fn summaries(&self) -> BTreeMap<String, &AccountConfig> {
        self.file
            .accounts
            .iter()
            .map(|(k, v)| (k.clone(), v))
            .collect()
    }

    pub fn set_service_credential_ref(
        &mut self,
        account_name: &str,
        service: &str,
        credential_ref: Option<String>,
    ) -> Result<()> {
        let account = self
            .file
            .accounts
            .get_mut(account_name)
            .ok_or_else(|| YacliError::AccountNotFound(account_name.to_string()))?;

        match service {
            "mail" => account.mail.credential_ref = credential_ref,
            "calendar" => account.calendar.credential_ref = credential_ref,
            "disk" => account.disk.credential_ref = credential_ref,
            _ => {
                return Err(YacliError::Config(format!(
                    "unknown service for credential_ref update: {service}"
                )));
            }
        }

        Ok(())
    }

    fn clear_default(&mut self) {
        for account in self.file.accounts.values_mut() {
            account.default = false;
        }
    }
}

#[derive(Debug)]
pub struct ValidationReport {
    pub valid: bool,
    pub errors: Vec<String>,
}

pub fn validate_account(name: &str, account: &AccountConfig) -> ValidationReport {
    let mut errors = Vec::new();

    if name.trim().is_empty() {
        errors.push("account name must not be empty".to_string());
    }

    if !account.email.contains('@') {
        errors.push("email must contain @".to_string());
    }

    if account.mail.imap_host.trim().is_empty() {
        errors.push("mail.imap_host must not be empty".to_string());
    }
    if account.mail.smtp_host.trim().is_empty() {
        errors.push("mail.smtp_host must not be empty".to_string());
    }
    if account.mail.imap_port == 0 {
        errors.push("mail.imap_port must not be zero".to_string());
    }
    if account.mail.smtp_port == 0 {
        errors.push("mail.smtp_port must not be zero".to_string());
    }

    if Url::parse(&account.calendar.caldav_base_url).is_err() {
        errors.push("calendar.caldav_base_url must be a valid URL".to_string());
    }
    if Url::parse(&account.disk.rest_base_url).is_err() {
        errors.push("disk.rest_base_url must be a valid URL".to_string());
    }

    for (label, value) in [
        (
            "mail.credential_ref",
            account.mail.credential_ref.as_deref(),
        ),
        (
            "disk.credential_ref",
            account.disk.credential_ref.as_deref(),
        ),
    ] {
        if let Some(reference) = value
            && !reference.starts_with("env:")
            && !reference.starts_with("store:")
        {
            errors.push(format!("{label} must use env:NAME or store:SERVICE"));
        }
    }

    if let Some(reference) = account.calendar.credential_ref.as_deref()
        && !reference.starts_with("env:")
        && !reference.starts_with("store:")
    {
        errors.push("calendar.credential_ref must use env:NAME or store:SERVICE".to_string());
    }

    errors.extend(endpoint_errors(account, !test_overrides_enabled()));

    ValidationReport {
        valid: errors.is_empty(),
        errors,
    }
}

/// Returns one message per endpoint in `account` that is not an allow-listed
/// Yandex host. With `strict == false` (debug/test builds only) nothing is reported.
pub(crate) fn endpoint_errors(account: &AccountConfig, strict: bool) -> Vec<String> {
    if !strict {
        return Vec::new();
    }
    let mut errors = Vec::new();
    let mut note = |result: crate::error::Result<()>| {
        if let Err(err) = result {
            errors.push(err.to_string());
        }
    };
    note(validate_mail_endpoint_strict(
        "mail.imap_host",
        &account.mail.imap_host,
        account.mail.imap_port,
        IMAP_HOSTS,
        IMAP_PORT,
    ));
    note(validate_mail_endpoint_strict(
        "mail.smtp_host",
        &account.mail.smtp_host,
        account.mail.smtp_port,
        SMTP_HOSTS,
        SMTP_PORT,
    ));
    note(
        validate_https_url_strict(
            "calendar.caldav_base_url",
            &account.calendar.caldav_base_url,
            CALDAV_HOSTS,
        )
        .map(|_| ()),
    );
    note(
        validate_https_url_strict(
            "disk.rest_base_url",
            &account.disk.rest_base_url,
            DISK_API_HOSTS,
        )
        .map(|_| ()),
    );
    errors
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cli::{CalendarAuthModeArg, DiskAuthModeArg, MailAuthModeArg};
    use crate::model::NewAccountInput;

    fn default_account() -> AccountConfig {
        AccountConfig::new(NewAccountInput {
            email: "me@yandex.ru".to_string(),
            default: true,
            mail_auth_mode: MailAuthModeArg::OauthXoauth2.into(),
            calendar_auth_mode: CalendarAuthModeArg::AppPassword.into(),
            disk_auth_mode: DiskAuthModeArg::Oauth.into(),
            mail_credential_ref: None,
            calendar_credential_ref: None,
            disk_credential_ref: None,
        })
    }

    #[test]
    fn default_account_passes_strict_endpoint_validation() {
        assert!(endpoint_errors(&default_account(), true).is_empty());
    }

    #[test]
    fn foreign_hosts_in_account_config_are_rejected() {
        let mut account = default_account();
        account.mail.imap_host = "imap.evil.example".to_string();
        account.mail.smtp_host = "127.0.0.1".to_string();
        account.calendar.caldav_base_url = "http://caldav.yandex.ru".to_string();
        account.disk.rest_base_url = "https://cloud-api.evil.example".to_string();

        let errors = endpoint_errors(&account, true);
        assert_eq!(errors.len(), 4, "{errors:?}");
        assert!(errors.iter().any(|e| e.contains("imap.evil.example")));
        assert!(errors.iter().any(|e| e.contains("127.0.0.1")));
        assert!(errors.iter().any(|e| e.contains("only https")));
        assert!(errors.iter().any(|e| e.contains("cloud-api.evil.example")));
    }

    #[test]
    fn non_strict_mode_reports_nothing_for_test_mock_servers() {
        let mut account = default_account();
        account.disk.rest_base_url = "http://127.0.0.1:9999".to_string();
        assert!(endpoint_errors(&account, false).is_empty());
    }
}
