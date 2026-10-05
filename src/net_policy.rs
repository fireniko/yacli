//! Hard-coded network policy: credentials may only be sent to Yandex hosts.
//!
//! Release builds accept only the allow-listed hosts below and only HTTPS for
//! HTTP(S) endpoints. Debug builds (`debug_assertions`, i.e. `cargo test` and
//! `cargo build` without `--release`) additionally accept any host so the
//! integration tests can talk to local mock servers. There is no environment
//! variable or config switch that relaxes the policy in a release build.

use url::Url;

use crate::error::{Result, YacliError};

pub const OAUTH_HOSTS: &[&str] = &["oauth.yandex.ru"];
pub const DISK_API_HOSTS: &[&str] = &["cloud-api.yandex.net"];
pub const CALDAV_HOSTS: &[&str] = &["caldav.yandex.ru"];
pub const IMAP_HOSTS: &[&str] = &["imap.yandex.com", "imap.yandex.ru"];
pub const SMTP_HOSTS: &[&str] = &["smtp.yandex.com", "smtp.yandex.ru"];
pub const IMAP_PORT: u16 = 993;
pub const SMTP_PORT: u16 = 465;

/// True when the build is allowed to talk to non-Yandex test endpoints.
pub const fn test_overrides_enabled() -> bool {
    cfg!(debug_assertions)
}

fn describe(allowed: &[&str]) -> String {
    allowed.join(", ")
}

/// Strict check: `https` scheme and host in `allowed`, no userinfo, default port.
pub fn validate_https_url_strict(label: &str, raw: &str, allowed: &[&str]) -> Result<Url> {
    let url = Url::parse(raw)
        .map_err(|err| YacliError::Config(format!("{label}: invalid URL `{raw}`: {err}")))?;
    if url.scheme() != "https" {
        return Err(YacliError::Config(format!(
            "{label}: only https URLs are allowed, got `{}`",
            url.scheme()
        )));
    }
    if !url.username().is_empty() || url.password().is_some() {
        return Err(YacliError::Config(format!(
            "{label}: URL must not contain credentials"
        )));
    }
    if url.port().is_some() {
        return Err(YacliError::Config(format!(
            "{label}: custom ports are not allowed"
        )));
    }
    let host = url.host_str().unwrap_or_default().to_ascii_lowercase();
    if !allowed.iter().any(|candidate| *candidate == host) {
        return Err(YacliError::Config(format!(
            "{label}: host `{host}` is not allowed; allowed hosts: {}",
            describe(allowed)
        )));
    }
    Ok(url)
}

/// Domain suffixes allowed for Yandex Disk transfer (upload/download) URLs.
pub const TRANSFER_HOST_SUFFIXES: &[&str] = &[
    "yandex.net",
    "yandex.ru",
    "yandex.com",
    "yandex.kz",
    "yandex.by",
];

/// Maximum number of redirects a policy-checked client will follow.
pub const MAX_REDIRECTS: usize = 5;

fn host_matches_suffix(host: &str, suffixes: &[&str]) -> bool {
    suffixes.iter().any(|suffix| {
        host == *suffix
            || host
                .strip_suffix(suffix)
                .is_some_and(|prefix| prefix.ends_with('.') && prefix.len() > 1)
    })
}

fn check_url_shape(label: &str, url: &Url) -> Result<()> {
    if url.scheme() != "https" {
        return Err(YacliError::Config(format!(
            "{label}: only https URLs are allowed, got `{}`",
            url.scheme()
        )));
    }
    if !url.username().is_empty() || url.password().is_some() {
        return Err(YacliError::Config(format!(
            "{label}: URL must not contain credentials"
        )));
    }
    if url.port().is_some() {
        return Err(YacliError::Config(format!(
            "{label}: custom ports are not allowed"
        )));
    }
    Ok(())
}

/// Strict check for transfer URLs handed out by the Disk API: `https`, no
/// userinfo, default port, host equal to or a subdomain of a Yandex suffix.
pub fn validate_transfer_url_strict(label: &str, raw: &str) -> Result<Url> {
    let url = Url::parse(raw)
        .map_err(|err| YacliError::Config(format!("{label}: invalid URL: {err}")))?;
    check_url_shape(label, &url)?;
    let host = url.host_str().unwrap_or_default().to_ascii_lowercase();
    if !host_matches_suffix(&host, TRANSFER_HOST_SUFFIXES) {
        return Err(YacliError::Config(format!(
            "{label}: host `{host}` is not a Yandex transfer host"
        )));
    }
    Ok(url)
}

/// Transfer URL check; debug builds accept any parseable URL so tests can use
/// local mock servers.
pub fn parse_transfer_url(label: &str, raw: &str) -> Result<Url> {
    if test_overrides_enabled() {
        return Url::parse(raw)
            .map_err(|err| YacliError::Config(format!("{label}: invalid URL: {err}")));
    }
    validate_transfer_url_strict(label, raw)
}

/// Which hosts a redirect may lead to.
#[derive(Clone, Copy, Debug)]
pub enum RedirectScope {
    /// Exact host names.
    Hosts(&'static [&'static str]),
    /// Yandex transfer suffixes (`TRANSFER_HOST_SUFFIXES`).
    YandexTransfer,
}

/// Strict redirect-target check (no debug relaxation).
pub fn check_redirect_target_strict(target: &Url, scope: RedirectScope) -> Result<()> {
    match scope {
        RedirectScope::Hosts(allowed) => {
            validate_https_url_strict("redirect", target.as_str(), allowed).map(|_| ())
        }
        RedirectScope::YandexTransfer => {
            validate_transfer_url_strict("redirect", target.as_str()).map(|_| ())
        }
    }
}

/// Redirect policy for reqwest clients: at most `MAX_REDIRECTS` hops, each
/// target must pass the strict check. Debug builds additionally allow
/// same-origin hops (mock servers in tests).
pub fn redirect_policy(scope: RedirectScope) -> reqwest::redirect::Policy {
    reqwest::redirect::Policy::custom(move |attempt| {
        if attempt.previous().len() >= MAX_REDIRECTS {
            return attempt.error("too many redirects");
        }
        let target = attempt.url().clone();
        if check_redirect_target_strict(&target, scope).is_ok() {
            return attempt.follow();
        }
        if test_overrides_enabled()
            && attempt.previous().last().is_some_and(|prev| {
                prev.host_str() == target.host_str()
                    && prev.port_or_known_default() == target.port_or_known_default()
            })
        {
            return attempt.follow();
        }
        attempt.error(format!(
            "redirect to `{}` blocked by network policy",
            target.host_str().unwrap_or("?")
        ))
    })
}

/// Strict check for a bare mail host name and its port.
pub fn validate_mail_endpoint_strict(
    label: &str,
    host: &str,
    port: u16,
    allowed: &[&str],
    expected_port: u16,
) -> Result<()> {
    let normalized = host.trim().to_ascii_lowercase();
    if !allowed.iter().any(|candidate| *candidate == normalized) {
        return Err(YacliError::Config(format!(
            "{label}: host `{host}` is not allowed; allowed hosts: {}",
            describe(allowed)
        )));
    }
    if port != expected_port {
        return Err(YacliError::Config(format!(
            "{label}: port {port} is not allowed; expected {expected_port}"
        )));
    }
    Ok(())
}

/// Parse an HTTP(S) endpoint, enforcing the allow-list unless test overrides are on.
pub fn parse_endpoint(label: &str, raw: &str, allowed: &[&str]) -> Result<Url> {
    if test_overrides_enabled() {
        return Url::parse(raw)
            .map_err(|err| YacliError::Config(format!("{label}: invalid URL `{raw}`: {err}")));
    }
    validate_https_url_strict(label, raw, allowed)
}

/// Check a mail endpoint, enforcing the allow-list unless test overrides are on.
pub fn check_mail_endpoint(
    label: &str,
    host: &str,
    port: u16,
    allowed: &[&str],
    expected_port: u16,
) -> Result<()> {
    if test_overrides_enabled() {
        return Ok(());
    }
    validate_mail_endpoint_strict(label, host, port, allowed, expected_port)
}

pub fn check_imap_endpoint(host: &str, port: u16) -> Result<()> {
    check_mail_endpoint("mail.imap_host", host, port, IMAP_HOSTS, IMAP_PORT)
}

pub fn check_smtp_endpoint(host: &str, port: u16) -> Result<()> {
    check_mail_endpoint("mail.smtp_host", host, port, SMTP_HOSTS, SMTP_PORT)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn https_yandex_hosts_are_accepted() {
        validate_https_url_strict("t", "https://oauth.yandex.ru", OAUTH_HOSTS).expect("oauth");
        validate_https_url_strict("t", "https://cloud-api.yandex.net/", DISK_API_HOSTS)
            .expect("disk");
        validate_https_url_strict("t", "https://CalDAV.Yandex.RU", CALDAV_HOSTS).expect("caldav");
    }

    #[test]
    fn foreign_hosts_are_rejected_with_clear_message() {
        let err = validate_https_url_strict("oauth base URL", "https://evil.example", OAUTH_HOSTS)
            .expect_err("foreign host");
        let text = err.to_string();
        assert!(text.contains("evil.example"), "{text}");
        assert!(text.contains("oauth.yandex.ru"), "{text}");
        // look-alike and suffix tricks
        for raw in [
            "https://oauth.yandex.ru.evil.example",
            "https://evil.example/oauth.yandex.ru",
            "https://oauth.yandex.ru@evil.example",
            "https://eviloauth.yandex.ru",
        ] {
            assert!(
                validate_https_url_strict("t", raw, OAUTH_HOSTS).is_err(),
                "{raw} must be rejected"
            );
        }
    }

    #[test]
    fn plain_http_credentials_and_ports_are_rejected() {
        for raw in [
            "http://oauth.yandex.ru",
            "https://user:pw@oauth.yandex.ru",
            "https://oauth.yandex.ru:8443",
            "ftp://oauth.yandex.ru",
            "not a url",
        ] {
            assert!(
                validate_https_url_strict("t", raw, OAUTH_HOSTS).is_err(),
                "{raw} must be rejected"
            );
        }
    }

    #[test]
    fn mail_endpoints_follow_allow_list_and_ports() {
        validate_mail_endpoint_strict("t", "imap.yandex.com", 993, IMAP_HOSTS, IMAP_PORT)
            .expect("imap com");
        validate_mail_endpoint_strict("t", "IMAP.yandex.ru", 993, IMAP_HOSTS, IMAP_PORT)
            .expect("imap ru");
        validate_mail_endpoint_strict("t", "smtp.yandex.ru", 465, SMTP_HOSTS, SMTP_PORT)
            .expect("smtp ru");
        assert!(
            validate_mail_endpoint_strict("t", "imap.evil.example", 993, IMAP_HOSTS, IMAP_PORT)
                .is_err()
        );
        assert!(
            validate_mail_endpoint_strict("t", "imap.yandex.com", 143, IMAP_HOSTS, IMAP_PORT)
                .is_err()
        );
        assert!(
            validate_mail_endpoint_strict("t", "127.0.0.1", 465, SMTP_HOSTS, SMTP_PORT).is_err()
        );
    }

    #[test]
    fn transfer_urls_follow_suffix_policy() {
        for ok in [
            "https://downloader.disk.yandex.ru/x",
            "https://uploader1.yandex.net/upload?id=1",
            "https://yandex.net/a",
            "https://a.b.yandex.kz",
            "https://disk.yandex.by/",
            "https://DISK.Yandex.COM/",
        ] {
            validate_transfer_url_strict("t", ok).unwrap_or_else(|e| panic!("{ok}: {e}"));
        }
        for bad in [
            "https://evilyandex.net/",
            "https://yandex.net.evil.com/",
            "https://evil.com/yandex.net",
            "http://uploader1.yandex.net/",
            "https://user:pw@uploader1.yandex.net/",
            "https://user@uploader1.yandex.net/",
            "https://uploader1.yandex.net:8443/",
            "https://uploader1.yandex.net@evil.com/",
            "ftp://uploader1.yandex.net/",
            "garbage",
        ] {
            assert!(
                validate_transfer_url_strict("t", bad).is_err(),
                "{bad} must be rejected"
            );
        }
    }

    #[test]
    fn redirect_targets_are_checked() {
        let u = |s: &str| Url::parse(s).unwrap();
        let caldav = RedirectScope::Hosts(CALDAV_HOSTS);
        assert!(check_redirect_target_strict(&u("https://caldav.yandex.ru/x"), caldav).is_ok());
        assert!(check_redirect_target_strict(&u("http://caldav.yandex.ru/x"), caldav).is_err());
        assert!(check_redirect_target_strict(&u("http://caldav.yandex.ru:443/x"), caldav).is_err());
        assert!(check_redirect_target_strict(&u("https://evil.example/x"), caldav).is_err());
        assert!(
            check_redirect_target_strict(&u("https://u:p@caldav.yandex.ru/x"), caldav).is_err()
        );
        let disk = RedirectScope::YandexTransfer;
        assert!(
            check_redirect_target_strict(&u("https://downloader.disk.yandex.ru/x"), disk).is_ok()
        );
        assert!(check_redirect_target_strict(&u("https://evilyandex.ru/x"), disk).is_err());
        assert!(check_redirect_target_strict(&u("http://cloud-api.yandex.net/x"), disk).is_err());
    }

    #[cfg(not(debug_assertions))]
    #[test]
    fn release_builds_enforce_policy_in_wrappers() {
        assert!(parse_endpoint("t", "http://127.0.0.1:1234", OAUTH_HOSTS).is_err());
        assert!(check_imap_endpoint("127.0.0.1", 993).is_err());
        assert!(check_smtp_endpoint("smtp.evil.example", 465).is_err());
        assert!(!test_overrides_enabled());
    }
}
