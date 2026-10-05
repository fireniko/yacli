use std::fs;
use std::path::Path;
use std::sync::Arc;

use serde::{Deserialize, Serialize};

use crate::credential_store::{
    keyring_secret_delete, keyring_secret_get, keyring_secret_set, secrets_use_keyring,
};
use crate::error::Result;
use crate::oauth::{AuthorizationRequest, AuthorizationSession, OauthService, unix_timestamp_now};
use crate::paths::oauth_sessions_path;
use crate::persist::write_config_file;

const PENDING_OAUTH_SESSION_TTL_SECS: u64 = 30 * 60;

/// Where PKCE code verifiers live between `yacli login` and `yacli login --code`.
///
/// In release builds they are kept in the system keyring and never written to
/// `oauth_sessions.toml`. Debug/test builds that use the plaintext `file`
/// secret backend keep them inline in the TOML (no vault).
pub trait VerifierVault: Send + Sync {
    fn put(&self, key: &str, verifier: &str) -> Result<()>;
    fn get(&self, key: &str) -> Result<Option<String>>;
    fn delete(&self, key: &str) -> Result<()>;
}

struct KeyringVault;

impl VerifierVault for KeyringVault {
    fn put(&self, key: &str, verifier: &str) -> Result<()> {
        keyring_secret_set(key, verifier)
    }

    fn get(&self, key: &str) -> Result<Option<String>> {
        keyring_secret_get(key)
    }

    fn delete(&self, key: &str) -> Result<()> {
        keyring_secret_delete(key)
    }
}

fn default_vault() -> Result<Option<Arc<dyn VerifierVault>>> {
    if secrets_use_keyring()? {
        Ok(Some(Arc::new(KeyringVault)))
    } else {
        Ok(None)
    }
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
struct PendingOauthSessionsFile {
    #[serde(default = "default_version")]
    version: u32,
    #[serde(default)]
    sessions: Vec<PendingOauthSession>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PendingOauthSession {
    pub account: String,
    pub services: Vec<String>,
    pub client_id: String,
    pub created_at_epoch_secs: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub login_hint: Option<String>,
    pub authorization: PendingAuthorizationRequest,
    /// Always empty on disk whenever a vault is in use.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub code_verifier: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PendingAuthorizationRequest {
    pub authorization_url: String,
    pub redirect_uri: String,
    pub state: String,
    pub code_challenge_method: String,
}

impl PendingOauthSession {
    pub fn from_authorization_session(
        account: String,
        services: &[OauthService],
        login_hint: Option<String>,
        session: AuthorizationSession,
    ) -> Self {
        Self {
            account,
            services: services
                .iter()
                .map(|service| service.as_str().to_string())
                .collect(),
            client_id: session.client_id.clone(),
            created_at_epoch_secs: unix_timestamp_now(),
            login_hint,
            authorization: PendingAuthorizationRequest::from_request(session.request),
            code_verifier: session.code_verifier,
        }
    }

    pub fn to_authorization_session(&self) -> AuthorizationSession {
        AuthorizationSession {
            request: self.authorization.to_request(),
            client_id: self.client_id.clone(),
            code_verifier: self.code_verifier.clone(),
        }
    }

    pub fn is_expired(&self, now: u64) -> bool {
        now.saturating_sub(self.created_at_epoch_secs) > PENDING_OAUTH_SESSION_TTL_SECS
    }

    fn vault_key(&self) -> String {
        format!(
            "{}:{}:{}",
            self.account,
            self.services.join("+"),
            self.client_id
        )
    }

    fn matches(&self, account: &str, services: &[OauthService], client_id: &str) -> bool {
        self.matches_service_names(account, client_id)
            && self.services
                == services
                    .iter()
                    .map(|service| service.as_str().to_string())
                    .collect::<Vec<_>>()
    }

    fn matches_service_names(&self, account: &str, client_id: &str) -> bool {
        self.account == account && self.client_id == client_id
    }
}

pub struct PendingOauthSessionStore {
    file: PendingOauthSessionsFile,
    vault: Option<Arc<dyn VerifierVault>>,
}

impl PendingOauthSessionStore {
    pub fn load() -> Result<Self> {
        let path = oauth_sessions_path()?;
        Self::load_from_path(&path, default_vault()?)
    }

    /// Loads the pending sessions. Expired sessions are purged on read: their
    /// verifiers are deleted from the vault and the file is rewritten at once.
    fn load_from_path(path: &Path, vault: Option<Arc<dyn VerifierVault>>) -> Result<Self> {
        if !path.exists() {
            return Ok(Self {
                file: PendingOauthSessionsFile::default(),
                vault,
            });
        }

        let content = fs::read_to_string(path)?;
        let mut file = toml::from_str::<PendingOauthSessionsFile>(&content)?;
        let now = unix_timestamp_now();
        let mut dirty = false;

        let sessions = std::mem::take(&mut file.sessions);
        for mut session in sessions {
            if session.is_expired(now) {
                if let Some(vault) = &vault {
                    vault.delete(&session.vault_key())?;
                }
                dirty = true;
                continue;
            }
            if let Some(vault) = &vault {
                if session.code_verifier.is_empty() {
                    match vault.get(&session.vault_key())? {
                        Some(verifier) => session.code_verifier = verifier,
                        None => {
                            // The verifier is gone, so the session can never be completed.
                            dirty = true;
                            continue;
                        }
                    }
                } else {
                    // Legacy plaintext verifier on disk: move it into the vault
                    // and rewrite the file without it.
                    vault.put(&session.vault_key(), &session.code_verifier)?;
                    dirty = true;
                }
            } else if session.code_verifier.is_empty() {
                dirty = true;
                continue;
            }
            file.sessions.push(session);
        }

        let store = Self { file, vault };
        if dirty {
            store.save_to_path(path)?;
        }
        Ok(store)
    }

    pub fn save(&self) -> Result<()> {
        let path = oauth_sessions_path()?;
        self.save_to_path(&path)
    }

    fn save_to_path(&self, path: &Path) -> Result<()> {
        if self.file.sessions.is_empty() {
            if path.exists() {
                fs::remove_file(path)?;
            }
            return Ok(());
        }

        let mut file = self.file.clone();
        if let Some(vault) = &self.vault {
            for session in &mut file.sessions {
                if !session.code_verifier.is_empty() {
                    vault.put(&session.vault_key(), &session.code_verifier)?;
                    session.code_verifier.clear();
                }
            }
        }

        let content = toml::to_string_pretty(&file)?;
        write_config_file(path, &content)
    }

    pub fn get_matching(
        &self,
        account: &str,
        services: &[OauthService],
        client_id: &str,
    ) -> Option<&PendingOauthSession> {
        self.file
            .sessions
            .iter()
            .find(|session| session.matches(account, services, client_id))
    }

    pub fn replace_matching(&mut self, session: PendingOauthSession) {
        self.file.sessions.retain(|item| {
            !(item.matches_service_names(&session.account, &session.client_id)
                && item.services == session.services)
        });
        self.file.sessions.push(session);
    }

    /// Removes matching sessions and erases their verifiers from the vault.
    pub fn remove_matching(
        &mut self,
        account: &str,
        services: &[OauthService],
        client_id: &str,
    ) -> Result<bool> {
        let previous_len = self.file.sessions.len();
        let mut doomed = Vec::new();
        self.file.sessions.retain(|session| {
            let hit = session.matches(account, services, client_id);
            if hit {
                doomed.push(session.vault_key());
            }
            !hit
        });
        if let Some(vault) = &self.vault {
            for key in doomed {
                vault.delete(&key)?;
            }
        }
        Ok(previous_len != self.file.sessions.len())
    }
}

const fn default_version() -> u32 {
    1
}

impl PendingAuthorizationRequest {
    fn from_request(request: AuthorizationRequest) -> Self {
        Self {
            authorization_url: request.authorization_url,
            redirect_uri: request.redirect_uri,
            state: request.state,
            code_challenge_method: request.code_challenge_method.to_string(),
        }
    }

    fn to_request(&self) -> AuthorizationRequest {
        AuthorizationRequest {
            authorization_url: self.authorization_url.clone(),
            redirect_uri: self.redirect_uri.clone(),
            state: self.state.clone(),
            code_challenge_method: "S256",
        }
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;
    use std::sync::Mutex;

    use tempfile::tempdir;

    use super::*;

    static OAUTH_SESSIONS_TEST_LOCK: Mutex<()> = Mutex::new(());

    #[derive(Default)]
    struct MemoryVault {
        secrets: Mutex<HashMap<String, String>>,
    }

    impl VerifierVault for MemoryVault {
        fn put(&self, key: &str, verifier: &str) -> Result<()> {
            self.secrets
                .lock()
                .expect("vault lock")
                .insert(key.to_string(), verifier.to_string());
            Ok(())
        }

        fn get(&self, key: &str) -> Result<Option<String>> {
            Ok(self.secrets.lock().expect("vault lock").get(key).cloned())
        }

        fn delete(&self, key: &str) -> Result<()> {
            self.secrets.lock().expect("vault lock").remove(key);
            Ok(())
        }
    }

    fn memory_vault() -> (Arc<MemoryVault>, Option<Arc<dyn VerifierVault>>) {
        let vault = Arc::new(MemoryVault::default());
        let dynamic: Arc<dyn VerifierVault> = vault.clone();
        (vault, Some(dynamic))
    }

    fn sample_session(account: &str) -> PendingOauthSession {
        PendingOauthSession {
            account: account.to_string(),
            services: vec!["mail".to_string(), "disk".to_string()],
            client_id: "client-123".to_string(),
            created_at_epoch_secs: unix_timestamp_now(),
            login_hint: Some("me@yandex.ru".to_string()),
            authorization: PendingAuthorizationRequest {
                authorization_url: "https://example.test/authorize".to_string(),
                redirect_uri: "https://oauth.yandex.ru/verification_code".to_string(),
                state: "state-123".to_string(),
                code_challenge_method: "S256".to_string(),
            },
            code_verifier: "verifier-123".to_string(),
        }
    }

    const BOTH: &[OauthService] = &[OauthService::Mail, OauthService::Disk];

    #[test]
    fn inline_mode_roundtrips_pending_session() {
        let _guard = OAUTH_SESSIONS_TEST_LOCK
            .lock()
            .expect("oauth sessions test lock");
        let temp = tempdir().expect("tempdir");
        let path = temp.path().join("oauth_sessions.toml");

        let mut store = PendingOauthSessionStore::load_from_path(&path, None).expect("load");
        store.replace_matching(sample_session("mock"));
        store.save_to_path(&path).expect("save");

        let store = PendingOauthSessionStore::load_from_path(&path, None).expect("reload");
        let saved = store
            .get_matching("mock", BOTH, "client-123")
            .expect("pending session");
        assert_eq!(
            saved.authorization.authorization_url,
            "https://example.test/authorize"
        );
        assert_eq!(saved.code_verifier, "verifier-123");
    }

    #[test]
    fn vault_mode_never_writes_verifier_to_disk_but_restores_it() {
        let _guard = OAUTH_SESSIONS_TEST_LOCK
            .lock()
            .expect("oauth sessions test lock");
        let temp = tempdir().expect("tempdir");
        let path = temp.path().join("oauth_sessions.toml");
        let (memory, vault) = memory_vault();

        let mut store = PendingOauthSessionStore::load_from_path(&path, vault.clone()).expect("load");
        store.replace_matching(sample_session("mock"));
        store.save_to_path(&path).expect("save");

        let on_disk = fs::read_to_string(&path).expect("read file");
        assert!(!on_disk.contains("verifier-123"), "{on_disk}");
        assert!(!on_disk.contains("code_verifier"), "{on_disk}");
        assert_eq!(memory.secrets.lock().expect("lock").len(), 1);

        let store = PendingOauthSessionStore::load_from_path(&path, vault).expect("reload");
        let saved = store
            .get_matching("mock", BOTH, "client-123")
            .expect("pending session");
        assert_eq!(saved.code_verifier, "verifier-123");
    }

    #[test]
    fn verifier_is_erased_from_vault_after_use() {
        let _guard = OAUTH_SESSIONS_TEST_LOCK
            .lock()
            .expect("oauth sessions test lock");
        let temp = tempdir().expect("tempdir");
        let path = temp.path().join("oauth_sessions.toml");
        let (memory, vault) = memory_vault();

        let mut store = PendingOauthSessionStore::load_from_path(&path, vault.clone()).expect("load");
        store.replace_matching(sample_session("mock"));
        store.save_to_path(&path).expect("save");
        assert_eq!(memory.secrets.lock().expect("lock").len(), 1);

        let mut store = PendingOauthSessionStore::load_from_path(&path, vault).expect("reload");
        assert!(
            store
                .remove_matching("mock", BOTH, "client-123")
                .expect("remove")
        );
        store.save_to_path(&path).expect("save after removal");

        assert!(memory.secrets.lock().expect("lock").is_empty());
        assert!(!path.exists(), "session file must be removed when empty");
    }

    #[test]
    fn expired_sessions_are_purged_on_read_including_vault_and_file() {
        let _guard = OAUTH_SESSIONS_TEST_LOCK
            .lock()
            .expect("oauth sessions test lock");
        let temp = tempdir().expect("tempdir");
        let path = temp.path().join("oauth_sessions.toml");
        let (memory, vault) = memory_vault();

        let mut stale = sample_session("mock");
        stale.created_at_epoch_secs = unix_timestamp_now() - PENDING_OAUTH_SESSION_TTL_SECS - 1;

        let mut store = PendingOauthSessionStore::load_from_path(&path, vault.clone()).expect("load");
        store.replace_matching(stale);
        store.save_to_path(&path).expect("save");
        assert_eq!(memory.secrets.lock().expect("lock").len(), 1);

        let store = PendingOauthSessionStore::load_from_path(&path, vault).expect("reload");
        assert!(store.get_matching("mock", BOTH, "client-123").is_none());
        assert!(memory.secrets.lock().expect("lock").is_empty());
        assert!(!path.exists(), "expired session file must be rewritten away");
    }

    #[test]
    fn expired_sessions_are_purged_from_file_in_inline_mode() {
        let _guard = OAUTH_SESSIONS_TEST_LOCK
            .lock()
            .expect("oauth sessions test lock");
        let temp = tempdir().expect("tempdir");
        let path = temp.path().join("oauth_sessions.toml");

        let mut stale = sample_session("mock");
        stale.created_at_epoch_secs = unix_timestamp_now() - PENDING_OAUTH_SESSION_TTL_SECS - 1;

        let mut store = PendingOauthSessionStore::load_from_path(&path, None).expect("load");
        store.replace_matching(stale);
        store.save_to_path(&path).expect("save");
        assert!(fs::read_to_string(&path).expect("read").contains("verifier-123"));

        let store = PendingOauthSessionStore::load_from_path(&path, None).expect("reload");
        assert!(store.get_matching("mock", BOTH, "client-123").is_none());
        assert!(!path.exists(), "verifier must not linger in the file");
    }

    #[test]
    fn legacy_plaintext_verifier_is_migrated_into_vault_and_scrubbed() {
        let _guard = OAUTH_SESSIONS_TEST_LOCK
            .lock()
            .expect("oauth sessions test lock");
        let temp = tempdir().expect("tempdir");
        let path = temp.path().join("oauth_sessions.toml");

        // Written by an older build / inline mode: verifier in plaintext.
        let mut legacy = PendingOauthSessionStore::load_from_path(&path, None).expect("load");
        legacy.replace_matching(sample_session("mock"));
        legacy.save_to_path(&path).expect("save legacy");
        assert!(fs::read_to_string(&path).expect("read").contains("verifier-123"));

        let (memory, vault) = memory_vault();
        let store = PendingOauthSessionStore::load_from_path(&path, vault).expect("migrate");
        assert_eq!(
            store
                .get_matching("mock", BOTH, "client-123")
                .expect("session")
                .code_verifier,
            "verifier-123"
        );
        assert!(!fs::read_to_string(&path).expect("read").contains("verifier-123"));
        assert_eq!(memory.secrets.lock().expect("lock").len(), 1);
    }

    #[test]
    fn session_without_verifier_in_vault_is_dropped() {
        let _guard = OAUTH_SESSIONS_TEST_LOCK
            .lock()
            .expect("oauth sessions test lock");
        let temp = tempdir().expect("tempdir");
        let path = temp.path().join("oauth_sessions.toml");
        let (memory, vault) = memory_vault();

        let mut store = PendingOauthSessionStore::load_from_path(&path, vault.clone()).expect("load");
        store.replace_matching(sample_session("mock"));
        store.save_to_path(&path).expect("save");
        memory.secrets.lock().expect("lock").clear();

        let store = PendingOauthSessionStore::load_from_path(&path, vault).expect("reload");
        assert!(store.get_matching("mock", BOTH, "client-123").is_none());
        assert!(!path.exists());
    }
}
