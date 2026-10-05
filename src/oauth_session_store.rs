use std::fs;
use std::io::ErrorKind;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::thread;
use std::time::{Duration, SystemTime};

use rand::Rng;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::credential_store::{
    keyring_secret_delete, keyring_secret_get, keyring_secret_set, secrets_use_keyring,
};
use crate::error::{Result, YacliError};
use crate::oauth::{
    AuthorizationRequest, AuthorizationSession, OauthService, deduped_scopes, unix_timestamp_now,
};
use crate::paths::oauth_sessions_path;
use crate::persist::write_config_file;

const PENDING_OAUTH_SESSION_TTL_SECS: u64 = 30 * 60;
const LOCK_WAIT: Duration = Duration::from_secs(10);
const LOCK_POLL: Duration = Duration::from_millis(25);
const LOCK_STALE_AFTER: Duration = Duration::from_secs(60);

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

fn warn(message: &str) {
    eprintln!("warning: {message}");
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn new_session_id() -> String {
    let mut bytes = [0u8; 16];
    rand::rng().fill(&mut bytes);
    hex(&bytes)
}

/// Short stable fingerprint of the sessions file path (i.e. of the config
/// directory), so two config directories never share keyring entries.
fn scope_for_path(path: &Path) -> String {
    let digest = Sha256::digest(path.to_string_lossy().as_bytes());
    hex(&digest[..8])
}

/// Inter-process lock around the read-modify-write cycle of the sessions file.
/// Implemented with an exclusive-create lock file; a lock older than
/// `LOCK_STALE_AFTER` is considered abandoned and removed.
struct FileLock {
    path: PathBuf,
}

impl FileLock {
    fn acquire(target: &Path) -> Result<Self> {
        let mut lock_name = target.as_os_str().to_os_string();
        lock_name.push(".lock");
        let path = PathBuf::from(lock_name);
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }
        let started = std::time::Instant::now();
        loop {
            match fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&path)
            {
                Ok(_) => return Ok(Self { path }),
                Err(err) if err.kind() == ErrorKind::AlreadyExists => {
                    let stale = fs::metadata(&path)
                        .and_then(|meta| meta.modified())
                        .ok()
                        .and_then(|modified| SystemTime::now().duration_since(modified).ok())
                        .is_some_and(|age| age > LOCK_STALE_AFTER);
                    if stale {
                        let _ = fs::remove_file(&path);
                        continue;
                    }
                    if started.elapsed() > LOCK_WAIT {
                        return Err(YacliError::Io(format!(
                            "timed out waiting for {}; remove it if no other yacli login is running",
                            path.display()
                        )));
                    }
                    thread::sleep(LOCK_POLL);
                }
                // Windows reports a lock file that is being deleted as access denied.
                Err(err) if err.kind() == ErrorKind::PermissionDenied => {
                    if started.elapsed() > LOCK_WAIT {
                        return Err(err.into());
                    }
                    thread::sleep(LOCK_POLL);
                }
                Err(err) => return Err(err.into()),
            }
        }
    }
}

impl Drop for FileLock {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.path);
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
    /// Random per-session ID (not a secret); part of the keyring key. Empty
    /// only for sessions written by older builds.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub session_id: String,
    pub account: String,
    pub services: Vec<String>,
    /// Scopes requested by this session. Empty for sessions written by older
    /// builds, which therefore never match (a fresh session is created).
    #[serde(default)]
    pub scopes: Vec<String>,
    pub client_id: String,
    pub created_at_epoch_secs: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub login_hint: Option<String>,
    pub authorization: PendingAuthorizationRequest,
    /// Always empty on disk whenever a vault is in use.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub code_verifier: String,
    /// True until the verifier has been stored in the vault.
    #[serde(skip)]
    fresh: bool,
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
            session_id: new_session_id(),
            account,
            services: services
                .iter()
                .map(|service| service.as_str().to_string())
                .collect(),
            scopes: desired_scopes(services),
            client_id: session.client_id.clone(),
            created_at_epoch_secs: unix_timestamp_now(),
            login_hint,
            authorization: PendingAuthorizationRequest::from_request(session.request),
            code_verifier: session.code_verifier,
            fresh: true,
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

    /// Keyring key: config-directory fingerprint plus the random session ID.
    /// Legacy sessions without an ID keep their old key so they stay readable.
    fn vault_key(&self, scope: &str) -> String {
        if self.session_id.is_empty() {
            format!(
                "{}:{}:{}",
                self.account,
                self.services.join("+"),
                self.client_id
            )
        } else {
            format!("oauth-pkce:{scope}:{}", self.session_id)
        }
    }

    /// Same login (account, client, services), regardless of requested scopes.
    fn matches_login(&self, account: &str, services: &[OauthService], client_id: &str) -> bool {
        self.matches_service_names(account, client_id)
            && self.services
                == services
                    .iter()
                    .map(|service| service.as_str().to_string())
                    .collect::<Vec<_>>()
    }

    /// Reusable only if the requested scopes are exactly the current ones.
    fn matches(&self, account: &str, services: &[OauthService], client_id: &str) -> bool {
        self.matches_login(account, services, client_id) && self.scopes == desired_scopes(services)
    }

    fn matches_service_names(&self, account: &str, client_id: &str) -> bool {
        self.account == account && self.client_id == client_id
    }
}

fn desired_scopes(services: &[OauthService]) -> Vec<String> {
    deduped_scopes(services)
        .into_iter()
        .map(ToString::to_string)
        .collect()
}

pub struct PendingOauthSessionStore {
    file: PendingOauthSessionsFile,
    vault: Option<Arc<dyn VerifierVault>>,
    scope: String,
}

/// Finds the pending session for this login, purging expired ones.
pub fn find_pending_session(
    account: &str,
    services: &[OauthService],
    client_id: &str,
) -> Result<Option<PendingOauthSession>> {
    PendingOauthSessionStore::locked(&oauth_sessions_path()?, default_vault()?, |store| {
        Ok(store.get_matching(account, services, client_id).cloned())
    })
}

/// Stores a new pending session (replacing and erasing any older one for the
/// same account/services/client).
pub fn save_pending_session(session: PendingOauthSession) -> Result<()> {
    PendingOauthSessionStore::locked(&oauth_sessions_path()?, default_vault()?, |store| {
        store.replace_matching(session);
        Ok(())
    })
}

/// Removes the pending session and erases its verifier.
pub fn discard_pending_session(
    account: &str,
    services: &[OauthService],
    client_id: &str,
) -> Result<bool> {
    PendingOauthSessionStore::locked(&oauth_sessions_path()?, default_vault()?, |store| {
        store.remove_matching(account, services, client_id)
    })
}

impl PendingOauthSessionStore {
    /// Runs `f` on a freshly loaded store while holding the inter-process lock,
    /// then persists the result.
    fn locked<T>(
        path: &Path,
        vault: Option<Arc<dyn VerifierVault>>,
        f: impl FnOnce(&mut Self) -> Result<T>,
    ) -> Result<T> {
        let _lock = FileLock::acquire(path)?;
        let mut store = Self::load_unlocked(path, vault)?;
        let out = f(&mut store)?;
        store.save_unlocked(path)?;
        Ok(out)
    }

    /// Loads the pending sessions. Expired sessions are purged on read: their
    /// verifiers are deleted from the vault (failures only warn) and the file
    /// is rewritten at once.
    fn load_unlocked(path: &Path, vault: Option<Arc<dyn VerifierVault>>) -> Result<Self> {
        let scope = scope_for_path(path);
        if !path.exists() {
            return Ok(Self {
                file: PendingOauthSessionsFile::default(),
                vault,
                scope,
            });
        }

        let content = fs::read_to_string(path)?;
        let mut file = toml::from_str::<PendingOauthSessionsFile>(&content)?;
        let now = unix_timestamp_now();
        let mut dirty = false;

        let sessions = std::mem::take(&mut file.sessions);
        for mut session in sessions {
            if session.is_expired(now) {
                if let Some(vault) = &vault
                    && let Err(err) = vault.delete(&session.vault_key(&scope))
                {
                    warn(&format!("could not erase expired PKCE verifier: {err}"));
                }
                dirty = true;
                continue;
            }
            if let Some(vault) = &vault {
                if session.code_verifier.is_empty() {
                    match vault.get(&session.vault_key(&scope))? {
                        Some(verifier) => session.code_verifier = verifier,
                        None => {
                            // The verifier is gone, so the session can never be completed.
                            dirty = true;
                            continue;
                        }
                    }
                } else {
                    // Legacy plaintext verifier on disk: re-key it under a fresh
                    // session ID; the next save moves it into the vault and
                    // rewrites the file without it.
                    if session.session_id.is_empty() {
                        session.session_id = new_session_id();
                    }
                    session.fresh = true;
                    dirty = true;
                }
            } else if session.code_verifier.is_empty() {
                dirty = true;
                continue;
            }
            file.sessions.push(session);
        }

        let mut store = Self { file, vault, scope };
        if dirty {
            store.save_unlocked(path)?;
        }
        Ok(store)
    }

    /// Order matters for crash safety: the TOML (without verifier) is written
    /// first, then the verifier goes into the vault; if that fails the TOML is
    /// rolled back so no session exists without its verifier.
    fn save_unlocked(&mut self, path: &Path) -> Result<()> {
        if self.file.sessions.is_empty() {
            if path.exists() {
                fs::remove_file(path)?;
            }
            return Ok(());
        }

        let mut file = self.file.clone();
        let mut to_store = Vec::new();
        if self.vault.is_some() {
            for session in &mut file.sessions {
                if session.fresh && !session.code_verifier.is_empty() {
                    to_store.push((
                        session.vault_key(&self.scope),
                        session.code_verifier.clone(),
                    ));
                }
                session.code_verifier.clear();
            }
        }

        let content = toml::to_string_pretty(&file)?;
        let previous = fs::read(path).ok();
        if to_store.is_empty() && previous.as_deref() == Some(content.as_bytes()) {
            return Ok(());
        }
        write_config_file(path, &content)?;

        if let Some(vault) = &self.vault {
            let mut stored: Vec<&str> = Vec::new();
            for (key, verifier) in &to_store {
                if let Err(err) = vault.put(key, verifier) {
                    for done in &stored {
                        if let Err(cleanup) = vault.delete(done) {
                            warn(&format!("could not erase PKCE verifier: {cleanup}"));
                        }
                    }
                    let rollback = match &previous {
                        Some(bytes) => String::from_utf8(bytes.clone())
                            .map_err(|e| YacliError::Io(e.to_string()))
                            .and_then(|text| write_config_file(path, &text)),
                        None => fs::remove_file(path).map_err(Into::into),
                    };
                    if let Err(rollback_err) = rollback {
                        warn(&format!(
                            "could not roll back {}: {rollback_err}",
                            path.display()
                        ));
                    }
                    return Err(err);
                }
                stored.push(key);
            }
        }
        for session in &mut self.file.sessions {
            session.fresh = false;
        }
        Ok(())
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

    /// Replaces any older session for the same login, erasing its verifier.
    pub fn replace_matching(&mut self, mut session: PendingOauthSession) {
        let scope = self.scope.clone();
        let vault = self.vault.clone();
        self.file.sessions.retain(|item| {
            let hit = item.matches_service_names(&session.account, &session.client_id)
                && item.services == session.services;
            if hit && let Some(vault) = &vault {
                let key = item.vault_key(&scope);
                if key != session.vault_key(&scope)
                    && let Err(err) = vault.delete(&key)
                {
                    warn(&format!("could not erase replaced PKCE verifier: {err}"));
                }
            }
            !hit
        });
        session.fresh = true;
        self.file.sessions.push(session);
    }

    /// Removes matching sessions and erases their verifiers from the vault.
    /// Vault errors are not fatal (a warning is printed).
    pub fn remove_matching(
        &mut self,
        account: &str,
        services: &[OauthService],
        client_id: &str,
    ) -> Result<bool> {
        let previous_len = self.file.sessions.len();
        let mut doomed = Vec::new();
        let scope = self.scope.clone();
        self.file.sessions.retain(|session| {
            let hit = session.matches_login(account, services, client_id);
            if hit {
                doomed.push(session.vault_key(&scope));
            }
            !hit
        });
        if let Some(vault) = &self.vault {
            for key in doomed {
                if let Err(err) = vault.delete(&key) {
                    warn(&format!("could not erase PKCE verifier: {err}"));
                }
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
            session_id: new_session_id(),
            fresh: true,
            account: account.to_string(),
            services: vec!["mail".to_string(), "disk".to_string()],
            scopes: desired_scopes(BOTH),
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

        let mut store = PendingOauthSessionStore::load_unlocked(&path, None).expect("load");
        store.replace_matching(sample_session("mock"));
        store.save_unlocked(&path).expect("save");

        let store = PendingOauthSessionStore::load_unlocked(&path, None).expect("reload");
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

        let mut store =
            PendingOauthSessionStore::load_unlocked(&path, vault.clone()).expect("load");
        store.replace_matching(sample_session("mock"));
        store.save_unlocked(&path).expect("save");

        let on_disk = fs::read_to_string(&path).expect("read file");
        assert!(!on_disk.contains("verifier-123"), "{on_disk}");
        assert!(!on_disk.contains("code_verifier"), "{on_disk}");
        assert_eq!(memory.secrets.lock().expect("lock").len(), 1);

        let store = PendingOauthSessionStore::load_unlocked(&path, vault).expect("reload");
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

        let mut store =
            PendingOauthSessionStore::load_unlocked(&path, vault.clone()).expect("load");
        store.replace_matching(sample_session("mock"));
        store.save_unlocked(&path).expect("save");
        assert_eq!(memory.secrets.lock().expect("lock").len(), 1);

        let mut store = PendingOauthSessionStore::load_unlocked(&path, vault).expect("reload");
        assert!(
            store
                .remove_matching("mock", BOTH, "client-123")
                .expect("remove")
        );
        store.save_unlocked(&path).expect("save after removal");

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

        let mut store =
            PendingOauthSessionStore::load_unlocked(&path, vault.clone()).expect("load");
        store.replace_matching(stale);
        store.save_unlocked(&path).expect("save");
        assert_eq!(memory.secrets.lock().expect("lock").len(), 1);

        let store = PendingOauthSessionStore::load_unlocked(&path, vault).expect("reload");
        assert!(store.get_matching("mock", BOTH, "client-123").is_none());
        assert!(memory.secrets.lock().expect("lock").is_empty());
        assert!(
            !path.exists(),
            "expired session file must be rewritten away"
        );
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

        let mut store = PendingOauthSessionStore::load_unlocked(&path, None).expect("load");
        store.replace_matching(stale);
        store.save_unlocked(&path).expect("save");
        assert!(
            fs::read_to_string(&path)
                .expect("read")
                .contains("verifier-123")
        );

        let store = PendingOauthSessionStore::load_unlocked(&path, None).expect("reload");
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
        let mut legacy = PendingOauthSessionStore::load_unlocked(&path, None).expect("load");
        legacy.replace_matching(sample_session("mock"));
        legacy.save_unlocked(&path).expect("save legacy");
        assert!(
            fs::read_to_string(&path)
                .expect("read")
                .contains("verifier-123")
        );

        let (memory, vault) = memory_vault();
        let store = PendingOauthSessionStore::load_unlocked(&path, vault).expect("migrate");
        assert_eq!(
            store
                .get_matching("mock", BOTH, "client-123")
                .expect("session")
                .code_verifier,
            "verifier-123"
        );
        assert!(
            !fs::read_to_string(&path)
                .expect("read")
                .contains("verifier-123")
        );
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

        let mut store =
            PendingOauthSessionStore::load_unlocked(&path, vault.clone()).expect("load");
        store.replace_matching(sample_session("mock"));
        store.save_unlocked(&path).expect("save");
        memory.secrets.lock().expect("lock").clear();

        let store = PendingOauthSessionStore::load_unlocked(&path, vault).expect("reload");
        assert!(store.get_matching("mock", BOTH, "client-123").is_none());
        assert!(!path.exists());
    }

    struct FlakyVault {
        inner: MemoryVault,
        fail_put: bool,
        fail_delete: bool,
    }

    impl VerifierVault for FlakyVault {
        fn put(&self, key: &str, verifier: &str) -> Result<()> {
            if self.fail_put {
                return Err(YacliError::Io("simulated keyring failure".to_string()));
            }
            self.inner.put(key, verifier)
        }

        fn get(&self, key: &str) -> Result<Option<String>> {
            self.inner.get(key)
        }

        fn delete(&self, key: &str) -> Result<()> {
            if self.fail_delete {
                return Err(YacliError::Io("simulated keyring failure".to_string()));
            }
            self.inner.delete(key)
        }
    }

    fn session_with(account: &str, verifier: &str) -> PendingOauthSession {
        let mut session = sample_session(account);
        session.code_verifier = verifier.to_string();
        session
    }

    #[test]
    fn vault_failure_rolls_back_toml_and_leaves_no_verifier() {
        let _guard = OAUTH_SESSIONS_TEST_LOCK.lock().expect("lock");
        let temp = tempdir().expect("tempdir");
        let path = temp.path().join("oauth_sessions.toml");
        let flaky = Arc::new(FlakyVault {
            inner: MemoryVault::default(),
            fail_put: true,
            fail_delete: false,
        });
        let vault: Option<Arc<dyn VerifierVault>> = Some(flaky.clone());

        let result = PendingOauthSessionStore::locked(&path, vault, |store| {
            store.replace_matching(session_with("mock", "verifier-xyz"));
            Ok(())
        });
        assert!(result.is_err());
        assert!(!path.exists(), "TOML must be rolled back");
        assert!(flaky.inner.secrets.lock().expect("lock").is_empty());
        assert!(
            !temp.path().join("oauth_sessions.toml.lock").exists(),
            "lock released"
        );
    }

    #[test]
    fn vault_failure_restores_previous_toml_content() {
        let _guard = OAUTH_SESSIONS_TEST_LOCK.lock().expect("lock");
        let temp = tempdir().expect("tempdir");
        let path = temp.path().join("oauth_sessions.toml");
        let (_memory, good) = memory_vault();
        PendingOauthSessionStore::locked(&path, good.clone(), |store| {
            store.replace_matching(session_with("first", "v-first"));
            Ok(())
        })
        .expect("first save");
        let before = fs::read_to_string(&path).expect("read");

        // Second save fails in put(); the file must be exactly as before.
        let flaky = Arc::new(FlakyVault {
            inner: MemoryVault::default(),
            fail_put: true,
            fail_delete: false,
        });
        let bad: Option<Arc<dyn VerifierVault>> = Some(flaky.clone());
        let mut store = PendingOauthSessionStore::load_unlocked(&path, good).expect("load");
        store.vault = bad;
        store.replace_matching(session_with("second", "v-second"));
        assert!(store.save_unlocked(&path).is_err());

        assert!(flaky.inner.secrets.lock().expect("lock").is_empty());
        assert_eq!(fs::read_to_string(&path).expect("read"), before);
    }

    #[test]
    fn cleanup_errors_on_remove_and_purge_are_not_fatal() {
        let _guard = OAUTH_SESSIONS_TEST_LOCK.lock().expect("lock");
        let temp = tempdir().expect("tempdir");
        let path = temp.path().join("oauth_sessions.toml");
        let flaky = Arc::new(FlakyVault {
            inner: MemoryVault::default(),
            fail_put: false,
            fail_delete: true,
        });
        let vault: Option<Arc<dyn VerifierVault>> = Some(flaky.clone());

        PendingOauthSessionStore::locked(&path, vault.clone(), |store| {
            store.replace_matching(session_with("mock", "v1"));
            Ok(())
        })
        .expect("save");
        let removed = PendingOauthSessionStore::locked(&path, vault.clone(), |store| {
            store.remove_matching("mock", BOTH, "client-123")
        })
        .expect("remove must succeed despite delete failure");
        assert!(removed);
        assert!(!path.exists());

        let mut stale = session_with("old", "v2");
        stale.created_at_epoch_secs = unix_timestamp_now() - PENDING_OAUTH_SESSION_TTL_SECS - 1;
        PendingOauthSessionStore::locked(&path, vault.clone(), |store| {
            store.replace_matching(stale);
            Ok(())
        })
        .expect("save stale");
        PendingOauthSessionStore::locked(&path, vault, |store| {
            assert!(store.get_matching("old", BOTH, "client-123").is_none());
            Ok(())
        })
        .expect("purge must succeed despite delete failure");
    }

    #[test]
    fn vault_keys_are_unique_per_session_and_per_config_dir() {
        let a = sample_session("mock");
        let b = sample_session("mock");
        let scope_a = scope_for_path(Path::new("/cfg/a/oauth_sessions.toml"));
        let scope_b = scope_for_path(Path::new("/cfg/b/oauth_sessions.toml"));
        assert_ne!(a.vault_key(&scope_a), b.vault_key(&scope_a));
        assert_ne!(a.vault_key(&scope_a), a.vault_key(&scope_b));
        assert!(a.vault_key(&scope_a).contains(&a.session_id));
        assert_eq!(a.session_id.len(), 32);
        let on_disk = toml::to_string_pretty(&a).expect("toml");
        assert!(on_disk.contains(&a.session_id));
    }

    #[test]
    fn parallel_logins_do_not_mix_verifiers() {
        let _guard = OAUTH_SESSIONS_TEST_LOCK.lock().expect("lock");
        let temp = tempdir().expect("tempdir");
        let path = temp.path().join("oauth_sessions.toml");
        let (memory, vault) = memory_vault();

        let mut handles = Vec::new();
        for n in 0..8 {
            let path = path.clone();
            let vault = vault.clone();
            handles.push(thread::spawn(move || {
                for round in 0..5 {
                    let account = format!("acc{n}");
                    PendingOauthSessionStore::locked(&path, vault.clone(), |store| {
                        store.replace_matching(session_with(
                            &account,
                            &format!("verifier-{n}-{round}"),
                        ));
                        Ok(())
                    })
                    .expect("locked save");
                }
            }));
        }
        for handle in handles {
            handle.join().expect("thread");
        }

        let store = PendingOauthSessionStore::load_unlocked(&path, vault).expect("reload");
        for n in 0..8 {
            let session = store
                .get_matching(&format!("acc{n}"), BOTH, "client-123")
                .expect("session survives");
            assert_eq!(session.code_verifier, format!("verifier-{n}-4"));
        }
        assert_eq!(memory.secrets.lock().expect("lock").len(), 8);
        let on_disk = fs::read_to_string(&path).expect("read");
        assert!(!on_disk.contains("verifier-"), "{on_disk}");
    }

    #[test]
    fn same_login_started_twice_keeps_only_latest_verifier() {
        let _guard = OAUTH_SESSIONS_TEST_LOCK.lock().expect("lock");
        let temp = tempdir().expect("tempdir");
        let path = temp.path().join("oauth_sessions.toml");
        let (memory, vault) = memory_vault();
        for verifier in ["first", "second"] {
            PendingOauthSessionStore::locked(&path, vault.clone(), |store| {
                store.replace_matching(session_with("mock", verifier));
                Ok(())
            })
            .expect("save");
        }
        let store = PendingOauthSessionStore::load_unlocked(&path, vault).expect("reload");
        assert_eq!(
            store
                .get_matching("mock", BOTH, "client-123")
                .expect("session")
                .code_verifier,
            "second"
        );
        assert_eq!(memory.secrets.lock().expect("lock").len(), 1);
    }

    #[test]
    fn stale_lock_file_is_taken_over() {
        let temp = tempdir().expect("tempdir");
        let path = temp.path().join("oauth_sessions.toml");
        let lock_path = temp.path().join("oauth_sessions.toml.lock");
        let file = fs::File::create(&lock_path).expect("lock file");
        file.set_modified(SystemTime::now() - Duration::from_secs(3600))
            .expect("age lock");
        drop(file);
        let lock = FileLock::acquire(&path).expect("stale lock is replaced");
        assert!(lock_path.exists());
        drop(lock);
        assert!(!lock_path.exists());
    }

    #[test]
    fn session_with_same_scopes_is_reused() {
        let mut store = PendingOauthSessionStore {
            file: PendingOauthSessionsFile::default(),
            vault: None,
            scope: String::new(),
        };
        store.replace_matching(sample_session("mock"));
        assert!(store.get_matching("mock", BOTH, "client-123").is_some());
    }

    #[test]
    fn session_with_different_scopes_is_not_reused() {
        let mut store = PendingOauthSessionStore {
            file: PendingOauthSessionsFile::default(),
            vault: None,
            scope: String::new(),
        };
        let mut session = sample_session("mock");
        session.scopes = vec!["mail:imap_ro".to_string()];
        store.replace_matching(session);
        assert!(store.get_matching("mock", BOTH, "client-123").is_none());
    }

    #[test]
    fn legacy_session_without_scopes_is_not_reused_but_is_cleaned_up() {
        let mut store = PendingOauthSessionStore {
            file: PendingOauthSessionsFile::default(),
            vault: None,
            scope: String::new(),
        };
        let mut session = sample_session("mock");
        session.scopes = Vec::new();
        store.replace_matching(session);
        assert!(store.get_matching("mock", BOTH, "client-123").is_none());
        assert!(
            store
                .remove_matching("mock", BOTH, "client-123")
                .expect("remove")
        );
    }

    #[test]
    fn legacy_toml_without_scopes_field_parses_with_empty_scopes() {
        let toml_text = r#"
[[sessions]]
account = "mock"
services = ["mail"]
client_id = "client-123"
created_at_epoch_secs = 1
code_verifier = "v"

[sessions.authorization]
authorization_url = "https://example.test/authorize"
redirect_uri = "https://oauth.yandex.ru/verification_code"
state = "s"
code_challenge_method = "S256"
"#;
        let file: PendingOauthSessionsFile = toml::from_str(toml_text).expect("parse");
        assert!(file.sessions[0].scopes.is_empty());
    }
}
