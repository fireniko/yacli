use std::fs;

use chrono::{SecondsFormat, Utc};
use rand::{Rng, distr::Alphanumeric};
use serde::{Deserialize, Serialize};

use crate::activity_undo::ActivityUndoAction;
use crate::error::Result;
use crate::paths::activity_log_path;
use crate::persist::write_config_file;

const ACTIVITY_FILE_VERSION: u32 = 1;
const MAX_ACTIVITY_ENTRIES: usize = 200;

#[derive(Clone, Debug, Serialize, Deserialize, Eq, PartialEq)]
pub struct ActivityEntry {
    pub id: String,
    pub occurred_at: String,
    pub source: String,
    pub operation: String,
    pub account: String,
    pub summary: String,
    pub replay_command: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub undo: Option<ActivityUndoAction>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub undo_command: Option<String>,
}

#[derive(Clone, Debug)]
pub struct NewActivityEntry {
    pub source: String,
    pub operation: String,
    pub account: String,
    pub summary: String,
    pub replay_command: String,
    pub undo: Option<ActivityUndoAction>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct ActivityFile {
    #[serde(default = "default_version")]
    version: u32,
    #[serde(default)]
    entries: Vec<ActivityEntry>,
}

impl Default for ActivityFile {
    fn default() -> Self {
        Self {
            version: default_version(),
            entries: Vec::new(),
        }
    }
}

#[derive(Clone, Debug)]
pub struct ActivityStore {
    file: ActivityFile,
}

impl ActivityStore {
    pub fn load() -> Result<Self> {
        let path = activity_log_path()?;
        if !path.exists() {
            return Ok(Self {
                file: ActivityFile::default(),
            });
        }

        let content = fs::read_to_string(path)?;
        let file = toml::from_str::<ActivityFile>(&content)?;
        Ok(Self { file })
    }

    pub fn save(&self) -> Result<()> {
        let path = activity_log_path()?;
        let content = toml::to_string_pretty(&self.file)?;
        write_config_file(&path, &content)
    }

    pub fn entries(&self) -> &[ActivityEntry] {
        &self.file.entries
    }

    pub fn find(&self, id: &str) -> Option<&ActivityEntry> {
        self.file.entries.iter().find(|entry| entry.id == id)
    }

    /// Удаляет все записи (файл остаётся пустым журналом текущей версии).
    pub fn clear(&mut self) -> usize {
        let removed = self.file.entries.len();
        self.file = ActivityFile::default();
        removed
    }

    pub fn append(&mut self, new_entry: NewActivityEntry) -> ActivityEntry {
        let undo_command = new_entry
            .undo
            .as_ref()
            .map(ActivityUndoAction::command_line);
        let replay_command = redact_replay_command(&new_entry.operation, new_entry.replay_command);
        let entry = ActivityEntry {
            id: generate_activity_id(),
            occurred_at: Utc::now().to_rfc3339_opts(SecondsFormat::Secs, true),
            source: new_entry.source,
            operation: new_entry.operation,
            account: new_entry.account,
            summary: new_entry.summary,
            replay_command,
            undo: new_entry.undo,
            undo_command,
        };
        self.file.entries.insert(0, entry.clone());
        if self.file.entries.len() > MAX_ACTIVITY_ENTRIES {
            self.file.entries.truncate(MAX_ACTIVITY_ENTRIES);
        }
        entry
    }
}

/// Журнал не хранит содержимое пользователя (получателей, темы, имена файлов,
/// пути Диска, публичные ссылки). Для операций почты, календаря и Диска вместо
/// реальной команды сохраняется шаблон с плейсхолдерами; это единая точка
/// защиты, поэтому новые места записи не смогут случайно утечь в журнал.
/// Технический идентификатор для отката хранится только в `undo`/`undo_command`.
fn redact_replay_command(operation: &str, replay_command: String) -> String {
    if !(operation.starts_with("mail.")
        || operation.starts_with("calendar.")
        || operation.starts_with("disk."))
    {
        return replay_command;
    }
    if operation == "mail.send" {
        return "yacli mail send <получатель> <тема> <текст>".to_string();
    }
    let words = operation
        .trim_end_matches(".partial")
        .split('.')
        .map(|part| part.replace('_', "-"))
        .collect::<Vec<_>>()
        .join(" ");
    format!("yacli {words} <аргументы>")
}

pub fn record_activity(new_entry: NewActivityEntry) -> Result<ActivityEntry> {
    let mut store = ActivityStore::load()?;
    let entry = store.append(new_entry);
    store.save()?;
    Ok(entry)
}

const fn default_version() -> u32 {
    ACTIVITY_FILE_VERSION
}

fn generate_activity_id() -> String {
    let suffix: String = rand::rng()
        .sample_iter(Alphanumeric)
        .take(8)
        .map(char::from)
        .collect();
    format!("act_{}_{}", Utc::now().format("%Y%m%dT%H%M%SZ"), suffix)
}

pub fn clear_activity() -> Result<usize> {
    let mut store = ActivityStore::load()?;
    let removed = store.clear();
    store.save()?;
    Ok(removed)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mail_send_replay_has_no_values() {
        let replay = redact_replay_command(
            "mail.send",
            "yacli mail send 'me@example.com' 'Secret subject' 'x' --dry-run".to_string(),
        );
        assert_eq!(replay, "yacli mail send <получатель> <тема> <текст>");
    }

    #[test]
    fn other_operations_use_generic_placeholder() {
        let replay = |op: &str| redact_replay_command(op, "yacli x 'secret'".to_string());
        assert_eq!(
            replay("mail.send_link.partial"),
            "yacli mail send-link <аргументы>"
        );
        assert_eq!(
            replay("disk.public.download"),
            "yacli disk public download <аргументы>"
        );
        assert_eq!(
            replay("mail.invite.create_event"),
            "yacli mail invite create-event <аргументы>"
        );
        assert_eq!(
            replay("calendar.create"),
            "yacli calendar create <аргументы>"
        );
    }

    #[test]
    fn non_content_operations_keep_replay() {
        let kept = redact_replay_command("doctor.apply_safe", "yacli doctor --apply-safe".into());
        assert_eq!(kept, "yacli doctor --apply-safe");
        let undo = redact_replay_command("activity.undo", "yacli disk unpublish <путь>".into());
        assert_eq!(undo, "yacli disk unpublish <путь>");
    }

    #[test]
    fn append_redacts_and_clear_empties() {
        let mut store = ActivityStore {
            file: ActivityFile::default(),
        };
        let entry = store.append(NewActivityEntry {
            source: "cli".into(),
            operation: "mail.send".into(),
            account: "main".into(),
            summary: "Отправлено письмо (получателей: 1, вложений: 0)".into(),
            replay_command: "yacli mail send 'me@example.com' 'MARKER_SUBJECT' 'MARKER_BODY'"
                .into(),
            undo: None,
        });
        assert!(!entry.replay_command.contains("MARKER"));
        assert!(!entry.replay_command.contains("example.com"));
        assert_eq!(store.clear(), 1);
        assert!(store.entries().is_empty());
        let toml = toml::to_string_pretty(&store.file).unwrap();
        assert!(toml.contains("version = 1"));
    }

    #[test]
    fn legacy_entries_still_parse() {
        let legacy = r#"
version = 1

[[entries]]
id = "act_1"
occurred_at = "2026-01-01T00:00:00Z"
source = "cli"
operation = "mail.send"
account = "main"
summary = "Отправлено письмо a@example.com: тема"
replay_command = "yacli mail send a@example.com тема текст"
"#;
        let file: ActivityFile = toml::from_str(legacy).unwrap();
        assert_eq!(file.entries.len(), 1);
        assert!(file.entries[0].summary.contains("a@example.com"));
    }
}
