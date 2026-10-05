//! Журнал действий не должен хранить содержимое пользователя.

use assert_cmd::Command;
use mockito::{Matcher, Server};
use serde_json::Value;
use std::fs;
use tempfile::tempdir;

fn yacli() -> Command {
    let mut command = Command::cargo_bin("yacli").expect("binary exists");
    command.env("YACLI_SECRET_BACKEND", "file");
    command
}

fn activity_toml(dir: &std::path::Path) -> String {
    fs::read_to_string(dir.join("activity.toml")).unwrap_or_default()
}

fn run_json(dir: &std::path::Path, args: &[&str]) -> (String, Value) {
    let out = yacli()
        .env("YACLI_CONFIG_DIR", dir)
        .args(args)
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let text = String::from_utf8(out).expect("utf8");
    let value = serde_json::from_str(&text).expect("json");
    (text, value)
}

#[test]
fn mail_send_entry_contains_no_recipient_subject_or_body() {
    let temp = tempdir().expect("tempdir");
    // Единственный тест в этом процессе, который читает конфиг через библиотеку.
    unsafe { std::env::set_var("YACLI_CONFIG_DIR", temp.path()) };

    yacli::activity_store::record_activity(yacli::activity_store::NewActivityEntry {
        source: "cli".to_string(),
        operation: "mail.send".to_string(),
        account: "mock".to_string(),
        summary: "Отправлено письмо (получателей: 1, вложений: 0)".to_string(),
        replay_command:
            "yacli mail send 'MARKER_TO@example.test' 'MARKER_SUBJECT' 'MARKER_BODY' --dry-run"
                .to_string(),
        undo: None,
    })
    .expect("record");

    let file = activity_toml(temp.path());
    for marker in ["MARKER_TO", "MARKER_SUBJECT", "MARKER_BODY", "example.test"] {
        assert!(!file.contains(marker), "{marker} leaked into activity.toml");
    }

    let (list, value) = run_json(temp.path(), &["activity", "list"]);
    let id = value["items"][0]["id"].as_str().expect("id").to_string();
    let (show, _) = run_json(temp.path(), &["activity", "show", &id]);
    for marker in ["MARKER_TO", "MARKER_SUBJECT", "MARKER_BODY"] {
        assert!(!list.contains(marker) && !show.contains(marker));
    }
    assert_eq!(
        value["items"][0]["replay_command"],
        "yacli mail send <получатель> <тема> <текст>"
    );
}

#[test]
fn clear_requires_yes_and_empties_log() {
    let temp = tempdir().expect("tempdir");
    fs::write(
        temp.path().join("activity.toml"),
        r#"
version = 1

[[entries]]
id = "act_1"
occurred_at = "2026-01-01T00:00:00Z"
source = "cli"
operation = "mail.send"
account = "mock"
summary = "Отправлено письмо old@example.test: старая тема"
replay_command = "yacli mail send old@example.test 'старая тема' text"
"#,
    )
    .expect("write legacy log");

    // Старые записи читаются как раньше.
    let (_, value) = run_json(temp.path(), &["activity", "list"]);
    assert_eq!(value["items"].as_array().expect("items").len(), 1);

    let output = yacli()
        .env("YACLI_CONFIG_DIR", temp.path())
        .args(["activity", "clear"])
        .assert()
        .failure()
        .get_output()
        .clone();
    let all = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(all.contains("--yes"), "hint missing: {all}");
    assert!(activity_toml(temp.path()).contains("old@example.test"));

    let (_, cleared) = run_json(temp.path(), &["activity", "clear", "--yes"]);
    assert_eq!(cleared["removed"], 1);
    let file = activity_toml(temp.path());
    assert!(file.contains("version = 1"));
    assert!(!file.contains("example.test"));
    let (_, value) = run_json(temp.path(), &["activity", "list"]);
    assert_eq!(value["items"].as_array().expect("items").len(), 0);
}

#[test]
fn disk_publish_log_hides_public_link_and_undo_still_works() {
    let temp = tempdir().expect("tempdir");
    let mut server = Server::new();
    fs::write(
        temp.path().join("accounts.toml"),
        format!(
            r#"
version = 1

[accounts.mock]
email = "me@example.test"
default = true

[accounts.mock.mail]
enabled = true
auth_mode = "oauth_xoauth2"
imap_host = "imap.yandex.com"
imap_port = 993
smtp_host = "smtp.yandex.com"
smtp_port = 465

[accounts.mock.calendar]
enabled = true
auth_mode = "app_password"
caldav_base_url = "https://caldav.yandex.ru"

[accounts.mock.disk]
enabled = true
auth_mode = "oauth"
rest_base_url = "{}"
credential_ref = "store:disk"
"#,
            server.url()
        ),
    )
    .expect("accounts");
    fs::write(
        temp.path().join("credentials.toml"),
        r#"
version = 1

[accounts.mock.services.disk]
kind = "oauth_pkce"
access_token = "disk-token"
token_type = "bearer"
expires_at_epoch_secs = 4102444800
scope = ["cloud_api:disk.write"]
client_id = "client-123"
"#,
    )
    .expect("credentials");

    let query = || {
        Matcher::AllOf(vec![
            Matcher::UrlEncoded("path".into(), "disk:/docs/report.pdf".into()),
            Matcher::UrlEncoded("limit".into(), "100".into()),
            Matcher::UrlEncoded("offset".into(), "0".into()),
        ])
    };
    let path_only = || Matcher::UrlEncoded("path".into(), "disk:/docs/report.pdf".into());
    let _publish = server
        .mock("PUT", "/v1/disk/resources/publish")
        .match_query(path_only())
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body("{}")
        .create();
    let _meta_published = server
        .mock("GET", "/v1/disk/resources")
        .match_query(query())
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(
            r#"{"name":"report.pdf","path":"disk:/docs/report.pdf","type":"file","size":42,
"public_url":"https://disk.example.test/i/MARKER_PUBLIC","public_key":"MARKER_KEY"}"#,
        )
        .expect(2)
        .create();
    let _unpublish = server
        .mock("PUT", "/v1/disk/resources/unpublish")
        .match_query(path_only())
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body("{}")
        .create();
    let _meta_unpublished = server
        .mock("GET", "/v1/disk/resources")
        .match_query(query())
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(
            r#"{"name":"report.pdf","path":"disk:/docs/report.pdf","type":"file","size":42}"#,
        )
        .create();

    yacli()
        .env("YACLI_CONFIG_DIR", temp.path())
        .args([
            "disk",
            "publish",
            "--account",
            "mock",
            "disk:/docs/report.pdf",
        ])
        .assert()
        .success();

    let file = activity_toml(temp.path());
    assert!(!file.contains("MARKER_PUBLIC") && !file.contains("MARKER_KEY"));
    let (_, list) = run_json(temp.path(), &["activity", "list"]);
    let item = &list["items"][0];
    assert_eq!(item["summary"], "Опубликован ресурс на Диске");
    assert_eq!(item["replay_command"], "yacli disk publish <аргументы>");
    // Технический идентификатор для отката остаётся.
    assert_eq!(item["undo"]["kind"], "disk_unpublish");
    let id = item["id"].as_str().expect("id").to_string();

    let (_, undo) = run_json(temp.path(), &["activity", "undo", &id]);
    assert_eq!(undo["operation"], "activity.undo");
    assert_eq!(undo["undo"]["result"]["kind"], "disk_unpublish");

    let file = activity_toml(temp.path());
    assert!(!file.contains("MARKER_PUBLIC") && !file.contains("MARKER_KEY"));
    let (_, list) = run_json(temp.path(), &["activity", "list"]);
    assert_eq!(list["items"][0]["operation"], "activity.undo");
    assert_eq!(
        list["items"][0]["replay_command"],
        "yacli disk unpublish <путь>"
    );
    assert!(
        !list["items"][0]["summary"]
            .as_str()
            .expect("summary")
            .contains("MARKER")
    );
}
