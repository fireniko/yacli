use assert_cmd::Command;
use predicates::prelude::*;
use tempfile::tempdir;

fn yacli() -> Command {
    let mut command = Command::cargo_bin("yacli").expect("binary exists");
    command.env("YACLI_SECRET_BACKEND", "file");
    command
}

#[test]
fn top_level_help_exposes_mcp_command() {
    yacli()
        .args(["--help"])
        .assert()
        .success()
        .stdout(predicate::str::contains("mcp"))
        .stdout(predicate::str::contains("Запустить MCP сервер"));
}

#[test]
fn mcp_help_describes_server_mode() {
    yacli()
        .args(["mcp", "--help"])
        .assert()
        .success()
        .stdout(predicate::str::contains("yacli mcp"))
        .stdout(predicate::str::contains("stdio"))
        .stdout(predicate::str::contains("http"))
        .stdout(predicate::str::contains("listen"))
        .stdout(predicate::str::contains("install").not());
}

#[test]
fn mcp_install_subcommand_is_removed_and_writes_no_client_files() {
    let home = tempdir().expect("home tempdir");
    let config = tempdir().expect("config tempdir");

    yacli()
        .env("HOME", home.path())
        .env("USERPROFILE", home.path())
        .env("YACLI_CONFIG_DIR", config.path())
        .args(["mcp", "install", "--client", "claude"])
        .assert()
        .failure();

    // Nothing may be written into the (fake) home directory.
    assert_eq!(
        std::fs::read_dir(home.path()).expect("read home").count(),
        0,
        "removed `mcp install` must not create any files"
    );
}

#[test]
fn removed_install_flags_are_rejected_by_setup() {
    for flag in ["--client", "--mcp-transport", "--skip-mcp-install"] {
        let mut cmd = yacli();
        cmd.args(["setup", "me@yandex.ru", flag]);
        if flag != "--skip-mcp-install" {
            cmd.arg("claude");
        }
        cmd.assert().failure();
    }
}
