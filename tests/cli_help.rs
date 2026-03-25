use assert_cmd::Command;

fn connect_test_bin() -> Command {
    Command::cargo_bin("connect").expect("binary should build")
}

#[test]
fn root_help_lists_core_commands() {
    let mut cmd = connect_test_bin();
    cmd.arg("--help")
        .assert()
        .success()
        .stdout(predicates::str::contains("open"))
        .stdout(predicates::str::contains("exec"))
        .stdout(predicates::str::contains("add"))
        .stdout(predicates::str::contains("copy"))
        .stdout(predicates::str::contains("hostkeys"))
        .stdout(predicates::str::contains("Open an interactive SSH shell"));
}

#[test]
fn root_help_lists_doctor_and_forward_commands() {
    let mut cmd = connect_test_bin();
    cmd.arg("--help")
        .assert()
        .success()
        .stdout(predicates::str::contains("doctor"))
        .stdout(predicates::str::contains("forward"));
}

#[test]
fn version_command_prints_binary_version() {
    let mut cmd = connect_test_bin();
    cmd.arg("version")
        .assert()
        .success()
        .stdout(predicates::str::contains(env!("CARGO_PKG_VERSION")));
}

#[test]
fn root_version_prints_binary_version() {
    let mut cmd = connect_test_bin();
    cmd.arg("--version")
        .assert()
        .success()
        .stdout(predicates::str::contains("connect"))
        .stdout(predicates::str::contains(env!("CARGO_PKG_VERSION")));
}

#[test]
fn positional_profile_parses_as_default_connect_action() {
    let mut cmd = connect_test_bin();
    cmd.arg("prod")
        .assert()
        .failure()
        .stderr(predicates::str::contains("profile 'prod' was not found"));
}

#[test]
fn completion_command_accepts_shell_argument() {
    let mut cmd = connect_test_bin();
    cmd.args(["completion", "bash"])
        .assert()
        .success()
        .stdout(predicates::str::contains("connect"));
}

#[test]
fn doctor_help_lists_optional_profile_argument() {
    let mut cmd = connect_test_bin();
    cmd.args(["doctor", "--help"])
        .assert()
        .success()
        .stdout(predicates::str::contains("PROFILE"));
}

#[test]
fn forward_help_lists_subcommands() {
    let mut cmd = connect_test_bin();
    cmd.args(["forward", "--help"])
        .assert()
        .success()
        .stdout(predicates::str::contains("add"))
        .stdout(predicates::str::contains("list"))
        .stdout(predicates::str::contains("remove"))
        .stdout(predicates::str::contains("run"));
}

#[test]
fn add_help_lists_secure_secret_input_flags() {
    let mut cmd = connect_test_bin();
    cmd.args(["add", "--help"])
        .assert()
        .success()
        .stdout(predicates::str::contains("--auth-mode"))
        .stdout(predicates::str::contains("--password"))
        .stdout(predicates::str::contains("--password-stdin"))
        .stdout(predicates::str::contains("--key-passphrase-stdin"));
}

#[test]
fn open_help_lists_profile_argument() {
    let mut cmd = connect_test_bin();
    cmd.args(["open", "--help"])
        .assert()
        .success()
        .stdout(predicates::str::contains("PROFILE"));
}

#[test]
fn copy_help_lists_resume_and_progress_flags() {
    let mut cmd = connect_test_bin();
    cmd.args(["copy", "--help"])
        .assert()
        .success()
        .stdout(predicates::str::contains("--resume"))
        .stdout(predicates::str::contains("--progress"));
}

#[test]
fn exec_help_lists_pty_and_command_usage() {
    let mut cmd = connect_test_bin();
    cmd.args(["exec", "--help"])
        .assert()
        .success()
        .stdout(predicates::str::contains("--pty"))
        .stdout(predicates::str::contains("COMMAND"));
}

#[test]
fn exec_command_accepts_separator_and_trailing_args() {
    let mut cmd = connect_test_bin();
    cmd.args(["exec", "prod", "--", "printf", "hello"])
        .assert()
        .failure()
        .stderr(predicates::str::contains("profile 'prod' was not found"));
}
