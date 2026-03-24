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
        .stdout(predicates::str::contains("add"))
        .stdout(predicates::str::contains("copy"))
        .stdout(predicates::str::contains("hostkeys"))
        .stdout(predicates::str::contains("Add a new SSH profile"));
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
fn add_help_lists_secure_secret_input_flags() {
    let mut cmd = connect_test_bin();
    cmd.args(["add", "--help"])
        .assert()
        .success()
        .stdout(predicates::str::contains("--password"))
        .stdout(predicates::str::contains("--password-stdin"))
        .stdout(predicates::str::contains("--key-passphrase-stdin"));
}
