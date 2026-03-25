use assert_cmd::Command as AssertCommand;
use clap::Parser;
use predicates::prelude::PredicateBooleanExt;

use connect::cli::{Cli, Command as CliCommand, ForwardCommand};

fn connect_test_bin() -> AssertCommand {
    AssertCommand::cargo_bin("connect").expect("binary should build")
}

fn parse_cli(args: &[&str]) -> Cli {
    Cli::try_parse_from(args).expect("CLI should parse")
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
fn doctor_parses_as_local_only_command() {
    let local = parse_cli(&["connect", "doctor"]);
    assert!(matches!(local.command, Some(CliCommand::Doctor(_))));
    assert!(local.profile.is_none());
}

#[test]
fn doctor_help_does_not_advertise_a_profile_argument() {
    let mut cmd = connect_test_bin();
    cmd.args(["doctor", "--help"])
        .assert()
        .success()
        .stdout(predicates::str::contains("Inspect the local environment"))
        .stdout(predicates::str::contains("PROFILE").not());
}

#[test]
fn forward_add_and_run_parse_with_explicit_subcommands() {
    let add = parse_cli(&[
        "connect",
        "forward",
        "add",
        "prod",
        "db",
        "--local",
        "127.0.0.1:15432:db.internal:5432",
    ]);
    match add.command {
        Some(CliCommand::Forward(args)) => match args.command {
            ForwardCommand::Add(args) => {
                assert_eq!(args.profile, "prod");
                assert_eq!(args.name, "db");
                assert_eq!(
                    args.local.as_deref(),
                    Some("127.0.0.1:15432:db.internal:5432")
                );
                assert!(args.socks.is_none());
            }
            other => panic!("expected forward add command, got {other:?}"),
        },
        other => panic!("expected forward command, got {other:?}"),
    }

    let run = parse_cli(&["connect", "forward", "run", "prod", "--all"]);
    match run.command {
        Some(CliCommand::Forward(args)) => match args.command {
            ForwardCommand::Run(args) => {
                assert_eq!(args.profile, "prod");
                assert!(args.name.is_none());
                assert!(args.all);
            }
            other => panic!("expected forward run command, got {other:?}"),
        },
        other => panic!("expected forward command, got {other:?}"),
    }
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
fn copy_parses_resume_and_progress_flags() {
    let cli = parse_cli(&[
        "connect",
        "copy",
        "--resume",
        "--progress",
        "artifact.txt",
        "prod:/tmp/artifact.txt",
    ]);

    match cli.command {
        Some(CliCommand::Copy(args)) => {
            assert!(args.resume);
            assert!(args.progress);
            assert!(!args.recursive);
            assert_eq!(args.source, "artifact.txt");
            assert_eq!(args.destination, "prod:/tmp/artifact.txt");
        }
        other => panic!("expected copy command, got {other:?}"),
    }
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
