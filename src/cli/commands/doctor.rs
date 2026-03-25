use std::io::Write;

use crate::{
    app::App,
    cli::DoctorArgs,
    doctor::{self, DefaultDoctorEnvironment},
    error::Result,
    ssh::RusshClient,
};

use super::add::validate_non_empty;

pub fn run(
    app: &App,
    args: &DoctorArgs,
    writer: &mut dyn Write,
) -> Result<doctor::checks::LocalDoctorReport> {
    match args.profile.as_ref() {
        Some(profile) => run_profile(app, profile, writer),
        None => run_local(writer),
    }
}

pub fn run_local(writer: &mut dyn Write) -> Result<doctor::checks::LocalDoctorReport> {
    doctor::run(writer)
}

fn run_profile(
    app: &App,
    profile: &str,
    writer: &mut dyn Write,
) -> Result<doctor::checks::LocalDoctorReport> {
    let profile = validate_non_empty("profile", profile.to_string())?;
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?;
    let ssh = RusshClient::new();
    let report = runtime.block_on(doctor::collect_profile_checks(
        &DefaultDoctorEnvironment,
        app,
        &profile,
        &ssh,
    ));
    doctor::output::write_report(&report, writer)?;
    Ok(report)
}
