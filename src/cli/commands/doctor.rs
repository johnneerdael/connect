use std::io::Write;

use crate::{
    cli::DoctorArgs,
    doctor::{
        self,
        checks::{LocalDoctorCheckResult, LocalDoctorCheckStatus},
        DefaultDoctorEnvironment,
    },
    error::Result,
    ssh::RusshClient,
};

use super::add::validate_non_empty;

pub fn run(args: &DoctorArgs, writer: &mut dyn Write) -> Result<doctor::checks::LocalDoctorReport> {
    match args.profile.as_ref() {
        Some(profile) => run_profile(profile, writer),
        None => run_local(writer),
    }
}

pub fn run_local(writer: &mut dyn Write) -> Result<doctor::checks::LocalDoctorReport> {
    doctor::run(writer)
}

fn run_profile(profile: &str, writer: &mut dyn Write) -> Result<doctor::checks::LocalDoctorReport> {
    let profile = validate_non_empty("profile", profile.to_string())?;
    let mut report = doctor::collect_local_checks(&DefaultDoctorEnvironment);
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?;
    let ssh = RusshClient::new();
    match crate::app::App::load() {
        Ok(app) => {
            let profile_report = runtime.block_on(doctor::collect_profile_specific_checks(
                &app,
                &profile,
                &ssh,
            ));
            report.checks.extend(profile_report.checks);
        }
        Err(error) => report.checks.push(LocalDoctorCheckResult {
            name: "profile app initialization".into(),
            status: LocalDoctorCheckStatus::Fail,
            detail: error.to_string(),
        }),
    }
    doctor::output::write_report(&report, writer)?;
    Ok(report)
}
