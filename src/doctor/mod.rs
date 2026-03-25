pub mod checks;
pub mod output;

use std::io::Write;

pub use checks::{collect_local_checks, DefaultDoctorEnvironment, LocalDoctorReport};

use crate::error::Result;

pub fn run(writer: &mut dyn Write) -> Result<LocalDoctorReport> {
    let report = collect_local_checks(&DefaultDoctorEnvironment);
    output::write_report(&report, writer)?;
    Ok(report)
}
