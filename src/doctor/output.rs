use std::io::Write;

use crate::error::{Error, Result};

use super::checks::{LocalDoctorCheckStatus, LocalDoctorReport};

pub fn write_report(report: &LocalDoctorReport, writer: &mut dyn Write) -> Result<()> {
    for check in &report.checks {
        write_check(check, writer)?;
    }

    Ok(())
}

fn write_check(
    check: &super::checks::LocalDoctorCheckResult,
    writer: &mut dyn Write,
) -> Result<()> {
    match check.status {
        LocalDoctorCheckStatus::Pass => {
            writeln!(writer, "PASS {}", check.name).map_err(Error::from)
        }
        LocalDoctorCheckStatus::Fail => {
            writeln!(writer, "FAIL {}: {}", check.name, check.detail).map_err(Error::from)
        }
    }
}
