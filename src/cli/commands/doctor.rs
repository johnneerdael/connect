use std::io::Write;

use crate::{cli::DoctorArgs, doctor, error::Result};

pub fn run(
    _args: &DoctorArgs,
    writer: &mut dyn Write,
) -> Result<doctor::checks::LocalDoctorReport> {
    doctor::run(writer)
}
