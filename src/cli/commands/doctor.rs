use std::io::Write;

use crate::{doctor, error::Result};

pub fn run(writer: &mut dyn Write) -> Result<doctor::checks::LocalDoctorReport> {
    doctor::run(writer)
}
