use std::io::Write;

use crate::{
    app::App,
    cli::DoctorArgs,
    error::{Error, Result},
};

use super::add::validate_non_empty;

pub fn run(app: &App, args: &DoctorArgs, writer: &mut dyn Write) -> Result<()> {
    if let Some(profile) = &args.profile {
        let profile = validate_non_empty("profile", profile.clone())?;
        let _ = app.get_profile(&profile)?;
        writeln!(writer, "Doctor checks passed for profile '{profile}'.").map_err(Error::from)
    } else {
        writeln!(writer, "Doctor checks passed.").map_err(Error::from)
    }
}
