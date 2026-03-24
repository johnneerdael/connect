use std::io::Write;

use crate::{
    app::App,
    error::{Error, Result},
};

pub fn run(app: &App, writer: &mut dyn Write) -> Result<()> {
    for profile in app.list_profiles()? {
        writeln!(
            writer,
            "{}\t{}@{}:{}",
            profile.name, profile.username, profile.host, profile.port
        )
        .map_err(Error::from)?;
    }

    Ok(())
}
