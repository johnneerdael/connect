use std::io::Write;

use crate::{
    app::App,
    cli::RemoveArgs,
    error::{Error, Result},
    terminal::prompt::Prompt,
};

use super::add::validate_non_empty;

pub fn run(
    app: &App,
    prompt: &dyn Prompt,
    args: &RemoveArgs,
    writer: &mut dyn Write,
) -> Result<()> {
    let name = validate_non_empty("name", args.name.clone())?;

    if !args.yes && !prompt.confirm("remove", &format!("Remove profile '{name}'?"), false)? {
        writeln!(writer, "Aborted.").map_err(Error::from)?;
        return Ok(());
    }

    app.delete_profile(&name)?;
    writeln!(writer, "Removed profile '{name}'.").map_err(Error::from)
}
