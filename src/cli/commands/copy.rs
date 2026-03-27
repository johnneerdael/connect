use crate::{
    app::App,
    cli::CopyArgs,
    error::Result,
    ssh::{parse_copy_spec, CopySpec, CopySummary, RusshClient},
    terminal::prompt::Prompt,
};
use std::io::{self, Write};

pub fn run(app: &App, prompt: &dyn Prompt, args: &CopyArgs) -> Result<()> {
    let spec = prepare_copy_spec(app, args)?;
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?;
    let ssh = RusshClient::new();

    let summary = runtime.block_on(app.copy(&spec, &ssh, prompt))?;
    emit_summary(&summary)?;
    Ok(())
}

pub fn emit_summary(summary: &CopySummary) -> Result<()> {
    let mut stderr = io::stderr().lock();
    emit_summary_to(summary, &mut stderr)
}

pub fn emit_summary_to(summary: &CopySummary, out: &mut impl Write) -> Result<()> {
    writeln!(out, "{summary}")?;
    Ok(())
}

pub fn prepare_copy_spec(app: &App, args: &CopyArgs) -> Result<CopySpec> {
    let mut spec = parse_copy_spec(
        &args.source,
        &args.destination,
        args.recursive,
        args.resume,
        args.progress,
    )?;
    spec.effective_threads = app.effective_copy_threads(spec.remote_profile(), args.threads)?;
    Ok(spec)
}
