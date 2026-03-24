use crate::{
    app::App,
    cli::CopyArgs,
    error::Result,
    ssh::{parse_copy_spec, RusshClient},
    terminal::prompt::Prompt,
};

pub fn run(app: &App, prompt: &dyn Prompt, args: &CopyArgs) -> Result<()> {
    let spec = parse_copy_spec(&args.source, &args.destination, args.recursive)?;
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?;
    let ssh = RusshClient::new();

    runtime.block_on(app.copy(&spec, &ssh, prompt))
}
