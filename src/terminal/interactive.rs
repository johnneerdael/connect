use std::env;

use crossterm::terminal;
use russh::{Channel, ChannelId, ChannelMsg};
use tokio::io::{self, AsyncReadExt, AsyncWriteExt};

use crate::error::{Error, Result};

#[derive(Debug, Clone, Default)]
pub struct InteractiveTerminal;

impl InteractiveTerminal {
    pub fn size(&self) -> (u32, u32) {
        match terminal::size() {
            Ok((columns, rows)) => (u32::from(columns), u32::from(rows)),
            Err(_) => (80, 24),
        }
    }

    pub fn term(&self) -> String {
        env::var("TERM").unwrap_or_else(|_| "xterm-256color".to_string())
    }

    pub async fn attach<S>(&self, channel: &mut Channel<S>) -> Result<u32>
    where
        S: From<(ChannelId, ChannelMsg)> + Send + Sync + 'static,
    {
        let _raw_mode = RawModeGuard::new()?;
        let mut stdin = io::stdin();
        let mut stdout = io::stdout();
        let mut stderr = io::stderr();
        let mut buffer = vec![0; 1024];
        let mut stdin_open = true;
        let mut exit_status = None;

        loop {
            tokio::select! {
                read = stdin.read(&mut buffer), if stdin_open => {
                    match read {
                        Ok(0) => {
                            stdin_open = false;
                            channel.eof().await.map_err(map_ssh_error)?;
                        }
                        Ok(count) => channel.data(&buffer[..count]).await.map_err(map_ssh_error)?,
                        Err(error) => return Err(Error::from(error)),
                    }
                }
                message = channel.wait() => {
                    let Some(message) = message else {
                        break;
                    };

                    match message {
                        ChannelMsg::Data { ref data } => {
                            stdout.write_all(data).await?;
                            stdout.flush().await?;
                        }
                        ChannelMsg::ExtendedData { ref data, .. } => {
                            stderr.write_all(data).await?;
                            stderr.flush().await?;
                        }
                        ChannelMsg::Eof | ChannelMsg::Close => break,
                        ChannelMsg::ExitStatus { exit_status: status } => {
                            exit_status = Some(status);
                        }
                        ChannelMsg::ExitSignal { signal_name, .. } => {
                            return Err(Error::new(format!(
                                "remote session terminated by signal {:?}",
                                signal_name
                            )));
                        }
                        _ => {}
                    }
                }
            }
        }

        Ok(exit_status.unwrap_or(0))
    }
}

struct RawModeGuard {
    enabled: bool,
}

impl RawModeGuard {
    fn new() -> Result<Self> {
        terminal::enable_raw_mode()
            .map_err(|error| Error::new(format!("terminal error: {error}")))?;
        Ok(Self { enabled: true })
    }
}

impl Drop for RawModeGuard {
    fn drop(&mut self) {
        if self.enabled {
            let _ = terminal::disable_raw_mode();
        }
    }
}

fn map_ssh_error(error: impl std::fmt::Display) -> Error {
    Error::new(format!("ssh error: {error}"))
}
