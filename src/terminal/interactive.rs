use std::{env, future::Future, pin::Pin};

use crossterm::terminal;
use russh::{Channel, ChannelId, ChannelMsg};
use tokio::io::{self, AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use crate::error::{Error, Result};

type BoxFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

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
        let mut channel = RusshChannelAdapter { channel };
        let mut stdin = io::stdin();
        let mut stdout = io::stdout();
        let mut stderr = io::stderr();
        self.attach_io(&mut channel, &mut stdin, &mut stdout, &mut stderr, true)
            .await
    }

    pub async fn stream_command_output<S>(
        &self,
        channel: &mut Channel<S>,
        watch_resize: bool,
    ) -> Result<u32>
    where
        S: From<(ChannelId, ChannelMsg)> + Send + Sync + 'static,
    {
        let mut channel = RusshChannelAdapter { channel };
        let mut stdin = io::empty();
        let mut stdout = io::stdout();
        let mut stderr = io::stderr();
        self.attach_io(
            &mut channel,
            &mut stdin,
            &mut stdout,
            &mut stderr,
            watch_resize,
        )
        .await
    }

    async fn attach_io<C, I, O, E>(
        &self,
        channel: &mut C,
        stdin: &mut I,
        stdout: &mut O,
        stderr: &mut E,
        watch_resize: bool,
    ) -> Result<u32>
    where
        C: SessionChannel,
        I: AsyncRead + Unpin,
        O: AsyncWrite + Unpin,
        E: AsyncWrite + Unpin,
    {
        let mut buffer = vec![0; 1024];
        let mut stdin_open = true;
        let mut exit_status = None;
        let mut resize_stream = ResizeStream::new(watch_resize);

        loop {
            tokio::select! {
                biased;
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
                            break;
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
                read = stdin.read(&mut buffer), if stdin_open => {
                    match read {
                        Ok(0) => {
                            stdin_open = false;
                            channel.eof().await?;
                        }
                        Ok(count) => channel.data(&buffer[..count]).await?,
                        Err(error) => return Err(Error::from(error)),
                    }
                }
                resize = resize_stream.next(), if watch_resize => {
                    if resize {
                        let (columns, rows) = self.size();
                        channel.window_change(columns, rows, 0, 0).await?;
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

trait SessionChannel {
    fn data<'a>(&'a self, data: &'a [u8]) -> BoxFuture<'a, Result<()>>;
    fn eof<'a>(&'a self) -> BoxFuture<'a, Result<()>>;
    fn wait<'a>(&'a mut self) -> BoxFuture<'a, Option<ChannelMsg>>;
    fn window_change<'a>(
        &'a self,
        columns: u32,
        rows: u32,
        pix_width: u32,
        pix_height: u32,
    ) -> BoxFuture<'a, Result<()>>;
}

struct RusshChannelAdapter<'a, S>
where
    S: From<(ChannelId, ChannelMsg)> + Send + Sync + 'static,
{
    channel: &'a mut Channel<S>,
}

impl<S> SessionChannel for RusshChannelAdapter<'_, S>
where
    S: From<(ChannelId, ChannelMsg)> + Send + Sync + 'static,
{
    fn data<'a>(&'a self, data: &'a [u8]) -> BoxFuture<'a, Result<()>> {
        Box::pin(async move { self.channel.data(data).await.map_err(map_ssh_error) })
    }

    fn eof<'a>(&'a self) -> BoxFuture<'a, Result<()>> {
        Box::pin(async move { self.channel.eof().await.map_err(map_ssh_error) })
    }

    fn wait<'a>(&'a mut self) -> BoxFuture<'a, Option<ChannelMsg>> {
        Box::pin(async move { self.channel.wait().await })
    }

    fn window_change<'a>(
        &'a self,
        columns: u32,
        rows: u32,
        pix_width: u32,
        pix_height: u32,
    ) -> BoxFuture<'a, Result<()>> {
        Box::pin(async move {
            self.channel
                .window_change(columns, rows, pix_width, pix_height)
                .await
                .map_err(map_ssh_error)
        })
    }
}

struct ResizeStream {
    #[cfg(unix)]
    signal: Option<tokio::signal::unix::Signal>,
}

impl ResizeStream {
    fn new(enabled: bool) -> Self {
        #[cfg(unix)]
        {
            let signal = if enabled {
                tokio::signal::unix::signal(tokio::signal::unix::SignalKind::window_change()).ok()
            } else {
                None
            };
            Self { signal }
        }

        #[cfg(not(unix))]
        {
            let _ = enabled;
            Self {}
        }
    }

    async fn next(&mut self) -> bool {
        #[cfg(unix)]
        {
            match self.signal.as_mut() {
                Some(signal) => {
                    signal.recv().await;
                    true
                }
                None => std::future::pending::<bool>().await,
            }
        }

        #[cfg(not(unix))]
        {
            std::future::pending::<bool>().await
        }
    }
}

#[cfg(test)]
mod tests {
    use std::{
        collections::VecDeque,
        sync::{
            atomic::{AtomicUsize, Ordering},
            Mutex,
        },
        task::{Context, Poll},
    };

    use tokio::io::{sink, AsyncRead, ReadBuf};
    use tokio::time::{timeout, Duration};

    use super::*;

    #[tokio::test]
    async fn attach_returns_on_exit_status_without_waiting_for_channel_close() {
        let terminal = InteractiveTerminal;
        let mut channel =
            FakeSessionChannel::with_messages([ChannelMsg::ExitStatus { exit_status: 23 }]);
        let mut stdin = PendingReader;
        let mut stdout = sink();
        let mut stderr = sink();

        let exit_status = timeout(
            Duration::from_millis(100),
            terminal.attach_io(&mut channel, &mut stdin, &mut stdout, &mut stderr, false),
        )
        .await
        .expect("session loop should stop on exit status")
        .expect("session loop should return successfully");

        assert_eq!(exit_status, 23);
        assert_eq!(channel.sent_data_len(), 0);
    }

    struct PendingReader;

    impl AsyncRead for PendingReader {
        fn poll_read(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            _buf: &mut ReadBuf<'_>,
        ) -> Poll<std::io::Result<()>> {
            Poll::Pending
        }
    }

    struct FakeSessionChannel {
        messages: VecDeque<ChannelMsg>,
        sent_data: Mutex<Vec<Vec<u8>>>,
        eof_count: AtomicUsize,
    }

    impl FakeSessionChannel {
        fn with_messages(messages: impl IntoIterator<Item = ChannelMsg>) -> Self {
            Self {
                messages: messages.into_iter().collect(),
                sent_data: Mutex::new(Vec::new()),
                eof_count: AtomicUsize::new(0),
            }
        }

        fn sent_data_len(&self) -> usize {
            self.sent_data.lock().expect("poisoned sent_data").len()
        }
    }

    impl SessionChannel for FakeSessionChannel {
        fn data<'a>(&'a self, data: &'a [u8]) -> BoxFuture<'a, Result<()>> {
            Box::pin(async move {
                self.sent_data
                    .lock()
                    .expect("poisoned sent_data")
                    .push(data.to_vec());
                Ok(())
            })
        }

        fn eof<'a>(&'a self) -> BoxFuture<'a, Result<()>> {
            Box::pin(async move {
                self.eof_count.fetch_add(1, Ordering::SeqCst);
                Ok(())
            })
        }

        fn wait<'a>(&'a mut self) -> BoxFuture<'a, Option<ChannelMsg>> {
            Box::pin(async move {
                if let Some(message) = self.messages.pop_front() {
                    Some(message)
                } else {
                    std::future::pending().await
                }
            })
        }

        fn window_change<'a>(
            &'a self,
            _columns: u32,
            _rows: u32,
            _pix_width: u32,
            _pix_height: u32,
        ) -> BoxFuture<'a, Result<()>> {
            Box::pin(async move { Ok(()) })
        }
    }
}
