use std::{
    future::Future,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
    time::Duration,
};

use tokio::{
    io::copy_bidirectional,
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    sync::mpsc,
    task::JoinSet,
    time::{self, MissedTickBehavior},
};

use crate::{
    error::{Error, Result},
    ssh::{connect_authenticated_session, DirectTcpipStream, SshClient, SshConnectionContext},
    store::{ForwardDefinition, ForwardKind, Profile},
    terminal::prompt::Prompt,
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SavedForwardSelection {
    Named(String),
    All,
}

struct BoundForward {
    definition: ForwardDefinition,
    listener: TcpListener,
}

enum ForwardRoute {
    Local {
        target_host: String,
        target_port: u16,
    },
    Socks,
}

struct OpenTunnelRequest<'a> {
    forward_name: &'a str,
    target_host: &'a str,
    target_port: u16,
    origin_host: &'a str,
    origin_port: u16,
    send_socks_success: bool,
}

struct PendingSocksTunnel {
    local_stream: TcpStream,
    target_host: String,
    target_port: u16,
    origin_host: String,
    origin_port: u16,
}

struct AcceptedConnection {
    local_stream: TcpStream,
    origin_host: String,
    origin_port: u16,
}

pub async fn run_saved_forwards<F>(
    ssh: &dyn SshClient,
    profile: &Profile,
    definitions: Vec<ForwardDefinition>,
    context: &dyn SshConnectionContext,
    prompt: &dyn Prompt,
    shutdown: F,
) -> Result<()>
where
    F: Future<Output = ()> + Send,
{
    if definitions.is_empty() {
        return Err(Error::new(format!(
            "profile '{}' has no saved forwards to run",
            profile.name
        )));
    }

    let mut bound = bind_requested_forwards(definitions).await?;
    let mut sessions = Vec::with_capacity(bound.len());
    for _ in &bound {
        sessions.push(connect_authenticated_session(ssh, profile, context, prompt).await?);
    }

    let stop = Arc::new(AtomicBool::new(false));
    let mut listeners = JoinSet::new();
    for (bound_forward, session) in bound.drain(..).zip(sessions.drain(..)) {
        let stop = Arc::clone(&stop);
        listeners.spawn(async move { run_listener(bound_forward, session, stop).await });
    }

    tokio::pin!(shutdown);
    let result = tokio::select! {
        _ = &mut shutdown => Ok(()),
        joined = listeners.join_next() => match joined {
            Some(Ok(result)) => result,
            Some(Err(error)) => Err(Error::new(format!("forward supervisor task failed: {error}"))),
            None => Ok(()),
        },
    };

    stop.store(true, Ordering::SeqCst);
    while let Some(joined) = listeners.join_next().await {
        match joined {
            Ok(Ok(())) => {}
            Ok(Err(error)) if result.is_ok() => return Err(error),
            Ok(Err(_)) => {}
            Err(error) if result.is_ok() => {
                return Err(Error::new(format!(
                    "forward supervisor task failed: {error}"
                )));
            }
            Err(_) => {}
        }
    }

    result
}

async fn bind_requested_forwards(definitions: Vec<ForwardDefinition>) -> Result<Vec<BoundForward>> {
    let mut bound = Vec::with_capacity(definitions.len());
    for definition in definitions {
        ensure_supported_local_forward(&definition)?;
        let address = format!("{}:{}", definition.bind_host, definition.bind_port);
        let listener = TcpListener::bind(&address).await.map_err(|error| {
            Error::new(format!(
                "failed to bind local forward '{}' on {}: {}",
                definition.name, address, error
            ))
        })?;
        bound.push(BoundForward {
            definition,
            listener,
        });
    }

    Ok(bound)
}

fn ensure_supported_local_forward(definition: &ForwardDefinition) -> Result<()> {
    match definition.kind {
        ForwardKind::Local => {
            if definition.target_host.is_none() || definition.target_port.is_none() {
                Err(Error::new(format!(
                    "local forward '{}' is missing its target endpoint",
                    definition.name
                )))
            } else {
                Ok(())
            }
        }
        ForwardKind::Socks => Ok(()),
    }
}

async fn run_listener(
    bound_forward: BoundForward,
    mut session: Box<dyn crate::ssh::SshSession + Send + 'static>,
    stop: Arc<AtomicBool>,
) -> Result<()> {
    let forward_name = bound_forward.definition.name.clone();
    let route = match bound_forward.definition.kind {
        ForwardKind::Local => ForwardRoute::Local {
            target_host: bound_forward
                .definition
                .target_host
                .clone()
                .expect("local forward target host should be validated"),
            target_port: bound_forward
                .definition
                .target_port
                .expect("local forward target port should be validated"),
        },
        ForwardKind::Socks => ForwardRoute::Socks,
    };
    let mut proxy_tasks = JoinSet::new();
    let (accepted_tx, mut accepted_rx) = mpsc::unbounded_channel::<AcceptedConnection>();
    let (prepared_socks_tx, mut prepared_socks_rx) =
        mpsc::unbounded_channel::<PendingSocksTunnel>();
    let mut accept_tasks = JoinSet::new();
    match route {
        ForwardRoute::Local { .. } => {
            accept_tasks.spawn(accept_connections(bound_forward.listener, accepted_tx));
        }
        ForwardRoute::Socks => {
            accept_tasks.spawn(accept_socks_connections(
                bound_forward.listener,
                prepared_socks_tx,
            ));
        }
    }
    let mut health_check = time::interval(Duration::from_millis(200));
    health_check.set_missed_tick_behavior(MissedTickBehavior::Delay);

    loop {
        tokio::select! {
            _ = health_check.tick() => {
                while let Some(joined) = proxy_tasks.try_join_next() {
                    match joined {
                        Ok(Ok(())) => {}
                        Ok(Err(_)) => {}
                        Err(error) => {
                            return Err(Error::new(format!(
                                "proxy task for forward '{forward_name}' failed: {error}"
                            )));
                        }
                    }
                }

                if stop.load(Ordering::SeqCst) {
                    break;
                }

                if !session.is_alive() {
                    return Err(Error::new(format!(
                        "ssh session for forward '{forward_name}' disconnected"
                    )));
                }
            }
            joined = accept_tasks.join_next(), if !accept_tasks.is_empty() => {
                match joined {
                    Some(Ok(Ok(()))) => {}
                    Some(Ok(Err(error))) => return Err(error),
                    Some(Err(error)) => {
                        return Err(Error::new(format!(
                            "forward accept task for '{forward_name}' failed: {error}"
                        )));
                    }
                    None => {}
                }
            }
            accepted = accepted_rx.recv(), if matches!(route, ForwardRoute::Local { .. }) => {
                let Some(AcceptedConnection {
                    local_stream,
                    origin_host,
                    origin_port,
                }) = accepted else {
                    break;
                };
                match route {
                    ForwardRoute::Local {
                        ref target_host,
                        target_port,
                    } => {
                        open_tunnel_or_continue(
                            &mut session,
                            local_stream,
                            OpenTunnelRequest {
                                forward_name: &forward_name,
                                target_host,
                                target_port,
                                origin_host: &origin_host,
                                origin_port,
                                send_socks_success: false,
                            },
                            &mut proxy_tasks,
                        )
                        .await?;
                    }
                    ForwardRoute::Socks => unreachable!("socks listeners use the prepared tunnel queue"),
                }
            }
            prepared = prepared_socks_rx.recv(), if matches!(route, ForwardRoute::Socks) => {
                let Some(pending) = prepared else {
                    break;
                };
                open_tunnel_or_continue(
                    &mut session,
                    pending.local_stream,
                    OpenTunnelRequest {
                        forward_name: &forward_name,
                        target_host: &pending.target_host,
                        target_port: pending.target_port,
                        origin_host: &pending.origin_host,
                        origin_port: pending.origin_port,
                        send_socks_success: true,
                    },
                    &mut proxy_tasks,
                )
                .await?;
            }
        }
    }

    accept_tasks.abort_all();
    while accept_tasks.join_next().await.is_some() {}
    proxy_tasks.abort_all();
    while proxy_tasks.join_next().await.is_some() {}
    let _ = session.disconnect().await;
    Ok(())
}

async fn accept_connections(
    listener: TcpListener,
    accepted_tx: mpsc::UnboundedSender<AcceptedConnection>,
) -> Result<()> {
    loop {
        let (local_stream, peer_addr) = listener.accept().await?;
        if accepted_tx
            .send(AcceptedConnection {
                local_stream,
                origin_host: peer_addr.ip().to_string(),
                origin_port: peer_addr.port(),
            })
            .is_err()
        {
            return Ok(());
        }
    }
}

async fn accept_socks_connections(
    listener: TcpListener,
    prepared_tx: mpsc::UnboundedSender<PendingSocksTunnel>,
) -> Result<()> {
    let mut handshakes: JoinSet<Result<Option<PendingSocksTunnel>>> = JoinSet::new();

    loop {
        tokio::select! {
            joined = handshakes.join_next(), if !handshakes.is_empty() => {
                match joined {
                    Some(Ok(Ok(Some(pending)))) => {
                        if prepared_tx.send(pending).is_err() {
                            return Ok(());
                        }
                    }
                    Some(Ok(Ok(None))) => {}
                    Some(Ok(Err(_))) => {}
                    Some(Err(error)) => {
                        return Err(Error::new(format!(
                            "socks handshake task failed: {error}"
                        )));
                    }
                    None => {}
                }
            }
            accepted = listener.accept() => {
                let (local_stream, peer_addr) = accepted?;
                handshakes.spawn(handle_socks_connection(
                    local_stream,
                    peer_addr.ip().to_string(),
                    peer_addr.port(),
                ));
            }
        }
    }
}

async fn proxy_connection(
    mut local_stream: TcpStream,
    mut remote_stream: Box<dyn DirectTcpipStream + Send + Unpin + 'static>,
) -> Result<()> {
    copy_bidirectional(&mut local_stream, &mut remote_stream).await?;
    Ok(())
}

async fn handle_socks_connection(
    mut local_stream: TcpStream,
    origin_host: String,
    origin_port: u16,
) -> Result<Option<PendingSocksTunnel>> {
    let handshake_accepted = match perform_socks_handshake(&mut local_stream).await {
        Ok(accepted) => accepted,
        Err(_) => {
            let _ = local_stream.shutdown().await;
            return Ok(None);
        }
    };
    if !handshake_accepted {
        return Ok(None);
    }

    let request = match read_socks_request(&mut local_stream).await {
        Ok(request) => request,
        Err(_) => {
            let _ = local_stream.shutdown().await;
            return Ok(None);
        }
    };

    match request.command {
        SocksCommand::Connect => Ok(Some(PendingSocksTunnel {
            local_stream,
            target_host: request.target_host,
            target_port: request.target_port,
            origin_host,
            origin_port,
        })),
        SocksCommand::Unsupported => {
            let _ = write_socks_reply(&mut local_stream, SocksReply::CommandNotSupported).await;
            Ok(None)
        }
    }
}

async fn open_tunnel_or_continue(
    session: &mut Box<dyn crate::ssh::SshSession + Send + 'static>,
    mut local_stream: TcpStream,
    request: OpenTunnelRequest<'_>,
    proxy_tasks: &mut JoinSet<Result<()>>,
) -> Result<()> {
    match session
        .open_direct_tcpip(
            request.target_host,
            request.target_port,
            request.origin_host,
            request.origin_port,
        )
        .await
    {
        Ok(remote_stream) => {
            if request.send_socks_success
                && write_socks_reply(&mut local_stream, SocksReply::Succeeded)
                    .await
                    .is_err()
            {
                return Ok(());
            }
            proxy_tasks.spawn(proxy_connection(local_stream, remote_stream));
            Ok(())
        }
        Err(_) if !session.is_alive() => Err(Error::new(format!(
            "ssh session for forward '{}' disconnected",
            request.forward_name
        ))),
        Err(_) => {
            if request.send_socks_success {
                let _ = write_socks_reply(&mut local_stream, SocksReply::GeneralFailure).await;
            }
            Ok(())
        }
    }
}

async fn perform_socks_handshake(stream: &mut TcpStream) -> Result<bool> {
    let mut header = [0_u8; 2];
    stream.read_exact(&mut header).await?;
    if header[0] != SOCKS_VERSION {
        return Err(Error::new("unsupported SOCKS version"));
    }

    let method_count = usize::from(header[1]);
    let mut methods = vec![0_u8; method_count];
    stream.read_exact(&mut methods).await?;
    if methods.contains(&SOCKS_AUTH_NONE) {
        stream.write_all(&[SOCKS_VERSION, SOCKS_AUTH_NONE]).await?;
        Ok(true)
    } else {
        stream
            .write_all(&[SOCKS_VERSION, SOCKS_AUTH_NO_ACCEPTABLE_METHODS])
            .await?;
        Ok(false)
    }
}

async fn read_socks_request(stream: &mut TcpStream) -> Result<SocksRequest> {
    let mut header = [0_u8; 4];
    stream.read_exact(&mut header).await?;
    if header[0] != SOCKS_VERSION {
        return Err(Error::new("unsupported SOCKS version"));
    }
    if header[2] != 0 {
        return Err(Error::new("SOCKS request used a non-zero reserved field"));
    }

    let command = match header[1] {
        SOCKS_COMMAND_CONNECT => SocksCommand::Connect,
        _ => SocksCommand::Unsupported,
    };
    let target_host = read_socks_address(stream, header[3]).await?;
    let mut port_bytes = [0_u8; 2];
    stream.read_exact(&mut port_bytes).await?;
    let target_port = u16::from_be_bytes(port_bytes);
    if target_port == 0 {
        return Err(Error::new("SOCKS target port must be between 1 and 65535"));
    }

    Ok(SocksRequest {
        command,
        target_host,
        target_port,
    })
}

async fn read_socks_address(stream: &mut TcpStream, atyp: u8) -> Result<String> {
    match atyp {
        SOCKS_ATYP_IPV4 => {
            let mut octets = [0_u8; 4];
            stream.read_exact(&mut octets).await?;
            Ok(std::net::Ipv4Addr::from(octets).to_string())
        }
        SOCKS_ATYP_DOMAIN => {
            let mut length = [0_u8; 1];
            stream.read_exact(&mut length).await?;
            let mut bytes = vec![0_u8; usize::from(length[0])];
            stream.read_exact(&mut bytes).await?;
            String::from_utf8(bytes)
                .map_err(|_| Error::new("SOCKS domain name was not valid utf-8"))
        }
        SOCKS_ATYP_IPV6 => {
            let mut octets = [0_u8; 16];
            stream.read_exact(&mut octets).await?;
            Ok(std::net::Ipv6Addr::from(octets).to_string())
        }
        _ => Err(Error::new("unsupported SOCKS address type")),
    }
}

async fn write_socks_reply(stream: &mut TcpStream, reply: SocksReply) -> Result<()> {
    stream
        .write_all(&[
            SOCKS_VERSION,
            reply as u8,
            0,
            SOCKS_ATYP_IPV4,
            0,
            0,
            0,
            0,
            0,
            0,
        ])
        .await?;
    Ok(())
}

const SOCKS_VERSION: u8 = 5;
const SOCKS_AUTH_NONE: u8 = 0;
const SOCKS_AUTH_NO_ACCEPTABLE_METHODS: u8 = 0xff;
const SOCKS_COMMAND_CONNECT: u8 = 1;
const SOCKS_ATYP_IPV4: u8 = 1;
const SOCKS_ATYP_DOMAIN: u8 = 3;
const SOCKS_ATYP_IPV6: u8 = 4;

enum SocksCommand {
    Connect,
    Unsupported,
}

struct SocksRequest {
    command: SocksCommand,
    target_host: String,
    target_port: u16,
}

#[repr(u8)]
enum SocksReply {
    GeneralFailure = 1,
    Succeeded = 0,
    CommandNotSupported = 7,
}
