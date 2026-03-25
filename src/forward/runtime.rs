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
    net::{TcpListener, TcpStream},
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
                return Err(Error::new(format!("forward supervisor task failed: {error}")));
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
        ForwardKind::Socks => Err(Error::new(format!(
            "socks forward '{}' is not supported by forward run yet",
            definition.name
        ))),
    }
}

async fn run_listener(
    bound_forward: BoundForward,
    mut session: Box<dyn crate::ssh::SshSession + Send + 'static>,
    stop: Arc<AtomicBool>,
) -> Result<()> {
    let target_host = bound_forward
        .definition
        .target_host
        .clone()
        .expect("local forward target host should be validated");
    let target_port = bound_forward
        .definition
        .target_port
        .expect("local forward target port should be validated");
    let forward_name = bound_forward.definition.name.clone();
    let mut proxy_tasks = JoinSet::new();
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
            accepted = bound_forward.listener.accept() => {
                let (local_stream, peer_addr) = accepted?;
                let origin_host = peer_addr.ip().to_string();
                let origin_port = peer_addr.port();
                match session
                    .open_direct_tcpip(&target_host, target_port, &origin_host, origin_port)
                    .await
                {
                    Ok(remote_stream) => {
                        proxy_tasks.spawn(proxy_connection(local_stream, remote_stream));
                    }
                    Err(error) => {
                        if !session.is_alive() {
                            return Err(Error::new(format!(
                                "ssh session for forward '{forward_name}' disconnected"
                            )));
                        }

                        drop(local_stream);
                        let _ = error;
                    }
                }
            }
        }
    }

    proxy_tasks.abort_all();
    while proxy_tasks.join_next().await.is_some() {}
    let _ = session.disconnect().await;
    Ok(())
}

async fn proxy_connection(
    mut local_stream: TcpStream,
    mut remote_stream: Box<dyn DirectTcpipStream + Send + Unpin + 'static>,
) -> Result<()> {
    copy_bidirectional(&mut local_stream, &mut remote_stream).await?;
    Ok(())
}
