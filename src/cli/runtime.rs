use std::{future::Future, time::Duration};

use crate::error::Result;

const RUNTIME_SHUTDOWN_TIMEOUT: Duration = Duration::from_millis(0);

pub fn run_async<F, T>(future: F) -> Result<T>
where
    F: Future<Output = Result<T>>,
{
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?;
    let result = runtime.block_on(future);
    runtime.shutdown_timeout(RUNTIME_SHUTDOWN_TIMEOUT);
    result
}

#[cfg(test)]
mod tests {
    use std::{sync::mpsc, thread, time::Duration};

    use crate::error::Error;

    use super::*;

    #[test]
    fn run_async_does_not_wait_for_background_blocking_tasks() {
        let (tx, rx) = mpsc::channel();
        thread::spawn(move || {
            let result = run_async(async {
                tokio::task::spawn_blocking(|| thread::sleep(Duration::from_secs(60)));
                Ok::<(), Error>(())
            });
            tx.send(result).expect("result should be sent");
        });

        let result = rx
            .recv_timeout(Duration::from_millis(250))
            .expect("runtime shutdown should not wait for background blocking tasks");
        assert!(result.is_ok());
    }
}
