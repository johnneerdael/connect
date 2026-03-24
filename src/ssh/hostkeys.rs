use std::{future::Future, pin::Pin};

use crate::{
    error::{Error, Result},
    store::HostKeyRecord,
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ObservedHostKey {
    pub host: String,
    pub port: u16,
    pub algorithm: String,
    pub fingerprint: String,
    pub public_key: String,
}

pub trait ObservedHostKeySource {
    fn observe_host_key<'a>(
        &'a self,
        profile: &'a crate::store::Profile,
    ) -> Pin<Box<dyn Future<Output = Result<ObservedHostKey>> + Send + 'a>>;
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HostKeyVerification {
    Trusted,
    TrustOnFirstUse,
}

pub fn verify_observed_host_key(
    stored: Option<&HostKeyRecord>,
    observed: &ObservedHostKey,
) -> Result<HostKeyVerification> {
    match stored {
        None => Ok(HostKeyVerification::TrustOnFirstUse),
        Some(record) if host_key_matches(record, observed) => Ok(HostKeyVerification::Trusted),
        Some(_) => Err(Error::new(
            "saved host key does not match the server host key",
        )),
    }
}

fn host_key_matches(stored: &HostKeyRecord, observed: &ObservedHostKey) -> bool {
    stored.host == observed.host
        && stored.port == observed.port
        && stored.algorithm == observed.algorithm
        && stored.fingerprint == observed.fingerprint
        && stored.public_key == observed.public_key
}
