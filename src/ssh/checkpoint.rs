use std::{
    fs,
    path::{Path, PathBuf},
};

use serde::{Deserialize, Serialize};

use crate::error::Result;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Hash)]
pub struct ChunkRange {
    pub start: u64,
    pub end: u64,
}

impl ChunkRange {
    pub fn len(&self) -> u64 {
        self.end.saturating_sub(self.start)
    }

    pub fn is_empty(&self) -> bool {
        self.start >= self.end
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Hash)]
pub enum CopyTransferMode {
    SingleFile,
    RecursiveTree,
}

impl CopyTransferMode {
    fn as_key_component(self) -> &'static str {
        match self {
            Self::SingleFile => "single-file",
            Self::RecursiveTree => "recursive-tree",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CopyCheckpointIdentity {
    pub profile_name: String,
    pub direction: super::CopyDirection,
    pub source_path: String,
    pub destination_path: String,
    pub transfer_mode: CopyTransferMode,
}

impl CopyCheckpointIdentity {
    pub fn stable_key(&self) -> String {
        let payload = format!(
            "v1\0{}\0{}\0{}\0{}\0{}",
            self.profile_name,
            self.direction,
            self.transfer_mode.as_key_component(),
            self.source_path,
            self.destination_path
        );
        format!("{:016x}.json", fnv1a64(payload.as_bytes()))
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct CheckpointFileIdentity {
    size_bytes: u64,
    modified_unix_secs: Option<u64>,
}

impl CheckpointFileIdentity {
    pub fn new(size_bytes: u64, modified_unix_secs: impl Into<Option<u64>>) -> Self {
        Self {
            size_bytes,
            modified_unix_secs: modified_unix_secs.into(),
        }
    }

    pub fn size_bytes(&self) -> u64 {
        self.size_bytes
    }

    pub fn modified_unix_secs(&self) -> Option<u64> {
        self.modified_unix_secs
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct CopyFileMetadata {
    size_bytes: u64,
    modified_unix_secs: Option<u64>,
}

impl CopyFileMetadata {
    pub fn new(size_bytes: u64, modified_unix_secs: impl Into<Option<u64>>) -> Self {
        Self {
            size_bytes,
            modified_unix_secs: modified_unix_secs.into(),
        }
    }

    pub fn size_bytes(&self) -> u64 {
        self.size_bytes
    }

    pub fn modified_unix_secs(&self) -> Option<u64> {
        self.modified_unix_secs
    }
}

impl From<CopyFileMetadata> for CheckpointFileIdentity {
    fn from(value: CopyFileMetadata) -> Self {
        Self::new(value.size_bytes, value.modified_unix_secs)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CopyCheckpointState {
    total_bytes: u64,
    source: CheckpointFileIdentity,
    destination: Option<CheckpointFileIdentity>,
    completed_ranges: Vec<ChunkRange>,
}

impl CopyCheckpointState {
    pub fn new(
        total_bytes: u64,
        source: CheckpointFileIdentity,
        destination: Option<CheckpointFileIdentity>,
    ) -> Self {
        Self {
            total_bytes,
            source,
            destination,
            completed_ranges: Vec::new(),
        }
    }

    pub fn total_bytes(&self) -> u64 {
        self.total_bytes
    }

    pub fn source(&self) -> CheckpointFileIdentity {
        self.source
    }

    pub fn destination(&self) -> Option<CheckpointFileIdentity> {
        self.destination
    }

    pub fn set_destination(&mut self, destination: Option<CheckpointFileIdentity>) {
        self.destination = destination;
    }

    pub fn completed_ranges(&self) -> &[ChunkRange] {
        &self.completed_ranges
    }

    pub fn resumed_bytes(&self) -> u64 {
        self.completed_ranges.iter().map(ChunkRange::len).sum()
    }

    pub fn mark_completed(&mut self, range: ChunkRange) {
        if range.is_empty() {
            return;
        }

        self.completed_ranges.push(range);
        self.completed_ranges.sort_by_key(|range| range.start);

        let mut merged: Vec<ChunkRange> = Vec::with_capacity(self.completed_ranges.len());
        for range in self.completed_ranges.drain(..) {
            match merged.last_mut() {
                Some(previous) if range.start <= previous.end => {
                    previous.end = previous.end.max(range.end);
                }
                _ => merged.push(range),
            }
        }
        self.completed_ranges = merged;
    }

    pub fn incomplete_ranges(&self, planned: &[ChunkRange]) -> Vec<ChunkRange> {
        planned
            .iter()
            .flat_map(|planned_range| subtract_completed(*planned_range, &self.completed_ranges))
            .collect()
    }
}

#[derive(Debug, Clone)]
pub struct CopyCheckpointStore {
    root: PathBuf,
}

impl CopyCheckpointStore {
    pub fn new(root: PathBuf) -> Self {
        Self { root }
    }

    pub fn checkpoint_path(&self, identity: &CopyCheckpointIdentity) -> PathBuf {
        checkpoint_path(&self.root, identity)
    }

    pub fn load(&self, identity: &CopyCheckpointIdentity) -> Result<Option<CopyCheckpointState>> {
        let path = self.checkpoint_path(identity);
        match fs::read_to_string(&path) {
            Ok(contents) => serde_json::from_str(&contents)
                .map(Some)
                .map_err(|error| crate::error::Error::new(format!("invalid checkpoint file: {error}"))),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(error) => Err(error.into()),
        }
    }

    pub fn save(&self, identity: &CopyCheckpointIdentity, state: &CopyCheckpointState) -> Result<()> {
        fs::create_dir_all(&self.root)?;
        let path = self.checkpoint_path(identity);
        let encoded = serde_json::to_vec_pretty(state)
            .map_err(|error| crate::error::Error::new(format!("failed to encode checkpoint: {error}")))?;
        fs::write(path, encoded)?;
        Ok(())
    }

    pub fn delete(&self, identity: &CopyCheckpointIdentity) -> Result<()> {
        let path = self.checkpoint_path(identity);
        match fs::remove_file(path) {
            Ok(()) => Ok(()),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(error) => Err(error.into()),
        }
    }
}

pub fn checkpoint_path(root: &Path, identity: &CopyCheckpointIdentity) -> PathBuf {
    root.join(identity.stable_key())
}

fn subtract_completed(range: ChunkRange, completed_ranges: &[ChunkRange]) -> Vec<ChunkRange> {
    let mut missing = vec![range];

    for completed in completed_ranges {
        let mut next = Vec::new();
        for segment in missing {
            if completed.end <= segment.start || completed.start >= segment.end {
                next.push(segment);
                continue;
            }
            if completed.start > segment.start {
                next.push(ChunkRange {
                    start: segment.start,
                    end: completed.start,
                });
            }
            if completed.end < segment.end {
                next.push(ChunkRange {
                    start: completed.end,
                    end: segment.end,
                });
            }
        }
        missing = next;
        if missing.is_empty() {
            break;
        }
    }

    missing
}

fn fnv1a64(bytes: &[u8]) -> u64 {
    const OFFSET: u64 = 0xcbf29ce484222325;
    const PRIME: u64 = 0x00000100000001b3;

    let mut hash = OFFSET;
    for byte in bytes {
        hash ^= u64::from(*byte);
        hash = hash.wrapping_mul(PRIME);
    }
    hash
}
