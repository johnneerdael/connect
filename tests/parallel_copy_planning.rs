use connect::ssh::{
    plan_copy, CopyEndpoint, CopyJob, CopyPlanMode, CopyPlannerConfig, CopyResumeStrategy,
    CopyRetryStrategy, CopySpec, PlannedCopySource, PlannedCopyTreeEntry, RemotePath,
};
use std::path::PathBuf;

fn single_file_spec(resume: bool) -> CopySpec {
    CopySpec {
        source: CopyEndpoint::Local(PathBuf::from("/tmp/source.bin")),
        destination: CopyEndpoint::Remote(RemotePath {
            profile: "prod".into(),
            path: "/tmp/destination.bin".into(),
        }),
        recursive: false,
        resume,
        progress: false,
        effective_threads: 1,
    }
}

fn recursive_tree_spec() -> CopySpec {
    CopySpec {
        source: CopyEndpoint::Local(PathBuf::from("/tmp/source-root")),
        destination: CopyEndpoint::Remote(RemotePath {
            profile: "prod".into(),
            path: "/tmp/destination-root".into(),
        }),
        recursive: true,
        resume: false,
        progress: false,
        effective_threads: 8,
    }
}

fn single_file_source(size: u64) -> PlannedCopySource {
    PlannedCopySource::File {
        path: "/tmp/source.bin".into(),
        size,
    }
}

fn recursive_tree_source() -> PlannedCopySource {
    PlannedCopySource::Tree {
        root: "/tmp/source-root".into(),
        entries: vec![
            PlannedCopyTreeEntry::File {
                path: "small.txt".into(),
                size: 4 * 1024 * 1024,
            },
            PlannedCopyTreeEntry::File {
                path: "large.bin".into(),
                size: 512 * 1024 * 1024,
            },
            PlannedCopyTreeEntry::Directory {
                path: "nested".into(),
            },
            PlannedCopyTreeEntry::File {
                path: "nested/nested.bin".into(),
                size: 96 * 1024 * 1024,
            },
        ],
    }
}

#[test]
fn planner_keeps_single_stream_resume_policy_for_unsplit_files() {
    let mut spec = single_file_spec(true);
    spec.effective_threads = 1;

    let plan = plan_copy(
        spec,
        CopyPlannerConfig {
            effective_threads: 1,
            retry: false,
        },
        single_file_source(128 * 1024 * 1024),
    )
    .unwrap();

    let job = match &plan.jobs[..] {
        [CopyJob::WholeFile { policy, .. }] => policy,
        _ => panic!("expected exactly one whole-file job"),
    };

    assert!(matches!(plan.mode, CopyPlanMode::SingleStream));
    assert!(matches!(
        job.resume,
        CopyResumeStrategy::DestinationSizeResume
    ));
    assert!(matches!(job.retry, CopyRetryStrategy::Disabled));
}

#[test]
fn planner_stripes_large_single_file_with_checkpointed_resume_policy() {
    let spec = single_file_spec(true);

    let plan = plan_copy(
        spec,
        CopyPlannerConfig {
            effective_threads: 4,
            retry: true,
        },
        single_file_source(512 * 1024 * 1024),
    )
    .unwrap();

    let job = match &plan.jobs[..] {
        [CopyJob::StripedFile { policy, chunks, .. }] => {
            assert!(!chunks.is_empty());
            policy
        }
        _ => panic!("expected exactly one striped job"),
    };

    assert!(matches!(plan.mode, CopyPlanMode::StripedFile { .. }));
    assert!(matches!(
        job.resume,
        CopyResumeStrategy::Checkpointed { .. }
    ));
    assert!(matches!(job.retry, CopyRetryStrategy::RetryStripedChunks));
}

#[test]
fn planner_mixes_file_queue_and_striped_large_files_for_recursive_trees() {
    let plan = plan_copy(
        recursive_tree_spec(),
        CopyPlannerConfig {
            effective_threads: 8,
            retry: true,
        },
        recursive_tree_source(),
    )
    .unwrap();

    let destinations: Vec<_> = plan
        .jobs
        .iter()
        .map(|job| match job {
            CopyJob::WholeFile {
                destination_path, ..
            }
            | CopyJob::StripedFile {
                destination_path, ..
            } => destination_path.as_str(),
        })
        .collect();

    assert!(destinations.contains(&"/tmp/destination-root/source-root/small.txt"));
    assert!(destinations.contains(&"/tmp/destination-root/source-root/large.bin"));
    assert!(destinations.contains(&"/tmp/destination-root/source-root/nested/nested.bin"));
    assert_ne!(destinations[0], destinations[1]);

    let whole = plan.jobs.iter().find_map(|job| match job {
        CopyJob::WholeFile { policy, .. } => Some(policy),
        _ => None,
    });
    let striped = plan.jobs.iter().find_map(|job| match job {
        CopyJob::StripedFile { policy, .. } => Some(policy),
        _ => None,
    });

    let whole = whole.expect("expected a whole-file job");
    let striped = striped.expect("expected a striped job");

    assert!(matches!(whole.retry, CopyRetryStrategy::RetryWholeFile));
    assert!(matches!(
        striped.retry,
        CopyRetryStrategy::RetryStripedChunks
    ));
}
