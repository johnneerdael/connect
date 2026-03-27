use connect::ssh::{
    plan_copy, CopyEndpoint, CopyJob, CopyPlanMode, CopyPlannerConfig, CopySpec, PlannedCopySource,
    PlannedCopyTreeEntry, RemotePath,
};
use std::path::PathBuf;

fn single_file_spec() -> CopySpec {
    CopySpec {
        source: CopyEndpoint::Local(PathBuf::from("/tmp/source.bin")),
        destination: CopyEndpoint::Remote(RemotePath {
            profile: "prod".into(),
            path: "/tmp/destination.bin".into(),
        }),
        recursive: false,
        resume: false,
        progress: false,
        effective_threads: 1,
    }
}

fn large_file_spec() -> CopySpec {
    single_file_spec()
}

fn recursive_tree_spec() -> CopySpec {
    CopySpec {
        recursive: true,
        ..single_file_spec()
    }
}

fn single_file_source() -> PlannedCopySource {
    PlannedCopySource::File {
        path: "/tmp/source.bin".into(),
        size: 128 * 1024 * 1024,
    }
}

fn large_file_source() -> PlannedCopySource {
    PlannedCopySource::File {
        path: "/tmp/source.bin".into(),
        size: 512 * 1024 * 1024,
    }
}

fn recursive_tree_source() -> PlannedCopySource {
    PlannedCopySource::Tree {
        root: "/tmp".into(),
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
fn planner_keeps_single_session_mode_when_effective_threads_is_one() {
    let plan = plan_copy(
        single_file_spec(),
        CopyPlannerConfig::new(1),
        single_file_source(),
    )
    .unwrap();

    assert!(matches!(plan.mode, CopyPlanMode::SingleStream));
}

#[test]
fn planner_stripes_large_single_file_when_threads_exceed_one() {
    let plan = plan_copy(
        large_file_spec(),
        CopyPlannerConfig::new(4),
        large_file_source(),
    )
    .unwrap();

    assert!(matches!(plan.mode, CopyPlanMode::StripedFile { .. }));
    assert!(plan
        .jobs
        .iter()
        .any(|job| matches!(job, CopyJob::StripedFile { .. })));
}

#[test]
fn planner_mixes_file_queue_and_striped_large_files_for_recursive_trees() {
    let plan = plan_copy(
        recursive_tree_spec(),
        CopyPlannerConfig::new(8),
        recursive_tree_source(),
    )
    .unwrap();

    assert!(plan
        .jobs
        .iter()
        .any(|job| matches!(job, CopyJob::StripedFile { .. })));
    assert!(plan
        .jobs
        .iter()
        .any(|job| matches!(job, CopyJob::WholeFile { .. })));
}
