use connect::app::AppPaths;
use directories::ProjectDirs;

#[test]
fn app_paths_follow_platform_conventions() {
    let project_dirs = ProjectDirs::from("", "", "connect").expect("project dirs should resolve");
    let paths = AppPaths::from_project_dirs(&project_dirs);

    #[cfg(target_os = "linux")]
    {
        assert!(paths.config_dir.ends_with("connect"));
        assert!(paths.config_dir.to_string_lossy().contains(".config"));
        assert!(paths.data_dir.ends_with("connect"));
        assert!(paths.data_dir.to_string_lossy().contains(".local/share"));
    }

    #[cfg(target_os = "macos")]
    {
        assert!(paths.config_dir.ends_with("Application Support/connect"));
        assert_eq!(paths.config_dir, paths.data_dir);
    }

    #[cfg(target_os = "windows")]
    {
        assert!(paths.config_dir.ends_with("connect"));
        assert_eq!(paths.config_dir, paths.data_dir);
    }
}

#[test]
fn sqlite_database_path_lives_under_data_dir() {
    let project_dirs = ProjectDirs::from("", "", "connect").expect("project dirs should resolve");
    let paths = AppPaths::from_project_dirs(&project_dirs);

    assert_eq!(paths.database_path.file_name().unwrap(), "connect.db");
    assert!(paths.database_path.starts_with(&paths.data_dir));
}
