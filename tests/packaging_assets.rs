use std::{fs, path::PathBuf};

#[test]
fn packaging_assets_exist() {
    let repo_root = PathBuf::from(env!("CARGO_MANIFEST_DIR"));

    assert_file_contains(
        &repo_root.join("packaging/install.sh"),
        [
            "/usr/local/bin/connect",
            "CONNECT_INSTALL_PREFIX",
            "/etc/profile.d/connect.sh",
            ".profile",
            "export PATH=",
        ],
    );
    assert_file_contains(
        &repo_root.join("packaging/macos/postinstall"),
        ["/usr/local/bin/connect", "/etc/paths.d/connect", "PATH"],
    );
    assert_file_contains(
        &repo_root.join("packaging/windows/connect.wxs"),
        ["ProgramFiles64Folder", "Environment", "PATH", "connect.exe"],
    );
    assert_file_contains(
        &repo_root.join(".github/workflows/release.yml"),
        [
            "actions/upload-artifact@v4",
            "cargo metadata --no-deps --format-version 1",
            "ConvertFrom-Json",
            "GITHUB_REF_NAME",
            "MACOS_DEVELOPER_ID_APPLICATION_P12",
            "MACOS_DEVELOPER_ID_INSTALLER_P12",
            "MACOS_NOTARY_API_KEY_P8",
            "MACOS_NOTARY_KEY_ID",
            "sudo xcode-select -s",
            "xcrun notarytool --version",
            "xcrun notarytool store-credentials",
            "skipping notarization",
            "--keychain-profile",
            "xcrun notarytool submit",
            "xcrun stapler staple",
            "security create-keychain",
            "codesign",
            "productsign",
            "pkgbuild",
            "dotnet tool install --global wix --version 6.0.2",
            "wix build",
        ],
    );
    assert_file_contains(
        &repo_root.join("README.md"),
        [
            "connect add",
            "connect copy",
            "hostkeys",
            "install",
            "MACOS_DEVELOPER_ID_APPLICATION_P12",
            "MACOS_NOTARY_API_KEY_P8",
            "Developer ID Application",
            "notarytool",
        ],
    );
    assert_file_contains(&repo_root.join("Cargo.toml"), ["readme = \"README.md\""]);
}

fn assert_file_contains<const N: usize>(path: &PathBuf, needles: [&str; N]) {
    let contents = fs::read_to_string(path)
        .unwrap_or_else(|error| panic!("failed to read {}: {error}", path.display()));

    for needle in needles {
        assert!(
            contents.contains(needle),
            "{} does not contain expected text `{needle}`",
            path.display()
        );
    }
}
