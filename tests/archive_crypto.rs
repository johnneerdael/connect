use connect::archive::{
    decrypt_archive, encrypt_archive, ArchiveKind, BackupPayload, BackupProfileRecord,
};

fn test_app_key() -> [u8; 32] {
    [7u8; 32]
}

fn sample_backup_payload() -> BackupPayload {
    BackupPayload {
        profiles: vec![BackupProfileRecord {
            name: "prod".into(),
            host: "prod.example.com".into(),
            port: 22,
            username: "alice".into(),
            auth_mode: "auto".into(),
            copy_threads: 1,
            has_password: true,
            has_private_key: false,
            has_key_passphrase: false,
            created_at: "2026-03-28T00:00:00Z".into(),
            updated_at: "2026-03-28T00:00:00Z".into(),
        }],
        forwards: Vec::new(),
        host_keys: Vec::new(),
        secret_bundles: Vec::new(),
    }
}

#[test]
fn encrypt_then_decrypt_round_trips_backup_payload() {
    let payload = sample_backup_payload();

    let archive = encrypt_archive(&payload, ArchiveKind::Backup, "correct horse", &test_app_key())
        .expect("archive should encrypt");
    let decrypted: BackupPayload =
        decrypt_archive(&archive, ArchiveKind::Backup, "correct horse", &test_app_key())
            .expect("archive should decrypt");

    assert_eq!(decrypted, payload);
}

#[test]
fn decrypt_rejects_wrong_psk() {
    let payload = sample_backup_payload();

    let archive =
        encrypt_archive(&payload, ArchiveKind::Backup, "correct horse", &test_app_key()).unwrap();

    let error = decrypt_archive::<BackupPayload>(
        &archive,
        ArchiveKind::Backup,
        "wrong battery",
        &test_app_key(),
    )
    .unwrap_err();

    assert_eq!(error.to_string(), "unable to decrypt archive");
}

#[test]
fn decrypt_rejects_corrupted_ciphertext() {
    let payload = sample_backup_payload();

    let mut archive =
        encrypt_archive(&payload, ArchiveKind::Backup, "correct horse", &test_app_key()).unwrap();
    let last = archive.len() - 1;
    archive[last] ^= 0x55;

    let error =
        decrypt_archive::<BackupPayload>(&archive, ArchiveKind::Backup, "correct horse", &test_app_key())
            .unwrap_err();

    assert_eq!(error.to_string(), "unable to decrypt archive");
}

#[test]
fn decrypt_rejects_wrong_artifact_kind() {
    let payload = sample_backup_payload();

    let archive =
        encrypt_archive(&payload, ArchiveKind::Backup, "correct horse", &test_app_key()).unwrap();

    let error = decrypt_archive::<BackupPayload>(
        &archive,
        ArchiveKind::ProfileExport,
        "correct horse",
        &test_app_key(),
    )
    .unwrap_err();

    assert_eq!(error.to_string(), "archive kind does not match requested operation");
}
