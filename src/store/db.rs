use std::{path::PathBuf, time::Duration};

use rusqlite::Connection;

use crate::error::Result;

#[derive(Debug, Clone)]
pub struct Database {
    path: PathBuf,
}

impl Database {
    pub fn new(path: PathBuf) -> Self {
        Self { path }
    }

    pub fn initialize(&self) -> Result<()> {
        let connection = self.connect()?;
        connection.execute_batch(
            "
            CREATE TABLE IF NOT EXISTS profiles (
                name TEXT PRIMARY KEY,
                host TEXT NOT NULL,
                port INTEGER NOT NULL,
                username TEXT NOT NULL,
                auth_mode TEXT NOT NULL DEFAULT 'auto',
                copy_threads INTEGER NOT NULL DEFAULT 1,
                has_password INTEGER NOT NULL DEFAULT 0,
                has_private_key INTEGER NOT NULL DEFAULT 0,
                has_key_passphrase INTEGER NOT NULL DEFAULT 0,
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
            );

            CREATE TABLE IF NOT EXISTS host_keys (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                host TEXT NOT NULL,
                port INTEGER NOT NULL,
                algorithm TEXT NOT NULL,
                fingerprint TEXT NOT NULL,
                public_key TEXT NOT NULL,
                accepted_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                UNIQUE(host, port, algorithm, fingerprint)
            );

            CREATE TABLE IF NOT EXISTS forward_definitions (
                profile_name TEXT NOT NULL,
                name TEXT NOT NULL,
                kind TEXT NOT NULL,
                bind_host TEXT NOT NULL,
                bind_port INTEGER NOT NULL,
                target_host TEXT,
                target_port INTEGER,
                description TEXT,
                PRIMARY KEY (profile_name, name),
                FOREIGN KEY (profile_name) REFERENCES profiles(name) ON DELETE CASCADE
            );
            ",
        )?;
        add_profiles_auth_mode_column_if_missing(&connection)?;
        add_profiles_copy_threads_column_if_missing(&connection)?;
        Ok(())
    }

    pub fn connect(&self) -> Result<Connection> {
        let connection = Connection::open(&self.path)?;
        connection.busy_timeout(Duration::from_secs(5))?;
        connection.pragma_update(None, "foreign_keys", true)?;
        Ok(connection)
    }
}

fn add_profiles_auth_mode_column_if_missing(connection: &Connection) -> Result<()> {
    let mut statement = connection.prepare("PRAGMA table_info(profiles)")?;
    let columns = statement.query_map([], |row| row.get::<_, String>(1))?;
    for column in columns {
        if column? == "auth_mode" {
            return Ok(());
        }
    }

    connection.execute(
        "ALTER TABLE profiles ADD COLUMN auth_mode TEXT NOT NULL DEFAULT 'auto'",
        [],
    )?;
    Ok(())
}

fn add_profiles_copy_threads_column_if_missing(connection: &Connection) -> Result<()> {
    let columns = profiles_table_columns(connection)?;
    match columns.iter().find(|column| column.name == "copy_threads") {
        None => {
            connection.execute(
                "ALTER TABLE profiles ADD COLUMN copy_threads INTEGER NOT NULL DEFAULT 1",
                [],
            )?;
        }
        Some(column) if column.is_concrete_copy_threads() => {}
        Some(_) => {
            rebuild_profiles_copy_threads_column(connection)?;
        }
    }

    connection.execute(
        "UPDATE profiles SET copy_threads = 1 WHERE copy_threads IS NULL OR copy_threads < 1",
        [],
    )?;
    Ok(())
}

fn rebuild_profiles_copy_threads_column(connection: &Connection) -> Result<()> {
    connection.execute_batch(
        "
        PRAGMA foreign_keys = OFF;
        BEGIN IMMEDIATE;

        CREATE TABLE profiles_new (
            name TEXT PRIMARY KEY,
            host TEXT NOT NULL,
            port INTEGER NOT NULL,
            username TEXT NOT NULL,
            auth_mode TEXT NOT NULL DEFAULT 'auto',
            copy_threads INTEGER NOT NULL DEFAULT 1,
            has_password INTEGER NOT NULL DEFAULT 0,
            has_private_key INTEGER NOT NULL DEFAULT 0,
            has_key_passphrase INTEGER NOT NULL DEFAULT 0,
            created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
            updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
        );

        INSERT INTO profiles_new (
            name,
            host,
            port,
            username,
            auth_mode,
            copy_threads,
            has_password,
            has_private_key,
            has_key_passphrase,
            created_at,
            updated_at
        )
        SELECT
            name,
            host,
            port,
            username,
            auth_mode,
            CASE
                WHEN copy_threads IS NULL OR copy_threads < 1 THEN 1
                ELSE copy_threads
            END,
            has_password,
            has_private_key,
            has_key_passphrase,
            created_at,
            updated_at
        FROM profiles;

        DROP TABLE profiles;
        ALTER TABLE profiles_new RENAME TO profiles;

        COMMIT;
        PRAGMA foreign_keys = ON;
        ",
    )?;
    Ok(())
}

fn profiles_table_columns(connection: &Connection) -> Result<Vec<ProfileTableColumn>> {
    let mut statement = connection.prepare("PRAGMA table_info(profiles)")?;
    let columns = statement.query_map([], |row| {
        Ok(ProfileTableColumn {
            name: row.get(1)?,
            notnull: row.get::<_, i64>(3)? != 0,
            default_value: row.get(4)?,
        })
    })?;

    Ok(columns.collect::<std::result::Result<Vec<_>, _>>()?)
}

#[derive(Debug)]
struct ProfileTableColumn {
    name: String,
    notnull: bool,
    default_value: Option<String>,
}

impl ProfileTableColumn {
    fn is_concrete_copy_threads(&self) -> bool {
        self.notnull && self.default_value.as_deref() == Some("1")
    }
}
