use rusqlite::{params, OptionalExtension, Row};

use crate::error::Result;

use super::{AuthMode, Database, Profile, ProfileInput};

#[derive(Debug, Clone)]
pub struct ProfileStore {
    database: Database,
}

impl ProfileStore {
    pub fn new(database: Database) -> Self {
        Self { database }
    }

    pub fn save(&self, profile: &ProfileInput) -> Result<()> {
        let connection = self.database.connect()?;
        connection.execute(
            "
            INSERT INTO profiles (
                name, host, port, username, auth_mode, has_password, has_private_key, has_key_passphrase
            ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)
            ON CONFLICT(name) DO UPDATE SET
                host = excluded.host,
                port = excluded.port,
                username = excluded.username,
                auth_mode = excluded.auth_mode,
                has_password = excluded.has_password,
                has_private_key = excluded.has_private_key,
                has_key_passphrase = excluded.has_key_passphrase,
                updated_at = CURRENT_TIMESTAMP
            ",
            params![
                profile.name,
                profile.host,
                i64::from(profile.port),
                profile.username,
                profile.auth_mode.as_str(),
                profile.has_password,
                profile.has_private_key,
                profile.has_key_passphrase,
            ],
        )?;
        Ok(())
    }

    pub fn get(&self, name: &str) -> Result<Option<Profile>> {
        let connection = self.database.connect()?;
        let profile = connection
            .query_row(
                "
                SELECT
                    name,
                    host,
                    port,
                    username,
                    auth_mode,
                    has_password,
                    has_private_key,
                    has_key_passphrase,
                    created_at,
                    updated_at
                FROM profiles
                WHERE name = ?1
                ",
                params![name],
                map_profile,
            )
            .optional()?;

        Ok(profile)
    }

    pub fn list(&self) -> Result<Vec<Profile>> {
        let connection = self.database.connect()?;
        let mut statement = connection.prepare(
            "
            SELECT
                name,
                host,
                port,
                username,
                auth_mode,
                has_password,
                has_private_key,
                has_key_passphrase,
                created_at,
                updated_at
            FROM profiles
            ORDER BY name ASC
            ",
        )?;

        let profiles = statement
            .query_map([], map_profile)?
            .collect::<std::result::Result<Vec<_>, _>>()?;

        Ok(profiles)
    }

    pub fn delete(&self, name: &str) -> Result<bool> {
        let connection = self.database.connect()?;
        let affected = connection.execute("DELETE FROM profiles WHERE name = ?1", params![name])?;
        Ok(affected > 0)
    }
}

fn map_profile(row: &Row<'_>) -> rusqlite::Result<Profile> {
    let auth_mode = row.get::<_, String>(4)?;
    let auth_mode = auth_mode.parse::<AuthMode>().map_err(|message| {
        rusqlite::Error::FromSqlConversionFailure(
            4,
            rusqlite::types::Type::Text,
            Box::new(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                message,
            )),
        )
    })?;

    Ok(Profile {
        name: row.get(0)?,
        host: row.get(1)?,
        port: row.get::<_, u16>(2)?,
        username: row.get(3)?,
        auth_mode,
        has_password: row.get(5)?,
        has_private_key: row.get(6)?,
        has_key_passphrase: row.get(7)?,
        created_at: row.get(8)?,
        updated_at: row.get(9)?,
    })
}
