use rusqlite::{params, ffi, ErrorCode, OptionalExtension, Row};

use crate::error::{Error, Result};

use super::{Database, ForwardDefinition};

#[derive(Debug, Clone)]
pub struct ForwardStore {
    database: Database,
}

impl ForwardStore {
    pub fn new(database: Database) -> Self {
        Self { database }
    }

    pub fn save(&self, definition: &ForwardDefinition) -> Result<()> {
        let connection = self.database.connect()?;
        match connection.execute(
            "
            INSERT INTO forward_definitions (
                profile_name,
                name,
                kind,
                bind_host,
                bind_port,
                target_host,
                target_port,
                description
            )
            VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)
            ",
            params![
                &definition.profile_name,
                &definition.name,
                definition.kind.as_str(),
                &definition.bind_host,
                i64::from(definition.bind_port),
                definition.target_host.as_deref(),
                definition.target_port.map(i64::from),
                definition.description.as_deref(),
            ],
        ) {
            Ok(_) => Ok(()),
            Err(error) => Err(map_save_error(error, definition)),
        }
    }

    pub fn get(&self, profile_name: &str, name: &str) -> Result<Option<ForwardDefinition>> {
        let connection = self.database.connect()?;
        let mut statement = connection.prepare(
            "
            SELECT profile_name, name, kind, bind_host, bind_port, target_host, target_port, description
            FROM forward_definitions
            WHERE profile_name = ?1 AND name = ?2
            ",
        )?;

        let definition = statement
            .query_row(params![profile_name, name], map_forward_definition)
            .optional()?;

        Ok(definition)
    }

    pub fn list(&self, profile_name: &str) -> Result<Vec<ForwardDefinition>> {
        let connection = self.database.connect()?;
        let mut statement = connection.prepare(
            "
            SELECT profile_name, name, kind, bind_host, bind_port, target_host, target_port, description
            FROM forward_definitions
            WHERE profile_name = ?1
            ORDER BY name ASC
            ",
        )?;

        let definitions = statement
            .query_map(params![profile_name], map_forward_definition)?
            .collect::<std::result::Result<Vec<_>, _>>()?;

        Ok(definitions)
    }

    pub fn delete(&self, profile_name: &str, name: &str) -> Result<bool> {
        let connection = self.database.connect()?;
        let affected = connection.execute(
            "DELETE FROM forward_definitions WHERE profile_name = ?1 AND name = ?2",
            params![profile_name, name],
        )?;
        Ok(affected > 0)
    }
}

fn map_forward_definition(row: &Row<'_>) -> rusqlite::Result<ForwardDefinition> {
    Ok(ForwardDefinition {
        profile_name: row.get(0)?,
        name: row.get(1)?,
        kind: row.get::<_, String>(2)?.parse().map_err(|error: String| {
            rusqlite::Error::FromSqlConversionFailure(
                2,
                rusqlite::types::Type::Text,
                Box::new(std::io::Error::new(std::io::ErrorKind::InvalidData, error)),
            )
        })?,
        bind_host: row.get(3)?,
        bind_port: row.get::<_, u16>(4)?,
        target_host: row.get(5)?,
        target_port: row.get::<_, Option<u16>>(6)?,
        description: row.get(7)?,
    })
}

fn map_save_error(error: rusqlite::Error, definition: &ForwardDefinition) -> Error {
    match error {
        rusqlite::Error::SqliteFailure(err, _)
            if err.code == ErrorCode::ConstraintViolation
                && (err.extended_code == ffi::SQLITE_CONSTRAINT_PRIMARYKEY
                    || err.extended_code == ffi::SQLITE_CONSTRAINT_UNIQUE) =>
        {
            Error::new(format!(
                "forward '{}' already exists for profile '{}'",
                definition.name, definition.profile_name
            ))
        }
        other => other.into(),
    }
}
