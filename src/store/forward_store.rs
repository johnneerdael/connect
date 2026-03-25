use rusqlite::{params, OptionalExtension, Row};

use crate::error::Result;

use super::{Database, ForwardDefinition};

#[allow(dead_code)]
#[derive(Debug, Clone)]
pub struct ForwardStore {
    database: Database,
}

#[allow(dead_code)]
impl ForwardStore {
    pub fn new(database: Database) -> Self {
        Self { database }
    }

    pub fn save(&self, definition: &ForwardDefinition) -> Result<()> {
        let connection = self.database.connect()?;
        connection.execute(
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
            ON CONFLICT(profile_name, name) DO UPDATE SET
                kind = excluded.kind,
                bind_host = excluded.bind_host,
                bind_port = excluded.bind_port,
                target_host = excluded.target_host,
                target_port = excluded.target_port,
                description = excluded.description
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
        )?;
        Ok(())
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

#[allow(dead_code)]
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
