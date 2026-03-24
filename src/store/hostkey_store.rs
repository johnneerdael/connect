use rusqlite::{params, Row};

use crate::error::Result;

use super::{Database, HostKeyRecord};

#[allow(dead_code)]
#[derive(Debug, Clone)]
pub struct HostKeyStore {
    database: Database,
}

#[allow(dead_code)]
impl HostKeyStore {
    pub fn new(database: Database) -> Self {
        Self { database }
    }

    pub fn save(
        &self,
        host: &str,
        port: u16,
        algorithm: &str,
        fingerprint: &str,
        public_key: &str,
    ) -> Result<()> {
        let connection = self.database.connect()?;
        connection.execute(
            "
            INSERT INTO host_keys (host, port, algorithm, fingerprint, public_key)
            VALUES (?1, ?2, ?3, ?4, ?5)
            ON CONFLICT(host, port, algorithm, fingerprint) DO UPDATE SET
                public_key = excluded.public_key
            ",
            params![host, i64::from(port), algorithm, fingerprint, public_key],
        )?;
        Ok(())
    }

    pub fn list(&self) -> Result<Vec<HostKeyRecord>> {
        let connection = self.database.connect()?;
        let mut statement = connection.prepare(
            "
            SELECT id, host, port, algorithm, fingerprint, public_key, accepted_at
            FROM host_keys
            ORDER BY host ASC, port ASC, accepted_at ASC
            ",
        )?;

        let records = statement
            .query_map([], map_host_key)?
            .collect::<std::result::Result<Vec<_>, _>>()?;

        Ok(records)
    }

    pub fn delete(&self, id: i64) -> Result<bool> {
        let connection = self.database.connect()?;
        let affected = connection.execute("DELETE FROM host_keys WHERE id = ?1", params![id])?;
        Ok(affected > 0)
    }
}

#[allow(dead_code)]
fn map_host_key(row: &Row<'_>) -> rusqlite::Result<HostKeyRecord> {
    Ok(HostKeyRecord {
        id: row.get(0)?,
        host: row.get(1)?,
        port: row.get::<_, u16>(2)?,
        algorithm: row.get(3)?,
        fingerprint: row.get(4)?,
        public_key: row.get(5)?,
        accepted_at: row.get(6)?,
    })
}
