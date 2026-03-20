use anyhow::Result;
use rusqlite::Connection;

pub fn init(conn: &Connection) -> Result<()> {
    conn.execute_batch(
        "
        CREATE TABLE IF NOT EXISTS scans (
            id TEXT PRIMARY KEY,
            sbom_filename TEXT NOT NULL,
            format_detected TEXT NOT NULL,
            total_components INTEGER NOT NULL,
            total_vulns INTEGER NOT NULL,
            critical_count INTEGER NOT NULL,
            high_count INTEGER NOT NULL,
            medium_count INTEGER NOT NULL,
            low_count INTEGER NOT NULL,
            license_issues INTEGER NOT NULL,
            report_json TEXT NOT NULL,
            created_at TEXT NOT NULL
        );
        ",
    )?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_schema_creation() {
        let conn = Connection::open_in_memory().unwrap();
        init(&conn).unwrap();
        // Verify table exists
        let count: i64 = conn
            .query_row("SELECT COUNT(*) FROM scans", [], |row| row.get(0))
            .unwrap();
        assert_eq!(count, 0);
    }
}
