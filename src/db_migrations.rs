use rusqlite::{Connection, params};

pub const LATEST_SCHEMA_VERSION: i64 = 2;

const BASE_SCHEMA: &str = r#"
PRAGMA foreign_keys = ON;
CREATE TABLE IF NOT EXISTS channels (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL COLLATE NOCASE UNIQUE,
    created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS notes (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    channel_id INTEGER NOT NULL,
    body TEXT NOT NULL,
    image_type TEXT,
    image_data BLOB,
    created_at TEXT NOT NULL,
    import_source TEXT UNIQUE,
    FOREIGN KEY (channel_id) REFERENCES channels(id) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS idx_notes_channel_id ON notes(channel_id);
"#;

const MARKDOWN_ATTACHMENT_MIGRATION: &str = r#"
ALTER TABLE notes ADD COLUMN attachment_name TEXT;
ALTER TABLE notes ADD COLUMN attachment_type TEXT;
ALTER TABLE notes ADD COLUMN attachment_data BLOB;
"#;

pub fn migrate(conn: &Connection) -> rusqlite::Result<()> {
    conn.execute_batch(
        r#"
        PRAGMA foreign_keys = ON;
        CREATE TABLE IF NOT EXISTS schema_migrations (
            version INTEGER PRIMARY KEY,
            applied_at TEXT NOT NULL DEFAULT (datetime('now'))
        );
        "#,
    )?;

    let current = current_version(conn)?;
    if current < 1 {
        conn.execute_batch(BASE_SCHEMA)?;
        record_migration(conn, 1)?;
    }
    if current < 2 {
        conn.execute_batch(MARKDOWN_ATTACHMENT_MIGRATION)?;
        record_migration(conn, 2)?;
    }
    debug_assert!(current_version(conn)? >= LATEST_SCHEMA_VERSION);
    Ok(())
}

fn current_version(conn: &Connection) -> rusqlite::Result<i64> {
    conn.query_row("SELECT MAX(version) FROM schema_migrations", [], |row| {
        row.get::<_, Option<i64>>(0)
    })
    .map(|version| version.unwrap_or(0))
}

fn record_migration(conn: &Connection, version: i64) -> rusqlite::Result<()> {
    conn.execute(
        "INSERT OR IGNORE INTO schema_migrations (version) VALUES (?1)",
        params![version],
    )?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn migrate_records_latest_schema_version() {
        let db = Connection::open_in_memory().unwrap();
        migrate(&db).unwrap();
        assert_eq!(current_version(&db).unwrap(), LATEST_SCHEMA_VERSION);
    }

    #[test]
    fn migrate_creates_notes_tables_only() {
        let db = Connection::open_in_memory().unwrap();
        migrate(&db).unwrap();

        let tables = db
            .prepare("SELECT name FROM sqlite_master WHERE type = 'table' ORDER BY name")
            .unwrap()
            .query_map([], |row| row.get::<_, String>(0))
            .unwrap()
            .collect::<Result<Vec<_>, _>>()
            .unwrap();

        assert!(tables.contains(&"channels".into()));
        assert!(tables.contains(&"notes".into()));
        assert!(!tables.contains(&"agent_slots".into()));
        assert!(!tables.contains(&"download_cache".into()));
    }

    #[test]
    fn migrate_adds_attachment_columns() {
        let db = Connection::open_in_memory().unwrap();
        migrate(&db).unwrap();

        let columns = db
            .prepare("PRAGMA table_info(notes)")
            .unwrap()
            .query_map([], |row| row.get::<_, String>(1))
            .unwrap()
            .collect::<Result<Vec<_>, _>>()
            .unwrap();

        assert!(columns.contains(&"attachment_name".into()));
        assert!(columns.contains(&"attachment_type".into()));
        assert!(columns.contains(&"attachment_data".into()));
    }

    #[test]
    fn migration_two_preserves_existing_notes() {
        let db = Connection::open_in_memory().unwrap();
        db.execute_batch(BASE_SCHEMA).unwrap();
        db.execute_batch(
            r#"
            CREATE TABLE schema_migrations (
                version INTEGER PRIMARY KEY,
                applied_at TEXT NOT NULL DEFAULT (datetime('now'))
            );
            INSERT INTO schema_migrations (version) VALUES (1);
            INSERT INTO channels (name, created_at) VALUES ('general', 'now');
            INSERT INTO notes (channel_id, body, created_at)
                SELECT id, 'keep me', 'now' FROM channels WHERE name = 'general';
            "#,
        )
        .unwrap();

        migrate(&db).unwrap();

        let body: String = db
            .query_row("SELECT body FROM notes", [], |row| row.get(0))
            .unwrap();
        assert_eq!(body, "keep me");
        assert_eq!(current_version(&db).unwrap(), LATEST_SCHEMA_VERSION);
    }
}
