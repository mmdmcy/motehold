use rusqlite::{Connection, OptionalExtension, params};

pub(crate) const MAX_ATTACHMENT_PREVIEW_CHARS: usize = 8 * 1024;

#[derive(Debug)]
pub(crate) struct ChannelRow {
    pub(crate) id: i64,
    pub(crate) name: String,
}

#[derive(Debug)]
pub(crate) struct NoteRow {
    pub(crate) id: i64,
    pub(crate) channel: String,
    pub(crate) body: String,
    pub(crate) has_image: bool,
    pub(crate) has_attachment: bool,
    pub(crate) attachment_name: Option<String>,
    pub(crate) attachment_type: Option<String>,
    pub(crate) attachment_preview: Option<String>,
    pub(crate) attachment_preview_truncated: bool,
}

pub(crate) struct NewNote {
    pub(crate) channel_id: i64,
    pub(crate) body: String,
    pub(crate) image_type: Option<String>,
    pub(crate) image_data: Option<Vec<u8>>,
    pub(crate) attachment_name: Option<String>,
    pub(crate) attachment_type: Option<String>,
    pub(crate) attachment_data: Option<Vec<u8>>,
    pub(crate) created_at: String,
}

pub(crate) fn ensure_channel(conn: &Connection, name: &str) -> rusqlite::Result<i64> {
    let existing = conn
        .query_row(
            "SELECT id FROM channels WHERE name = ?1",
            params![name],
            |row| row.get::<_, i64>(0),
        )
        .optional()?;
    if let Some(id) = existing {
        return Ok(id);
    }
    conn.execute(
        "INSERT INTO channels (name, created_at) VALUES (?1, ?2)",
        params![name, chrono::Utc::now().to_rfc3339()],
    )?;
    Ok(conn.last_insert_rowid())
}

pub(crate) fn channel_count(conn: &Connection) -> rusqlite::Result<i64> {
    conn.query_row("SELECT COUNT(*) FROM channels", [], |row| row.get(0))
}

pub(crate) fn delete_channel(conn: &Connection, id: i64) -> rusqlite::Result<usize> {
    conn.execute("DELETE FROM channels WHERE id = ?1", params![id])
}

pub(crate) fn channel_exists(conn: &Connection, id: i64) -> rusqlite::Result<bool> {
    Ok(conn
        .query_row("SELECT 1 FROM channels WHERE id = ?1", params![id], |row| {
            row.get::<_, i64>(0)
        })
        .optional()?
        .is_some())
}

pub(crate) fn insert_note(conn: &Connection, note: NewNote) -> rusqlite::Result<usize> {
    conn.execute(
        "INSERT INTO notes (channel_id, body, image_type, image_data, attachment_name, attachment_type, attachment_data, created_at) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
        params![
            note.channel_id,
            note.body,
            note.image_type,
            note.image_data,
            note.attachment_name,
            note.attachment_type,
            note.attachment_data,
            note.created_at,
        ],
    )
}

pub(crate) fn note_channel_id(conn: &Connection, id: i64) -> rusqlite::Result<Option<i64>> {
    conn.query_row(
        "SELECT channel_id FROM notes WHERE id = ?1",
        params![id],
        |row| row.get::<_, i64>(0),
    )
    .optional()
}

pub(crate) fn delete_note(conn: &Connection, id: i64) -> rusqlite::Result<usize> {
    conn.execute("DELETE FROM notes WHERE id = ?1", params![id])
}

pub(crate) fn note_image(
    conn: &Connection,
    id: i64,
) -> rusqlite::Result<Option<(Option<String>, Vec<u8>)>> {
    conn.query_row(
        "SELECT image_type, image_data FROM notes WHERE id = ?1 AND image_data IS NOT NULL",
        params![id],
        |row| Ok((row.get::<_, Option<String>>(0)?, row.get::<_, Vec<u8>>(1)?)),
    )
    .optional()
}

pub(crate) fn note_attachment(
    conn: &Connection,
    id: i64,
) -> rusqlite::Result<Option<(Option<String>, Vec<u8>)>> {
    conn.query_row(
        "SELECT attachment_name, attachment_data FROM notes WHERE id = ?1 AND attachment_data IS NOT NULL",
        params![id],
        |row| Ok((row.get::<_, Option<String>>(0)?, row.get::<_, Vec<u8>>(1)?)),
    )
    .optional()
}

pub(crate) fn list_channels(db: &Connection) -> rusqlite::Result<Vec<ChannelRow>> {
    let mut stmt = db.prepare("SELECT id, name FROM channels ORDER BY id ASC")?;
    stmt.query_map([], |row| {
        Ok(ChannelRow {
            id: row.get(0)?,
            name: row.get(1)?,
        })
    })?
    .collect()
}

pub(crate) fn list_notes(db: &Connection, channel: Option<i64>) -> rusqlite::Result<Vec<NoteRow>> {
    let sql = if channel.is_some() {
        format!(
            "SELECT n.id, c.name, n.body, n.image_data IS NOT NULL, n.attachment_name, n.attachment_type, n.attachment_data IS NOT NULL, substr(CAST(n.attachment_data AS TEXT), 1, {MAX_ATTACHMENT_PREVIEW_CHARS}), length(CAST(n.attachment_data AS TEXT)) > {MAX_ATTACHMENT_PREVIEW_CHARS} FROM notes n JOIN channels c ON c.id = n.channel_id WHERE n.channel_id = ?1 ORDER BY n.id DESC LIMIT 200"
        )
    } else {
        format!(
            "SELECT n.id, c.name, n.body, n.image_data IS NOT NULL, n.attachment_name, n.attachment_type, n.attachment_data IS NOT NULL, substr(CAST(n.attachment_data AS TEXT), 1, {MAX_ATTACHMENT_PREVIEW_CHARS}), length(CAST(n.attachment_data AS TEXT)) > {MAX_ATTACHMENT_PREVIEW_CHARS} FROM notes n JOIN channels c ON c.id = n.channel_id ORDER BY n.id DESC LIMIT 200"
        )
    };
    let mut stmt = db.prepare(&sql)?;
    if let Some(channel) = channel {
        stmt.query_map(params![channel], note_from_row)?
            .collect::<rusqlite::Result<Vec<_>>>()
    } else {
        stmt.query_map([], note_from_row)?
            .collect::<rusqlite::Result<Vec<_>>>()
    }
}

fn note_from_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<NoteRow> {
    Ok(NoteRow {
        id: row.get(0)?,
        channel: row.get(1)?,
        body: row.get(2)?,
        has_image: row.get::<_, i64>(3)? != 0,
        has_attachment: row.get::<_, i64>(6)? != 0,
        attachment_name: row.get(4)?,
        attachment_type: row.get(5)?,
        attachment_preview: row.get(7)?,
        attachment_preview_truncated: row.get::<_, Option<i64>>(8)?.unwrap_or(0) != 0,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::persistence::migrations;

    #[test]
    fn note_listing_caps_attachment_preview_but_preserves_full_download() {
        let db = Connection::open_in_memory().unwrap();
        migrations::migrate(&db).unwrap();
        db.execute(
            "INSERT INTO channels (name, created_at) VALUES ('general', 'now')",
            [],
        )
        .unwrap();
        let channel_id = db.last_insert_rowid();
        let attachment = "é".repeat(MAX_ATTACHMENT_PREVIEW_CHARS + 64);
        db.execute(
            "INSERT INTO notes (channel_id, body, attachment_name, attachment_type, attachment_data, created_at) VALUES (?1, '', 'notes.md', 'text/markdown; charset=utf-8', ?2, 'now')",
            params![channel_id, attachment.as_bytes()],
        )
        .unwrap();

        let notes = list_notes(&db, Some(channel_id)).unwrap();
        assert_eq!(notes.len(), 1);
        let note = &notes[0];
        assert_eq!(
            note.attachment_preview.as_deref().unwrap().chars().count(),
            MAX_ATTACHMENT_PREVIEW_CHARS
        );
        assert!(note.attachment_preview_truncated);

        let stored: Vec<u8> = db
            .query_row(
                "SELECT attachment_data FROM notes WHERE id = ?1",
                params![note.id],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(stored, attachment.as_bytes());
    }
}
