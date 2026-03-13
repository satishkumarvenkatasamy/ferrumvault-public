use anyhow::Result;
use rusqlite::Connection;

/// Apply schema objects to the master vault database.
pub fn apply_master_schema(conn: &Connection) -> Result<()> {
    conn.execute_batch(MASTER_SCHEMA)?;
    ensure_column(conn, "credentials", "username", "TEXT")?;
    ensure_column(conn, "sync_credentials", "client_id", "TEXT")?;
    ensure_column(conn, "sync_credentials", "client_secret", "TEXT")?;
    ensure_column(conn, "sync_credentials", "redirect_uri", "TEXT")?;
    Ok(())
}

/// Apply schema objects to a shard database.
pub fn apply_shard_schema(conn: &Connection) -> Result<()> {
    conn.execute_batch(SHARD_SCHEMA)?;
    Ok(())
}

const MASTER_SCHEMA: &str = r#"
PRAGMA journal_mode=WAL;
PRAGMA foreign_keys=ON;
PRAGMA secure_delete=ON;
PRAGMA auto_vacuum=INCREMENTAL;

CREATE TABLE IF NOT EXISTS vault_metadata (
    id INTEGER PRIMARY KEY CHECK(id = 1),
    kdf_salt BLOB NOT NULL,
    kdf_iters INTEGER NOT NULL,
    verifier_nonce BLOB NOT NULL,
    verifier_cipher BLOB NOT NULL
);

CREATE TABLE IF NOT EXISTS credentials (
    cred_id INTEGER PRIMARY KEY,
    app_name TEXT NOT NULL UNIQUE,
    username TEXT,
    url TEXT,
    description TEXT,
    json_tags TEXT,
    tag_blob TEXT NOT NULL DEFAULT '',
    folder TEXT NOT NULL DEFAULT 'general',
    categories TEXT NOT NULL DEFAULT '[]',
    created_at_utc TEXT NOT NULL,
    last_accessed_utc TEXT,
    assembly_sequence BLOB NOT NULL,
    assembly_dek_wrapped BLOB NOT NULL,
    part1_cipher BLOB NOT NULL,
    part1_nonce BLOB NOT NULL,
    part1_dek_wrapped BLOB NOT NULL,
    verifier_hmac BLOB NOT NULL
);

CREATE TABLE IF NOT EXISTS credential_tags (
    tag_id INTEGER PRIMARY KEY,
    tag_value TEXT NOT NULL UNIQUE
);

CREATE TABLE IF NOT EXISTS credential_tag_map (
    cred_id INTEGER NOT NULL,
    tag_id INTEGER NOT NULL,
    created_at_utc TEXT NOT NULL,
    PRIMARY KEY (cred_id, tag_id),
    FOREIGN KEY (cred_id) REFERENCES credentials(cred_id) ON DELETE CASCADE,
    FOREIGN KEY (tag_id) REFERENCES credential_tags(tag_id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS credential_parts (
    part_id INTEGER PRIMARY KEY,
    cred_id INTEGER NOT NULL,
    part_index INTEGER NOT NULL,
    cipher_blob BLOB NOT NULL,
    nonce BLOB NOT NULL,
    dek_wrapped BLOB NOT NULL,
    hmac BLOB NOT NULL,
    FOREIGN KEY (cred_id) REFERENCES credentials(cred_id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS credential_access_log (
    log_id INTEGER PRIMARY KEY,
    cred_id INTEGER NOT NULL,
    accessed_at_utc TEXT NOT NULL,
    device_name TEXT,
    location_hint TEXT,
    access_type TEXT NOT NULL,
    result TEXT NOT NULL,
    FOREIGN KEY (cred_id) REFERENCES credentials(cred_id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS password_history (
    history_id INTEGER PRIMARY KEY,
    cred_id INTEGER NOT NULL,
    padded_cipher BLOB NOT NULL,
    padded_nonce BLOB NOT NULL,
    comment TEXT,
    created_at_utc TEXT NOT NULL,
    dek_wrapped BLOB NOT NULL,
    FOREIGN KEY (cred_id) REFERENCES credentials(cred_id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS sync_credentials (
    id INTEGER PRIMARY KEY CHECK(id = 1),
    access_token TEXT,
    refresh_token TEXT,
    token_expires_at_utc TEXT,
    folder_id TEXT,
    device_fingerprint TEXT,
    device_label TEXT,
    client_id TEXT,
    client_secret TEXT,
    redirect_uri TEXT
);

CREATE TABLE IF NOT EXISTS sync_state (
    id INTEGER PRIMARY KEY CHECK(id = 1),
    last_revision INTEGER NOT NULL DEFAULT 0,
    last_bundle_id TEXT,
    last_uploaded_at_utc TEXT
);

CREATE TABLE IF NOT EXISTS sync_preferences (
    id INTEGER PRIMARY KEY CHECK(id = 1),
    auto_upload_on_exit INTEGER NOT NULL DEFAULT 0,
    auto_download_on_new INTEGER NOT NULL DEFAULT 0,
    keep_revisions INTEGER NOT NULL DEFAULT 5
);

CREATE INDEX IF NOT EXISTS idx_credentials_app_name ON credentials(app_name);
CREATE INDEX IF NOT EXISTS idx_credentials_folder ON credentials(folder);
CREATE INDEX IF NOT EXISTS idx_credentials_url ON credentials(url);
CREATE INDEX IF NOT EXISTS idx_tag_map_tag_id ON credential_tag_map(tag_id);

CREATE VIRTUAL TABLE IF NOT EXISTS credential_fts USING fts5(
    app_name, url, description, tag_blob,
    content='credentials', content_rowid='cred_id',
    tokenize='porter'
);

CREATE TRIGGER IF NOT EXISTS credential_ai AFTER INSERT ON credentials BEGIN
    INSERT INTO credential_fts(rowid, app_name, url, description, tag_blob)
    VALUES (new.cred_id, new.app_name, new.url, new.description, new.tag_blob);
END;

CREATE TRIGGER IF NOT EXISTS credential_ad AFTER DELETE ON credentials BEGIN
    INSERT INTO credential_fts(credential_fts, rowid, app_name, url, description, tag_blob)
    VALUES('delete', old.cred_id, old.app_name, old.url, old.description, old.tag_blob);
END;

CREATE TRIGGER IF NOT EXISTS credential_au AFTER UPDATE ON credentials BEGIN
    INSERT INTO credential_fts(credential_fts, rowid, app_name, url, description, tag_blob)
    VALUES('delete', old.cred_id, old.app_name, old.url, old.description, old.tag_blob);
    INSERT INTO credential_fts(rowid, app_name, url, description, tag_blob)
    VALUES (new.cred_id, new.app_name, new.url, new.description, new.tag_blob);
END;
"#;

const SHARD_SCHEMA: &str = r#"
PRAGMA journal_mode=WAL;
PRAGMA foreign_keys=OFF;
PRAGMA secure_delete=ON;
PRAGMA auto_vacuum=INCREMENTAL;

CREATE TABLE IF NOT EXISTS credential_parts (
    part_id INTEGER PRIMARY KEY,
    cred_id INTEGER NOT NULL,
    part_index INTEGER NOT NULL,
    cipher_blob BLOB NOT NULL,
    nonce BLOB NOT NULL,
    dek_wrapped BLOB NOT NULL,
    hmac BLOB NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_parts_cred_id ON credential_parts(cred_id);
"#;

fn ensure_column(conn: &Connection, table: &str, column: &str, ddl: &str) -> Result<()> {
    if column_exists(conn, table, column)? {
        return Ok(());
    }
    let sql = format!("ALTER TABLE {table} ADD COLUMN {column} {ddl}");
    conn.execute(&sql, [])?;
    Ok(())
}

fn column_exists(conn: &Connection, table: &str, column: &str) -> Result<bool> {
    let pragma = format!("PRAGMA table_info({table})");
    let mut stmt = conn.prepare(&pragma)?;
    let mut rows = stmt.query([])?;
    while let Some(row) = rows.next()? {
        let name: String = row.get("name")?;
        if name.eq_ignore_ascii_case(column) {
            return Ok(true);
        }
    }
    Ok(false)
}
