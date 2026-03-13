use std::{
    fs,
    path::{Path, PathBuf},
};

use anyhow::{Context, Result};
use rusqlite::{Connection, OpenFlags};

pub mod schema;

/// Paths pointing to each vault database component.
#[derive(Debug, Clone)]
pub struct VaultPaths {
    pub profile_root: PathBuf,
    pub master_db: PathBuf,
    pub part2_db: PathBuf,
    pub part3_db: PathBuf,
    pub part4_db: PathBuf,
}

impl VaultPaths {
    pub fn new(base_dir: &Path, profile: &str) -> Self {
        let profile_root = base_dir.join(profile);
        Self {
            master_db: profile_root.join("vault_master.db"),
            part2_db: profile_root.join("vault_p2.db"),
            part3_db: profile_root.join("vault_p3.db"),
            part4_db: profile_root.join("vault_p4.db"),
            profile_root,
        }
    }

    pub fn ensure_dirs(&self) -> Result<()> {
        if !self.profile_root.exists() {
            fs::create_dir_all(&self.profile_root)
                .with_context(|| format!("Creating vault directory {:?}", self.profile_root))?;
        }
        Ok(())
    }
}

/// Initialize (or migrate) the SQLite databases backing the vault.
pub fn initialize_vault(paths: &VaultPaths) -> Result<()> {
    paths.ensure_dirs()?;

    let master = open_connection(&paths.master_db)
        .with_context(|| format!("Opening master database at {:?}", paths.master_db))?;
    schema::apply_master_schema(&master)?;

    for (path, idx) in [
        (&paths.part2_db, 2u8),
        (&paths.part3_db, 3u8),
        (&paths.part4_db, 4u8),
    ] {
        let conn = open_connection(path)
            .with_context(|| format!("Opening shard #{idx} database at {}", path.display()))?;
        schema::apply_shard_schema(&conn)?;
    }

    Ok(())
}

pub fn open_connection(path: &Path) -> Result<Connection> {
    let flags = OpenFlags::SQLITE_OPEN_CREATE | OpenFlags::SQLITE_OPEN_READ_WRITE;
    let conn = Connection::open_with_flags(path, flags)?;
    conn.pragma_update(None, "busy_timeout", 5000i64)?;
    conn.execute_batch(
        r#"
        PRAGMA journal_mode=WAL;
        PRAGMA synchronous=NORMAL;
        PRAGMA foreign_keys=ON;
        PRAGMA temp_store=MEMORY;
        PRAGMA secure_delete=ON;
        "#,
    )?;
    conn.set_prepared_statement_cache_capacity(64);
    Ok(conn)
}
