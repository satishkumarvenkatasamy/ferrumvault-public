pub mod crypto;
pub mod db;
pub mod sync;
pub mod ui;
pub mod vault;

use std::path::PathBuf;

use anyhow::Result;

pub fn default_base_dir() -> Result<PathBuf> {
    let dir = dirs::data_dir()
        .or_else(dirs::home_dir)
        .unwrap_or(std::env::current_dir().expect("working dir"));
    Ok(dir.join("credmanager"))
}
