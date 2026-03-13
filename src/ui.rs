use std::collections::HashSet;

use anyhow::{Result, ensure};
use chrono::Utc;
use rusqlite::{Connection, params, params_from_iter};
use serde::{Deserialize, Serialize};

use crate::db::{VaultPaths, open_connection};
use crate::vault::{NewCredential, VaultEngine};

#[derive(Debug, Clone, Default, Serialize)]
pub struct UiOptions {
    pub folder: Option<String>,
    pub tag: Option<String>,
    pub search: Option<String>,
}

pub fn run_ui(paths: &VaultPaths, opts: UiOptions) -> Result<()> {
    let model = gather_snapshot(paths, opts.clone())?;
    render_cli(&model);
    Ok(())
}

pub fn gather_snapshot(paths: &VaultPaths, opts: UiOptions) -> Result<UiSnapshot> {
    let conn = open_connection(&paths.master_db)?;
    UiSnapshot::load(&conn, &opts)
}

pub fn load_detail_with_relations(paths: &VaultPaths, cred_id: i64) -> Result<CredentialDetail> {
    let conn = open_connection(&paths.master_db)?;
    let tags = load_tags_for_credential(&conn, cred_id)?;
    let detail = load_detail(&conn, cred_id)?;
    Ok(detail.with_tags(tags))
}

pub fn update_credential(
    paths: &VaultPaths,
    payload: UpdateCredentialInput,
) -> Result<CredentialDetail> {
    let cred_id = payload.cred_id;
    let conn = open_connection(&paths.master_db)?;
    apply_credential_update(&conn, payload)?;
    load_detail_with_relations(paths, cred_id)
}

pub fn create_credential(
    paths: &VaultPaths,
    payload: CreateCredentialInput,
    master_key: [u8; 32],
) -> Result<CredentialDetail> {
    let CreateCredentialInput {
        app_name,
        username,
        url,
        description,
        folder,
        tags,
        categories,
        password,
    } = payload;

    let normalized_name = app_name.trim().to_string();
    ensure!(!normalized_name.is_empty(), "APP_NAME_REQUIRED");
    let folder_value = sanitize_folder(folder);
    let username_value = username.trim().to_string();
    let url_value = sanitize_optional(url).unwrap_or_default();
    let description_value = sanitize_optional(description).unwrap_or_default();
    let normalized_tags = normalize_tags(&tags);
    let normalized_categories = normalize_simple_list(&categories);
    let password_value = password.trim().to_string();
    ensure!(!password_value.is_empty(), "PASSWORD_REQUIRED");

    let tag_refs: Vec<&str> = normalized_tags.iter().map(|s| s.as_str()).collect();
    let category_refs: Vec<&str> = normalized_categories.iter().map(|s| s.as_str()).collect();

    let mut engine = VaultEngine::resume_with_master_key(paths, master_key)?;
    let entry = NewCredential {
        app_name: &normalized_name,
        username: &username_value,
        url: url_value.as_str(),
        description: description_value.as_str(),
        tags: &tag_refs,
        password: &password_value,
        folder: folder_value.as_str(),
        categories: &category_refs,
    };
    let cred_id = engine.insert_credential(entry)?;
    load_detail_with_relations(paths, cred_id)
}

fn apply_credential_update(conn: &Connection, payload: UpdateCredentialInput) -> Result<()> {
    let UpdateCredentialInput {
        cred_id,
        app_name,
        username,
        url,
        description,
        folder,
        tags,
        categories,
        password: _,
        password_reason: _,
    } = payload;

    let normalized_name = app_name.trim().to_string();
    ensure!(!normalized_name.is_empty(), "APP_NAME_REQUIRED");
    let folder_value = sanitize_folder(folder);
    let username_value = sanitize_optional(username);
    let url_value = sanitize_optional(url);
    let description_value = sanitize_optional(description);
    let normalized_tags = normalize_tags(&tags);
    let normalized_categories = normalize_simple_list(&categories);
    let categories_blob =
        serde_json::to_string(&normalized_categories).unwrap_or_else(|_| "[]".to_string());
    let tag_blob = normalized_tags.join(" ");
    let json_tags = serde_json::to_string(&normalized_tags).unwrap_or_else(|_| "[]".to_string());

    conn.execute(
        "UPDATE credentials SET app_name=?1, username=?2, url=?3, description=?4, folder=?5, categories=?6, tag_blob=?7, json_tags=?8 WHERE cred_id=?9",
        params![
            normalized_name,
            username_value.as_deref(),
            url_value.as_deref(),
            description_value.as_deref(),
            folder_value,
            categories_blob,
            tag_blob,
            json_tags,
            cred_id,
        ],
    )?;

    replace_tags(conn, cred_id, &normalized_tags)?;
    Ok(())
}

fn sanitize_optional(value: String) -> Option<String> {
    let trimmed = value.trim().to_string();
    if trimmed.is_empty() {
        None
    } else {
        Some(trimmed)
    }
}

fn sanitize_folder(folder: String) -> String {
    let trimmed = folder.trim();
    if trimmed.is_empty() {
        "general".to_string()
    } else {
        trimmed.to_string()
    }
}

fn normalize_tags(raw: &[String]) -> Vec<String> {
    let mut seen = HashSet::new();
    raw.iter()
        .map(|tag| tag.trim().to_lowercase())
        .filter(|tag| !tag.is_empty())
        .filter(|tag| seen.insert(tag.clone()))
        .collect()
}

fn normalize_simple_list(raw: &[String]) -> Vec<String> {
    let mut seen = HashSet::new();
    raw.iter()
        .map(|item| item.trim().to_string())
        .filter(|item| !item.is_empty())
        .filter(|item| seen.insert(item.to_lowercase()))
        .collect()
}

fn replace_tags(conn: &Connection, cred_id: i64, tags: &[String]) -> Result<()> {
    conn.execute(
        "DELETE FROM credential_tag_map WHERE cred_id=?1",
        params![cred_id],
    )?;
    for tag in tags {
        conn.execute(
            "INSERT OR IGNORE INTO credential_tags (tag_value) VALUES (?1)",
            params![tag],
        )?;
        let tag_id: i64 = conn.query_row(
            "SELECT tag_id FROM credential_tags WHERE tag_value=?1",
            params![tag],
            |row| row.get(0),
        )?;
        conn.execute(
            "INSERT OR REPLACE INTO credential_tag_map (cred_id, tag_id, created_at_utc) VALUES (?1, ?2, ?3)",
            params![cred_id, tag_id, Utc::now().to_rfc3339()],
        )?;
    }
    Ok(())
}

#[derive(Debug, Clone, Serialize)]
pub struct UiSnapshot {
    pub folders: Vec<FolderSummary>,
    pub tags: Vec<TagSummary>,
    pub credentials: Vec<CredentialListItem>,
    pub selected: Option<CredentialDetail>,
    pub filters: UiOptions,
}

#[derive(Debug, Clone, Serialize)]
pub struct FolderSummary {
    pub name: String,
    pub count: usize,
}

#[derive(Debug, Clone, Serialize)]
pub struct TagSummary {
    pub name: String,
    pub count: usize,
}

#[derive(Debug, Clone, Serialize)]
pub struct CredentialListItem {
    pub cred_id: i64,
    pub app_name: String,
    pub folder: String,
    pub tags: Vec<String>,
    pub categories: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct CredentialDetail {
    pub cred_id: i64,
    pub app_name: String,
    pub username: String,
    pub url: String,
    pub description: String,
    pub folder: String,
    pub tags: Vec<String>,
    pub categories: Vec<String>,
    pub created_at: String,
    pub last_accessed: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct UpdateCredentialInput {
    pub cred_id: i64,
    pub app_name: String,
    pub username: String,
    pub url: String,
    pub description: String,
    pub folder: String,
    pub tags: Vec<String>,
    pub categories: Vec<String>,
    pub password: Option<String>,
    pub password_reason: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct CreateCredentialInput {
    pub app_name: String,
    pub username: String,
    pub url: String,
    pub description: String,
    pub folder: String,
    pub tags: Vec<String>,
    pub categories: Vec<String>,
    pub password: String,
}

impl UiSnapshot {
    fn load(conn: &Connection, opts: &UiOptions) -> Result<Self> {
        let folders = load_folders(conn)?;
        let tags = load_tags(conn)?;
        let credentials = load_credentials(conn, opts)?;
        let selected = if let Some(item) = credentials.first() {
            Some(
                load_detail(conn, item.cred_id)?
                    .with_tags(item.tags.clone())
                    .with_categories(item.categories.clone()),
            )
        } else {
            None
        };
        Ok(Self {
            folders,
            tags,
            credentials,
            selected,
            filters: opts.clone(),
        })
    }
}

fn load_folders(conn: &Connection) -> Result<Vec<FolderSummary>> {
    let mut stmt = conn.prepare(
        "SELECT folder, COUNT(*) FROM credentials GROUP BY folder ORDER BY folder COLLATE NOCASE",
    )?;
    let rows = stmt
        .query_map([], |row| {
            Ok(FolderSummary {
                name: row.get(0)?,
                count: row.get::<_, i64>(1)? as usize,
            })
        })?
        .collect::<Result<Vec<_>, _>>()?;
    Ok(rows)
}

fn load_tags(conn: &Connection) -> Result<Vec<TagSummary>> {
    let mut stmt = conn.prepare(
        "SELECT ct.tag_value, COUNT(*) FROM credential_tag_map ctm
         JOIN credential_tags ct ON ct.tag_id = ctm.tag_id
         GROUP BY ct.tag_value ORDER BY ct.tag_value COLLATE NOCASE",
    )?;
    let rows = stmt
        .query_map([], |row| {
            Ok(TagSummary {
                name: row.get(0)?,
                count: row.get::<_, i64>(1)? as usize,
            })
        })?
        .collect::<Result<Vec<_>, _>>()?;
    Ok(rows)
}

fn load_credentials(conn: &Connection, opts: &UiOptions) -> Result<Vec<CredentialListItem>> {
    let mut sql =
        String::from("SELECT c.cred_id, c.app_name, c.folder, c.categories FROM credentials c");
    let mut conditions: Vec<String> = Vec::new();
    let mut params: Vec<String> = Vec::new();

    if let Some(folder) = &opts.folder {
        conditions.push("LOWER(c.folder) = ?".into());
        params.push(folder.to_lowercase());
    }

    if let Some(tag) = &opts.tag {
        conditions.push(
            "EXISTS (SELECT 1 FROM credential_tag_map ctm JOIN credential_tags ct ON ct.tag_id = ctm.tag_id
             WHERE ctm.cred_id = c.cred_id AND LOWER(ct.tag_value) = ?)"
                .into(),
        );
        params.push(tag.to_lowercase());
    }

    if let Some(search) = &opts.search {
        let like = format!("%{}%", search.to_lowercase());
        conditions.push(
            "(LOWER(c.app_name) LIKE ? OR LOWER(IFNULL(c.username,'')) LIKE ? OR LOWER(IFNULL(c.url,'')) LIKE ? OR LOWER(IFNULL(c.description,'')) LIKE ?
              OR LOWER(c.folder) LIKE ? OR LOWER(c.categories) LIKE ? OR LOWER(IFNULL(c.tag_blob,'')) LIKE ?)"
                .into(),
        );
        for _ in 0..7 {
            params.push(like.clone());
        }
    }

    if !conditions.is_empty() {
        sql.push_str(" WHERE ");
        sql.push_str(&conditions.join(" AND "));
    }
    sql.push_str(" ORDER BY c.app_name COLLATE NOCASE");

    let mut stmt = conn.prepare(&sql)?;
    let rows = stmt.query_map(params_from_iter(params.iter()), |row| {
        let cred_id: i64 = row.get(0)?;
        let app_name: String = row.get(1)?;
        let folder: String = row.get(2)?;
        let categories_raw: String = row.get(3)?;
        let categories = parse_categories(&categories_raw);
        Ok((cred_id, app_name, folder, categories))
    })?;

    let mut items = Vec::new();
    for row in rows {
        let (cred_id, app_name, folder, categories) = row?;
        let tags = load_tags_for_credential(conn, cred_id)?;
        items.push(CredentialListItem {
            cred_id,
            app_name,
            folder,
            tags,
            categories,
        });
    }

    Ok(items)
}

fn load_detail(conn: &Connection, cred_id: i64) -> Result<CredentialDetail> {
    let mut stmt = conn.prepare(
        "SELECT app_name, username, url, description, folder, categories, created_at_utc, IFNULL(last_accessed_utc, '')
         FROM credentials WHERE cred_id=?1",
    )?;
    let detail = stmt.query_row([cred_id], |row| {
        let categories_raw: String = row.get(5)?;
        let url: Option<String> = row.get(2)?;
        let description: Option<String> = row.get(3)?;
        let username: Option<String> = row.get(1)?;
        Ok(CredentialDetail {
            cred_id,
            app_name: row.get(0)?,
            username: username.unwrap_or_default(),
            url: url.unwrap_or_default(),
            description: description.unwrap_or_default(),
            folder: row.get(4)?,
            tags: Vec::new(),
            categories: parse_categories(&categories_raw),
            created_at: row.get(6)?,
            last_accessed: row.get(7)?,
        })
    })?;
    Ok(detail)
}

fn load_tags_for_credential(conn: &Connection, cred_id: i64) -> Result<Vec<String>> {
    let mut stmt = conn.prepare(
        "SELECT ct.tag_value FROM credential_tag_map ctm
         JOIN credential_tags ct ON ct.tag_id = ctm.tag_id
         WHERE ctm.cred_id=?1 ORDER BY ct.tag_value COLLATE NOCASE",
    )?;
    let tags = stmt
        .query_map([cred_id], |row| row.get(0))?
        .collect::<Result<Vec<String>, _>>()?;
    Ok(tags)
}

fn parse_categories(raw: &str) -> Vec<String> {
    serde_json::from_str(raw).unwrap_or_default()
}

fn render_cli(model: &UiSnapshot) {
    println!("================ Credential UI Preview ================");
    println!(
        "Filters -> folder: {:?}, tag: {:?}, search: {:?}",
        model.filters.folder, model.filters.tag, model.filters.search
    );

    println!("\n[Column 1 • Folders]");
    let total_folders: usize = model.folders.iter().map(|f| f.count).sum();
    println!("  • All Folders ({} credentials)", total_folders);
    for folder in &model.folders {
        println!("  • {} ({})", folder.name, folder.count);
    }
    println!(
        "  (Start typing to search; new folder names are created automatically when you save.)"
    );

    println!("\n[Column 1 • Tags]");
    println!("  • All Tags");
    for tag in &model.tags {
        println!("  • {} ({})", tag.name, tag.count);
    }

    println!("\n[Column 2 • Credential List]");
    if model.credentials.is_empty() {
        println!("  No credentials match your filters yet.");
    } else {
        for cred in &model.credentials {
            println!(
                "  - {} [folder: {}] tags: {} | categories: {}",
                cred.app_name,
                cred.folder,
                if cred.tags.is_empty() {
                    "(none)".into()
                } else {
                    cred.tags.join(", ")
                },
                if cred.categories.is_empty() {
                    "(none)".into()
                } else {
                    cred.categories.join(", ")
                }
            );
        }
    }

    println!("\n[Column 3 • Details]");
    if let Some(detail) = &model.selected {
        println!("App Name: {}", detail.app_name);
        println!("Folder: {}", detail.folder);
        if detail.username.is_empty() {
            println!("Username: (none)");
        } else {
            println!("Username: {}", detail.username);
        }
        println!("URL: {}", detail.url);
        println!("Description: {}", detail.description);
        println!(
            "Tags: {}",
            if detail.tags.is_empty() {
                "(none)".into()
            } else {
                detail.tags.join(", ")
            }
        );
        println!(
            "Categories: {}",
            if detail.categories.is_empty() {
                "(none)".into()
            } else {
                detail.categories.join(", ")
            }
        );
        println!("Created: {}", detail.created_at);
        println!("Last accessed: {}", detail.last_accessed);
        println!("Actions: [Edit] [Save] [Delete] [Archive]");
        println!("Password reveal requires re-authentication when timer expires.");
    } else {
        println!("Select a credential to view its details.");
    }
}

trait DetailExt {
    fn with_tags(self, tags: Vec<String>) -> Self;
    fn with_categories(self, categories: Vec<String>) -> Self;
}

impl DetailExt for CredentialDetail {
    fn with_tags(mut self, tags: Vec<String>) -> Self {
        self.tags = tags;
        self
    }

    fn with_categories(mut self, categories: Vec<String>) -> Self {
        self.categories = categories;
        self
    }
}
