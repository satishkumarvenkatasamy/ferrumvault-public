use std::collections::HashMap;
use std::fs;
use std::io::{Cursor, Read, Write};
use std::path::Path;
use std::sync::Mutex;
use std::time::Duration;

use anyhow::{Context, Result, anyhow, ensure};
use base64::{
    Engine as _,
    engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD},
};
use chrono::{DateTime, Utc};
use hex::encode as hex_encode;
use once_cell::sync::Lazy;
use rand::RngCore;
use reqwest::blocking::Client;
use reqwest::header::CONTENT_TYPE;
use rusqlite::{Connection, OptionalExtension};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tempfile::TempDir;
use uuid::Uuid;
use zip::write::FileOptions;
use zip::{CompressionMethod, ZipArchive, ZipWriter};

use crate::crypto::{CipherBlob, decrypt_with_key, encrypt_with_key, generate_random_dek};
use crate::db::{VaultPaths, open_connection};

const BUNDLE_SCHEMA_VERSION: &str = "1";
const DRIVE_API_ROOT: &str = "https://www.googleapis.com/drive/v3";
const DRIVE_UPLOAD_ROOT: &str = "https://www.googleapis.com/upload/drive/v3";
const TOKEN_ENDPOINT: &str = "https://oauth2.googleapis.com/token";
const DRIVE_APPDATA_PARENT: &str = "appDataFolder";
const OAUTH_AUTH_ENDPOINT: &str = "https://accounts.google.com/o/oauth2/v2/auth";
const OAUTH_SCOPE: &str = "https://www.googleapis.com/auth/drive.appdata";
pub const GOOGLE_OAUTH_CLIENT_ID: &str = "__SET_GOOGLE_OAUTH_CLIENT_ID__";
pub const GOOGLE_OAUTH_REDIRECT_URI: &str = "http://localhost";
pub const GOOGLE_OAUTH_CLIENT_SECRET: &str = "__SET_GOOGLE_OAUTH_CLIENT_SECRET__";

struct PendingPkce {
    verifier: String,
    redirect_uri: String,
}

static PENDING_PKCE: Lazy<Mutex<HashMap<String, PendingPkce>>> =
    Lazy::new(|| Mutex::new(HashMap::new()));

static BUILTIN_CLIENT_ID: Lazy<String> = Lazy::new(|| GOOGLE_OAUTH_CLIENT_ID.to_string());
static BUILTIN_REDIRECT_URI: Lazy<String> = Lazy::new(|| GOOGLE_OAUTH_REDIRECT_URI.to_string());
static BUILTIN_CLIENT_SECRET: Lazy<String> = Lazy::new(|| GOOGLE_OAUTH_CLIENT_SECRET.to_string());

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BundleFileMeta {
    pub name: String,
    pub checksum_hex: String,
    pub bytes: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BundleManifest {
    pub bundle_id: String,
    pub profile: String,
    pub revision: i64,
    pub schema_version: String,
    pub created_at_utc: String,
    pub device_fingerprint: String,
    pub device_label: String,
    pub files: Vec<BundleFileMeta>,
}

#[derive(Debug, Clone)]
pub struct BundleContext<'a> {
    pub profile: &'a str,
    pub revision: i64,
    pub device_fingerprint: &'a str,
    pub device_label: &'a str,
}

#[derive(Debug, Clone)]
pub struct BundleEnvelope {
    pub manifest: BundleManifest,
    pub cipher_blob: CipherBlob,
    pub wrapped_dek: CipherBlob,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct BundlePackage {
    manifest: BundleManifest,
    wrapped_dek: String,
    cipher_blob: String,
}

#[derive(Debug, Clone, Default)]
pub struct SyncCredentials {
    pub access_token: Option<String>,
    pub refresh_token: Option<String>,
    pub token_expires_at_utc: Option<String>,
    pub folder_id: Option<String>,
    pub device_fingerprint: Option<String>,
    pub device_label: Option<String>,
    pub client_id: Option<String>,
    pub client_secret: Option<String>,
    pub redirect_uri: Option<String>,
}

impl SyncCredentials {
    fn load(conn: &Connection) -> Result<Self> {
        let row = conn
            .query_row(
                "SELECT access_token, refresh_token, token_expires_at_utc, folder_id, \
                 device_fingerprint, device_label, client_id, client_secret, redirect_uri \
                 FROM sync_credentials WHERE id=1",
                [],
                |row| {
                    Ok(SyncCredentials {
                        access_token: row.get(0).ok(),
                        refresh_token: row.get(1).ok(),
                        token_expires_at_utc: row.get(2).ok(),
                        folder_id: row.get(3).ok(),
                        device_fingerprint: row.get(4).ok(),
                        device_label: row.get(5).ok(),
                        client_id: row.get(6).ok(),
                        client_secret: row.get(7).ok(),
                        redirect_uri: row.get(8).ok(),
                    })
                },
            )
            .optional()?;
        Ok(row.unwrap_or_default())
    }

    fn save(&self, conn: &Connection) -> Result<()> {
        conn.execute(
            "INSERT INTO sync_credentials \
             (id, access_token, refresh_token, token_expires_at_utc, folder_id, \
              device_fingerprint, device_label, client_id, client_secret, redirect_uri) \
             VALUES (1, ?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9) \
             ON CONFLICT(id) DO UPDATE SET \
                access_token=excluded.access_token,
                refresh_token=excluded.refresh_token,
                token_expires_at_utc=excluded.token_expires_at_utc,
                folder_id=excluded.folder_id,
                device_fingerprint=excluded.device_fingerprint,
                device_label=excluded.device_label,
                client_id=excluded.client_id,
                client_secret=excluded.client_secret,
                redirect_uri=excluded.redirect_uri",
            rusqlite::params![
                self.access_token,
                self.refresh_token,
                self.token_expires_at_utc,
                self.folder_id,
                self.device_fingerprint,
                self.device_label,
                self.client_id,
                self.client_secret,
                self.redirect_uri,
            ],
        )?;
        Ok(())
    }

    fn require_refresh_token(&self) -> Result<&str> {
        self.refresh_token
            .as_deref()
            .ok_or_else(|| anyhow!("SYNC_NOT_CONFIGURED"))
    }

    pub fn require_client_config(&self) -> Result<GoogleOAuthConfig> {
        if let Some(client_id) = self.client_id.clone() {
            let redirect = self
                .redirect_uri
                .clone()
                .filter(|value| !value.trim().is_empty())
                .unwrap_or_else(|| (*BUILTIN_REDIRECT_URI).clone());
            return Ok(GoogleOAuthConfig {
                client_id,
                client_secret: self.client_secret.clone(),
                redirect_uri: redirect,
            });
        }
        builtin_client_config()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SyncPreferences {
    pub auto_upload_on_exit: bool,
    pub auto_download_on_new: bool,
    pub keep_revisions: i64,
}

impl Default for SyncPreferences {
    fn default() -> Self {
        Self {
            auto_upload_on_exit: false,
            auto_download_on_new: false,
            keep_revisions: 5,
        }
    }
}

#[derive(Debug, Clone)]
pub struct DeviceInfo {
    pub fingerprint: String,
    pub label: String,
}

impl DeviceInfo {
    pub fn current() -> Result<Self> {
        let hostname = whoami::fallible::hostname().unwrap_or_else(|_| "unknown-host".to_string());
        let username = whoami::username();
        let platform = whoami::platform().to_string();
        let distro = whoami::distro();
        let arch = std::env::consts::ARCH;
        let payload = format!("{}:{}:{}:{}:{}", hostname, username, platform, distro, arch);
        let digest = Sha256::digest(payload.as_bytes());
        Ok(Self {
            fingerprint: hex_encode(digest),
            label: format!("{} ({})", hostname, platform),
        })
    }
}

#[derive(Debug, Clone)]
pub struct SyncStatus {
    pub last_revision: i64,
    pub last_bundle_id: Option<String>,
    pub last_uploaded_at_utc: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct DriveBundleInfo {
    pub file_id: String,
    pub name: String,
    pub modified_time: Option<String>,
    pub profile: Option<String>,
    pub revision: Option<i64>,
}

#[derive(Debug, Serialize)]
pub struct OauthBegin {
    pub auth_url: String,
    pub state: String,
}

pub struct SyncService<'a> {
    paths: &'a VaultPaths,
}

impl<'a> SyncService<'a> {
    pub fn new(paths: &'a VaultPaths) -> Self {
        Self { paths }
    }

    pub fn configure(
        &self,
        refresh_token: String,
        client_id: Option<String>,
        client_secret: Option<String>,
        redirect_uri: Option<String>,
    ) -> Result<()> {
        let conn = open_connection(&self.paths.master_db)?;
        let mut creds = SyncCredentials::load(&conn)?;
        if let Some(id) = client_id {
            creds.client_id = Some(id);
        }
        if let Some(secret) = client_secret {
            creds.client_secret = Some(secret);
        }
        if let Some(uri) = redirect_uri {
            creds.redirect_uri = Some(uri);
        }
        creds.refresh_token = Some(refresh_token);
        creds.access_token = None;
        creds.token_expires_at_utc = None;
        creds.folder_id = Some(DRIVE_APPDATA_PARENT.to_string());
        creds.save(&conn)
    }

    pub fn upload_bundle(
        &self,
        master_key: &[u8; 32],
        device: &DeviceInfo,
        drive: &mut GoogleDriveClient,
        creds: &mut SyncCredentials,
    ) -> Result<BundleManifest> {
        let revision = self.next_revision()?;
        let ctx = BundleContext {
            profile: self.profile_name(),
            revision,
            device_fingerprint: &device.fingerprint,
            device_label: &device.label,
        };
        let bundle = create_encrypted_bundle(self.paths, &ctx, master_key)?;
        let payload = serialize_bundle(&bundle)?;
        creds.device_fingerprint = Some(device.fingerprint.clone());
        creds.device_label = Some(device.label.clone());
        drive.upload_payload(creds, &bundle.manifest, &payload)?;
        self.record_upload(&bundle.manifest)?;
        self.save_credentials(creds)?;
        Ok(bundle.manifest)
    }

    pub fn download_latest(
        &self,
        master_key: &[u8; 32],
        drive: &mut GoogleDriveClient,
        creds: &mut SyncCredentials,
    ) -> Result<BundleManifest> {
        let files = drive.list_bundles(creds)?;
        let file = files.first().ok_or_else(|| anyhow!("NO_BUNDLES"))?;
        self.download_by_id(master_key, drive, creds, &file.file_id)
    }

    pub fn download_by_id(
        &self,
        master_key: &[u8; 32],
        drive: &mut GoogleDriveClient,
        creds: &mut SyncCredentials,
        file_id: &str,
    ) -> Result<BundleManifest> {
        let bytes = drive.download_file(creds, file_id)?;
        let manifest = restore_bundle(self.paths, &bytes, master_key)?;
        self.record_upload(&manifest)?;
        self.save_credentials(creds)?;
        Ok(manifest)
    }

    pub fn status(&self) -> Result<SyncStatus> {
        let conn = open_connection(&self.paths.master_db)?;
        let row = conn
            .query_row(
                "SELECT last_revision, last_bundle_id, last_uploaded_at_utc FROM sync_state WHERE id=1",
                [],
                |row| {
                    Ok(SyncStatus {
                        last_revision: row.get(0)?,
                        last_bundle_id: row.get::<_, Option<String>>(1)?,
                        last_uploaded_at_utc: row.get::<_, Option<String>>(2)?,
                    })
                },
            )
            .optional()?;
        Ok(row.unwrap_or(SyncStatus {
            last_revision: 0,
            last_bundle_id: None,
            last_uploaded_at_utc: None,
        }))
    }

    pub fn load_credentials(&self) -> Result<SyncCredentials> {
        let conn = open_connection(&self.paths.master_db)?;
        SyncCredentials::load(&conn)
    }

    pub fn save_credentials(&self, creds: &SyncCredentials) -> Result<()> {
        let conn = open_connection(&self.paths.master_db)?;
        creds.save(&conn)
    }

    pub fn load_preferences(&self) -> Result<SyncPreferences> {
        let conn = open_connection(&self.paths.master_db)?;
        let row = conn
            .query_row(
                "SELECT auto_upload_on_exit, auto_download_on_new, keep_revisions FROM sync_preferences WHERE id=1",
                [],
                |row| {
                    Ok(SyncPreferences {
                        auto_upload_on_exit: row.get::<_, i64>(0)? != 0,
                        auto_download_on_new: row.get::<_, i64>(1)? != 0,
                        keep_revisions: row.get(2)?,
                    })
                },
            )
            .optional()?;
        Ok(row.unwrap_or_default())
    }

    pub fn update_preferences(&self, prefs: &SyncPreferences) -> Result<()> {
        let conn = open_connection(&self.paths.master_db)?;
        conn.execute(
            "INSERT INTO sync_preferences (id, auto_upload_on_exit, auto_download_on_new, keep_revisions) \
             VALUES (1, ?1, ?2, ?3) \
             ON CONFLICT(id) DO UPDATE SET \
                 auto_upload_on_exit=excluded.auto_upload_on_exit,
                 auto_download_on_new=excluded.auto_download_on_new,
                 keep_revisions=excluded.keep_revisions",
            rusqlite::params![
                prefs.auto_upload_on_exit as i64,
                prefs.auto_download_on_new as i64,
                prefs.keep_revisions,
            ],
        )?;
        Ok(())
    }

    pub fn begin_oauth_flow(&self, override_redirect: Option<&str>) -> Result<OauthBegin> {
        let creds = self.load_credentials()?;
        let mut config = creds.require_client_config()?;
        if let Some(uri) = override_redirect {
            config.redirect_uri = uri.to_string();
        }
        let (verifier, challenge) = generate_pkce_pair();
        let state = Uuid::new_v4().to_string();
        {
            let mut map = PENDING_PKCE.lock().expect("pkce lock");
            map.insert(
                state.clone(),
                PendingPkce {
                    verifier,
                    redirect_uri: config.redirect_uri.clone(),
                },
            );
        }
        let auth_url = format!(
            "{}?client_id={}&response_type=code&scope={}&redirect_uri={}&code_challenge={}&code_challenge_method=S256&access_type=offline&prompt=consent&state={}",
            OAUTH_AUTH_ENDPOINT,
            urlencoding::encode(&config.client_id),
            urlencoding::encode(OAUTH_SCOPE),
            urlencoding::encode(&config.redirect_uri),
            challenge,
            state
        );
        Ok(OauthBegin { auth_url, state })
    }

    pub fn complete_oauth_flow(&self, state: &str, code: &str) -> Result<()> {
        let pending = {
            let mut map = PENDING_PKCE.lock().expect("pkce lock");
            map.remove(state)
        }
        .ok_or_else(|| anyhow!("PKCE_STATE_NOT_FOUND"))?;
        let mut creds = self.load_credentials()?;
        let config = creds.require_client_config()?;
        let mut params = vec![
            ("client_id", config.client_id.as_str()),
            ("code", code),
            ("code_verifier", pending.verifier.as_str()),
            ("grant_type", "authorization_code"),
            ("redirect_uri", pending.redirect_uri.as_str()),
        ];
        if let Some(secret) = config.client_secret.as_deref() {
            params.push(("client_secret", secret));
        }
        let http = Client::new();
        let resp = http.post(TOKEN_ENDPOINT).form(&params).send()?;
        if !resp.status().is_success() {
            return Err(anyhow!("OAUTH_EXCHANGE_FAILED: {}", resp.text()?));
        }
        let mut payload: TokenResponse = resp.json()?;
        if payload.refresh_token.is_none() {
            return Err(anyhow!("REFRESH_TOKEN_MISSING"));
        }
        creds.refresh_token = payload.refresh_token.take();
        creds.access_token = Some(payload.access_token);
        let expires_at = Utc::now() + chrono::Duration::seconds(payload.expires_in as i64 - 30);
        creds.token_expires_at_utc = Some(expires_at.to_rfc3339());
        self.save_credentials(&creds)
    }

    fn record_upload(&self, manifest: &BundleManifest) -> Result<()> {
        let conn = open_connection(&self.paths.master_db)?;
        conn.execute(
            "INSERT INTO sync_state (id, last_revision, last_bundle_id, last_uploaded_at_utc) \
             VALUES (1, ?1, ?2, ?3) \
             ON CONFLICT(id) DO UPDATE SET \
                last_revision=excluded.last_revision,
                last_bundle_id=excluded.last_bundle_id,
                last_uploaded_at_utc=excluded.last_uploaded_at_utc",
            rusqlite::params![
                manifest.revision,
                manifest.bundle_id,
                manifest.created_at_utc,
            ],
        )?;
        Ok(())
    }

    fn profile_name(&self) -> &str {
        self.paths
            .profile_root
            .file_name()
            .and_then(|s| s.to_str())
            .unwrap_or("default")
    }

    fn next_revision(&self) -> Result<i64> {
        Ok(self.status()?.last_revision + 1)
    }
}

fn serialize_bundle(bundle: &BundleEnvelope) -> Result<Vec<u8>> {
    let package = BundlePackage {
        manifest: bundle.manifest.clone(),
        wrapped_dek: STANDARD.encode(bundle.wrapped_dek.to_bytes()),
        cipher_blob: STANDARD.encode(bundle.cipher_blob.to_bytes()),
    };
    Ok(serde_json::to_vec(&package)?)
}

fn deserialize_bundle(bytes: &[u8]) -> Result<BundlePackage> {
    let package: BundlePackage = serde_json::from_slice(bytes)?;
    Ok(package)
}

fn restore_bundle(
    paths: &VaultPaths,
    bytes: &[u8],
    master_key: &[u8; 32],
) -> Result<BundleManifest> {
    let package = deserialize_bundle(bytes)?;
    let wrapped = STANDARD.decode(package.wrapped_dek)?;
    let cipher = STANDARD.decode(package.cipher_blob)?;
    let wrapped_blob = CipherBlob::from_bytes(&wrapped)?;
    let dek_bytes = decrypt_with_key(master_key, &wrapped_blob)?;
    ensure!(dek_bytes.len() == 32, "invalid bundle DEK length");
    let mut dek = [0u8; 32];
    dek.copy_from_slice(&dek_bytes);
    let cipher_blob = CipherBlob::from_bytes(&cipher)?;
    let plaintext = decrypt_with_key(&dek, &cipher_blob)?;
    extract_archive(paths, &package.manifest, &plaintext)?;
    Ok(package.manifest)
}

fn extract_archive(paths: &VaultPaths, manifest: &BundleManifest, data: &[u8]) -> Result<()> {
    let tmp = TempDir::new()?;
    let cursor = Cursor::new(data);
    let mut archive = ZipArchive::new(cursor)?;
    for (name, target) in vault_file_pairs(paths) {
        let mut file = archive
            .by_name(name)
            .with_context(|| format!("Missing file {name} in bundle"))?;
        let mut buf = Vec::new();
        file.read_to_end(&mut buf)?;
        let expected = manifest
            .files
            .iter()
            .find(|meta| meta.name == name)
            .ok_or_else(|| anyhow!("Missing checksum meta for {name}"))?;
        let checksum = hex_encode(Sha256::digest(&buf));
        ensure!(
            checksum == expected.checksum_hex,
            "checksum mismatch for {name}"
        );
        let tmp_path = tmp.path().join(name);
        fs::write(&tmp_path, &buf)?;
        fs::rename(tmp_path, target)?;
    }
    Ok(())
}

fn vault_file_pairs(paths: &VaultPaths) -> Vec<(&'static str, &Path)> {
    vec![
        ("vault_master.db", &paths.master_db),
        ("vault_p2.db", &paths.part2_db),
        ("vault_p3.db", &paths.part3_db),
        ("vault_p4.db", &paths.part4_db),
    ]
}

fn parse_revision_from_name(name: Option<&str>) -> Option<i64> {
    let name = name?;
    let parts: Vec<_> = name.split('-').collect();
    if parts.len() < 2 {
        return None;
    }
    let rev_part = parts[1];
    if let Some(rest) = rev_part.strip_prefix('r') {
        rest.parse().ok()
    } else {
        None
    }
}

fn parse_profile_from_name(name: Option<&str>) -> Option<String> {
    let name = name?;
    name.split('-').next().map(|p| p.to_string())
}

fn generate_pkce_pair() -> (String, String) {
    let mut verifier_bytes = [0u8; 64];
    rand::thread_rng().fill_bytes(&mut verifier_bytes);
    let verifier = URL_SAFE_NO_PAD.encode(verifier_bytes);
    let challenge_bytes = Sha256::digest(verifier.as_bytes());
    let challenge = URL_SAFE_NO_PAD.encode(challenge_bytes);
    (verifier, challenge)
}

#[derive(Debug, Clone)]
pub struct GoogleOAuthConfig {
    client_id: String,
    client_secret: Option<String>,
    redirect_uri: String,
}

fn builtin_client_config() -> Result<GoogleOAuthConfig> {
    let client_id = (*BUILTIN_CLIENT_ID).clone();
    ensure!(!client_id.trim().is_empty(), "CLIENT_ID_MISSING");
    let redirect_uri = (*BUILTIN_REDIRECT_URI).clone();
    ensure!(!redirect_uri.trim().is_empty(), "REDIRECT_URI_MISSING");
    let secret = (*BUILTIN_CLIENT_SECRET).clone();
    ensure!(!secret.trim().is_empty(), "CLIENT_SECRET_MISSING");
    Ok(GoogleOAuthConfig {
        client_id,
        client_secret: Some(secret),
        redirect_uri,
    })
}

pub struct GoogleDriveClient {
    http: Client,
    config: GoogleOAuthConfig,
}

impl GoogleDriveClient {
    pub fn new(config: GoogleOAuthConfig) -> Result<Self> {
        let http = Client::builder().timeout(Duration::from_secs(60)).build()?;
        Ok(Self { http, config })
    }

    pub fn upload_payload(
        &mut self,
        creds: &mut SyncCredentials,
        manifest: &BundleManifest,
        payload: &[u8],
    ) -> Result<()> {
        self.ensure_access_token(creds)?;
        creds.folder_id = Some(DRIVE_APPDATA_PARENT.to_string());
        let metadata = serde_json::json!({
            "name": format!("{}-r{}-{}.fvault", manifest.profile, manifest.revision, manifest.bundle_id),
            "parents": [DRIVE_APPDATA_PARENT],
            "mimeType": "application/octet-stream"
        });
        let metadata_json = serde_json::to_string(&metadata)?;
        let boundary = format!("batch_{}", Uuid::new_v4());
        let mut body = Vec::new();
        body.extend_from_slice(
            format!(
                "--{}\r\nContent-Type: application/json; charset=UTF-8\r\n\r\n",
                boundary
            )
            .as_bytes(),
        );
        body.extend_from_slice(metadata_json.as_bytes());
        body.extend_from_slice(b"\r\n");
        body.extend_from_slice(
            format!(
                "--{}\r\nContent-Type: application/octet-stream\r\n\r\n",
                boundary
            )
            .as_bytes(),
        );
        body.extend_from_slice(payload);
        body.extend_from_slice(format!("\r\n--{}--\r\n", boundary).as_bytes());
        let token = creds
            .access_token
            .as_deref()
            .ok_or_else(|| anyhow!("MISSING_ACCESS_TOKEN"))?;
        let url = format!(
            "{}/files?uploadType=multipart&supportsAllDrives=false",
            DRIVE_UPLOAD_ROOT
        );
        let resp = self
            .http
            .post(url)
            .bearer_auth(token)
            .body(body)
            .header(
                CONTENT_TYPE,
                format!("multipart/related; boundary={}", boundary),
            )
            .send()?;
        if !resp.status().is_success() {
            return Err(anyhow!("UPLOAD_FAILED: {}", resp.text()?));
        }
        Ok(())
    }

    pub fn list_bundles(&mut self, creds: &mut SyncCredentials) -> Result<Vec<DriveBundleInfo>> {
        self.ensure_access_token(creds)?;
        let token = creds
            .access_token
            .as_deref()
            .ok_or_else(|| anyhow!("MISSING_ACCESS_TOKEN"))?;
        let query = format!("'{}' in parents and trashed = false", DRIVE_APPDATA_PARENT);
        let url = format!(
            "{}/files?q={}&spaces={}&fields=files(id,name,modifiedTime,size)&orderBy=modifiedTime desc&pageSize=20",
            DRIVE_API_ROOT,
            urlencoding::encode(&query),
            DRIVE_APPDATA_PARENT
        );
        let resp = self.http.get(url).bearer_auth(token).send()?;
        if !resp.status().is_success() {
            return Err(anyhow!("LIST_FAILED: {}", resp.text()?));
        }
        let wrapper: DriveListResponse = resp.json()?;
        let bundles = wrapper
            .files
            .into_iter()
            .map(|file| DriveBundleInfo {
                file_id: file.id,
                name: file.name.clone().unwrap_or_default(),
                modified_time: file.modified_time.clone(),
                profile: parse_profile_from_name(file.name.as_deref()),
                revision: parse_revision_from_name(file.name.as_deref()),
            })
            .collect();
        Ok(bundles)
    }

    pub fn download_file(&mut self, creds: &mut SyncCredentials, file_id: &str) -> Result<Vec<u8>> {
        self.ensure_access_token(creds)?;
        let token = creds
            .access_token
            .as_deref()
            .ok_or_else(|| anyhow!("MISSING_ACCESS_TOKEN"))?;
        let url = format!("{}/files/{}?alt=media", DRIVE_API_ROOT, file_id);
        let resp = self.http.get(url).bearer_auth(token).send()?;
        if !resp.status().is_success() {
            return Err(anyhow!("DOWNLOAD_FAILED: {}", resp.text()?));
        }
        Ok(resp.bytes()?.to_vec())
    }

    fn ensure_access_token(&self, creds: &mut SyncCredentials) -> Result<()> {
        match (
            creds.token_expires_at_utc.as_ref(),
            creds.access_token.as_ref(),
        ) {
            (Some(expiry), Some(token)) if !token.is_empty() && !is_expired(expiry) => {
                return Ok(());
            }
            _ => {}
        }
        self.refresh_access_token(creds)
    }

    fn refresh_access_token(&self, creds: &mut SyncCredentials) -> Result<()> {
        let refresh = creds.require_refresh_token()?.to_string();
        let mut params = vec![
            ("client_id", self.config.client_id.as_str()),
            ("grant_type", "refresh_token"),
            ("refresh_token", refresh.as_str()),
        ];
        if let Some(secret) = self.config.client_secret.as_deref() {
            params.push(("client_secret", secret));
        }
        let resp = self.http.post(TOKEN_ENDPOINT).form(&params).send()?;
        if !resp.status().is_success() {
            return Err(anyhow!("TOKEN_REFRESH_FAILED: {}", resp.text()?));
        }
        let payload: TokenResponse = resp.json()?;
        let expires_at = Utc::now() + chrono::Duration::seconds(payload.expires_in as i64 - 30);
        creds.access_token = Some(payload.access_token);
        creds.token_expires_at_utc = Some(expires_at.to_rfc3339());
        Ok(())
    }
}

#[derive(Debug, Deserialize)]
struct TokenResponse {
    access_token: String,
    expires_in: u64,
    #[serde(default)]
    refresh_token: Option<String>,
}

#[derive(Debug, Deserialize, Clone)]
pub struct DriveFile {
    pub id: String,
    pub name: Option<String>,
    #[serde(rename = "modifiedTime", default)]
    pub modified_time: Option<String>,
    #[serde(default)]
    pub size: Option<String>,
}

#[derive(Debug, Deserialize)]
struct DriveListResponse {
    #[serde(default)]
    files: Vec<DriveFile>,
}

fn is_expired(expires_at: &str) -> bool {
    DateTime::parse_from_rfc3339(expires_at)
        .map(|dt| dt.with_timezone(&Utc) <= Utc::now())
        .unwrap_or(true)
}

pub fn create_encrypted_bundle(
    paths: &VaultPaths,
    ctx: &BundleContext<'_>,
    master_key: &[u8; 32],
) -> Result<BundleEnvelope> {
    let mut files = Vec::new();
    let mut cursor = Cursor::new(Vec::new());
    let manifest;
    {
        let mut zip = ZipWriter::new(&mut cursor);
        let file_options = FileOptions::default()
            .compression_method(CompressionMethod::Deflated)
            .unix_permissions(0o600);

        for (name, path) in vault_file_pairs(paths) {
            let data = fs::read(path)
                .with_context(|| format!("Reading vault file for bundling: {}", path.display()))?;
            let checksum = Sha256::digest(&data);
            let metadata = BundleFileMeta {
                name: name.to_string(),
                checksum_hex: hex_encode(checksum),
                bytes: data.len() as u64,
            };
            zip.start_file(name, file_options)?;
            zip.write_all(&data)?;
            files.push(metadata);
        }

        manifest = BundleManifest {
            bundle_id: Uuid::new_v4().to_string(),
            profile: ctx.profile.to_string(),
            revision: ctx.revision,
            schema_version: BUNDLE_SCHEMA_VERSION.to_string(),
            created_at_utc: Utc::now().to_rfc3339(),
            device_fingerprint: ctx.device_fingerprint.to_string(),
            device_label: ctx.device_label.to_string(),
            files: files.clone(),
        };
        let manifest_bytes = serde_json::to_vec(&manifest)?;
        zip.start_file("manifest.json", file_options)?;
        zip.write_all(&manifest_bytes)?;
        zip.finish()?;
    }

    let archive_bytes = cursor.into_inner();
    let bundle_dek = generate_random_dek();
    let cipher_blob = encrypt_with_key(&bundle_dek, &archive_bytes)?;
    let wrapped_dek = encrypt_with_key(master_key, bundle_dek.as_slice())?;

    Ok(BundleEnvelope {
        manifest,
        cipher_blob,
        wrapped_dek,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn write_file(path: &Path, content: &[u8]) {
        fs::write(path, content).unwrap();
    }

    #[test]
    fn bundle_contains_all_files() {
        let tmp = TempDir::new().unwrap();
        let base = tmp.path();
        let paths = VaultPaths::new(base, "test-profile");
        fs::create_dir_all(&paths.profile_root).unwrap();
        write_file(&paths.master_db, b"master");
        write_file(&paths.part2_db, b"p2");
        write_file(&paths.part3_db, b"p3");
        write_file(&paths.part4_db, b"p4");

        let master_key = [0u8; 32];
        let device = DeviceInfo::current().unwrap();
        let ctx = BundleContext {
            profile: "test-profile",
            revision: 1,
            device_fingerprint: &device.fingerprint,
            device_label: &device.label,
        };
        let bundle = create_encrypted_bundle(&paths, &ctx, &master_key).unwrap();
        assert_eq!(bundle.manifest.files.len(), 4);
        assert_eq!(bundle.manifest.profile, "test-profile");
        let payload = serialize_bundle(&bundle).unwrap();
        let manifest = restore_bundle(&paths, &payload, &master_key).unwrap();
        assert_eq!(manifest.profile, "test-profile");
    }
}
