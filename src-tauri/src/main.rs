#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use std::{
    env,
    fs::{self, OpenOptions},
    io::{BufRead, BufReader, Write},
    net::{TcpListener, TcpStream},
    path::{Path, PathBuf},
    sync::{Mutex, OnceLock},
    thread,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

use anyhow::{anyhow, Context as AnyhowContext, Result};
use credmanager_app::{
    crypto::{MIN_SECRET_LEN, PBKDF2_DEFAULT_ITERS},
    db::{initialize_vault, VaultPaths},
    default_base_dir,
    sync::{
        DeviceInfo, DriveBundleInfo, GoogleDriveClient, OauthBegin, SyncPreferences, SyncService,
    },
    ui::{
        create_credential, gather_snapshot, load_detail_with_relations, update_credential,
        CreateCredentialInput, CredentialDetail, UiOptions, UiSnapshot, UpdateCredentialInput,
    },
    vault::{
        change_master_password, derive_master_key_for_profile, vault_initialized,
        PasswordHistoryMeta, VaultEngine,
    },
};
use serde::{Deserialize, Serialize};
use serde_json::json;
use tauri::Manager;
use url::Url;

const DEFAULT_PROFILE: &str = "default";
const SESSION_TIMEOUT: Duration = Duration::from_secs(5 * 60);
const LOG_FILE_NAME: &str = "tauri-debug.log";
const CONTEXT_FILE_NAME: &str = "vault-context.json";
const OAUTH_DEEP_LINK_EVENT: &str = "sync://oauth-complete";
const LOOPBACK_HOST: &str = "127.0.0.1";
const LOOPBACK_REDIRECT_HOST: &str = "localhost";
const OAUTH_LOOPBACK_PATH: &str = "/oauth2callback";
const OAUTH_LOOPBACK_TIMEOUT: Duration = Duration::from_secs(5 * 60);

static LOG_PATH: OnceLock<PathBuf> = OnceLock::new();
static LOG_FILE_LOCK: OnceLock<Mutex<()>> = OnceLock::new();

fn default_context() -> VaultContext {
    let base_dir = match default_base_dir() {
        Ok(dir) => dir,
        Err(err) => {
            eprintln!("Failed to determine default base dir: {}", err);
            env::current_dir().unwrap_or_else(|_| PathBuf::from("."))
        }
    };
    VaultContext {
        base_dir,
        profile: DEFAULT_PROFILE.to_string(),
    }
}

fn load_context_or_default() -> VaultContext {
    match load_saved_context() {
        Ok(ctx) => ctx,
        Err(err) => {
            eprintln!("Falling back to default context: {}", err);
            default_context()
        }
    }
}

fn load_saved_context() -> Result<VaultContext> {
    let path = context_file_path()?;
    let data = fs::read(&path)
        .with_context(|| format!("Reading vault context file at {}", path.display()))?;
    let stored: StoredContext = serde_json::from_slice(&data)
        .with_context(|| format!("Parsing vault context from {}", path.display()))?;
    Ok(VaultContext {
        base_dir: stored.base_dir,
        profile: stored.profile,
    })
}

fn persist_context(context: &VaultContext) -> Result<()> {
    let path = context_file_path()?;
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)
            .with_context(|| format!("Preparing context directory {}", parent.display()))?;
    }
    let stored = StoredContext {
        base_dir: context.base_dir.clone(),
        profile: context.profile.clone(),
    };
    let data = serde_json::to_vec_pretty(&stored)?;
    fs::write(&path, data)
        .with_context(|| format!("Writing context file at {}", path.display()))?;
    Ok(())
}

fn context_file_path() -> Result<PathBuf> {
    let default = default_base_dir()?;
    Ok(default.join(CONTEXT_FILE_NAME))
}

fn normalize_base_dir_input(raw: &str) -> Result<PathBuf> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return Err(anyhow!("BASE_DIR_REQUIRED"));
    }
    let expanded = if trimmed == "~" {
        resolve_home_dir().ok_or_else(|| anyhow!("HOME_DIR_UNAVAILABLE"))?
    } else if trimmed.starts_with("~/") || trimmed.starts_with("~\\") {
        let home = resolve_home_dir().ok_or_else(|| anyhow!("HOME_DIR_UNAVAILABLE"))?;
        let suffix = &trimmed[2..];
        home.join(suffix)
    } else {
        PathBuf::from(trimmed)
    };
    let resolved = if expanded.is_absolute() {
        expanded
    } else {
        env::current_dir()
            .with_context(|| "Resolving current working directory for vault base path")?
            .join(expanded)
    };
    Ok(resolved)
}

fn resolve_home_dir() -> Option<PathBuf> {
    if cfg!(windows) {
        env::var("USERPROFILE").map(PathBuf::from).ok()
    } else {
        env::var("HOME").map(PathBuf::from).ok()
    }
}

#[derive(Clone, Debug)]
struct VaultContext {
    base_dir: PathBuf,
    profile: String,
}

#[derive(Serialize, Deserialize)]
struct StoredContext {
    base_dir: PathBuf,
    profile: String,
}

fn initialize_logging() {
    println!("Entered initialize_logging...");
    if LOG_PATH.get().is_some() {
        println!("Logging path is valid.");
        return;
    }
    let base = load_context_or_default().base_dir;
    let path = base.join(LOG_FILE_NAME);
    println!("Logging path is {}", path.display());
    if LOG_PATH.set(path.clone()).is_ok() {
        if let Some(parent) = path.parent() {
            let _ = std::fs::create_dir_all(parent);
        }
        let _ = OpenOptions::new().create(true).append(true).open(path);
    }
}

fn log_event(command: &str, message: impl std::fmt::Display) {
    println!("Entering log_event...");
    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let line = format!("[{}][TAURI][{}] {}", timestamp, command, message);
    println!("{}", line);
    if let Some(path) = LOG_PATH.get() {
        if let Some(parent) = path.parent() {
            let _ = std::fs::create_dir_all(parent);
        }
        let lock = LOG_FILE_LOCK.get_or_init(|| Mutex::new(()));
        if let Ok(_guard) = lock.lock() {
            if let Ok(mut file) = OpenOptions::new().create(true).append(true).open(path) {
                let _ = writeln!(file, "{}", line);
            }
        }
    }
}

struct Session {
    #[allow(dead_code)]
    master_key: [u8; 32],
    authenticated_at: Instant,
}

impl Session {
    fn is_fresh(&self) -> bool {
        self.authenticated_at.elapsed() < SESSION_TIMEOUT
    }

    fn seconds_remaining(&self) -> u64 {
        let elapsed = self.authenticated_at.elapsed();
        SESSION_TIMEOUT
            .checked_sub(elapsed)
            .unwrap_or(Duration::ZERO)
            .as_secs()
    }
}

struct AppState {
    session: Mutex<Option<Session>>,
    context: Mutex<VaultContext>,
}

impl AppState {
    fn new() -> Self {
        Self {
            session: Mutex::new(None),
            context: Mutex::new(load_context_or_default()),
        }
    }

    fn current_context(&self) -> Result<VaultContext> {
        let guard = self
            .context
            .lock()
            .map_err(|_| anyhow!("CONTEXT_LOCK_FAILED"))?;
        Ok(guard.clone())
    }

    fn update_context(&self, context: VaultContext) -> Result<()> {
        persist_context(&context)?;
        {
            let mut guard = self
                .context
                .lock()
                .map_err(|_| anyhow!("CONTEXT_LOCK_FAILED"))?;
            *guard = context;
        }
        let mut session = self
            .session
            .lock()
            .map_err(|_| anyhow!("SESSION_LOCK_FAILED"))?;
        *session = None;
        Ok(())
    }
}

#[derive(Serialize)]
struct VaultStatus {
    initialized: bool,
    profile_exists: bool,
    profile: String,
    base_dir: String,
    profile_path: String,
    available_profiles: Vec<String>,
}

#[derive(Serialize)]
struct SyncUiStatus {
    last_revision: i64,
    last_uploaded_at: Option<String>,
    configured: bool,
}

#[derive(Serialize)]
struct SyncConfigSnapshot {
    client_id: Option<String>,
    client_secret: Option<String>,
    refresh_token_present: bool,
    folder_id: Option<String>,
}

#[derive(Serialize)]
struct SessionStatusPayload {
    authenticated: bool,
    seconds_remaining: u64,
}

fn resolve_paths(state: &tauri::State<AppState>) -> Result<VaultPaths> {
    resolve_paths_from_appstate(state.inner())
}

fn resolve_paths_from_appstate(state: &AppState) -> Result<VaultPaths> {
    let context = state.current_context()?;
    log_event(
        "resolve_paths",
        format!(
            "Base directory {:?}, profile {}",
            context.base_dir, context.profile
        ),
    );
    Ok(VaultPaths::new(&context.base_dir, &context.profile))
}

fn complete_sync_oauth(state: &AppState, state_token: &str, auth_code: &str) -> Result<(), String> {
    let paths = resolve_paths_from_appstate(state).map_err(|e| e.to_string())?;
    let service = SyncService::new(&paths);
    service
        .complete_oauth_flow(state_token, auth_code)
        .map_err(|e| e.to_string())
}

struct LoopbackResult {
    success: bool,
    message: String,
}

fn spawn_loopback_listener(
    listener: TcpListener,
    expected_state: String,
    app_handle: tauri::AppHandle,
) {
    thread::spawn(move || {
        let result = wait_for_loopback_redirect(listener, expected_state, app_handle.clone());
        emit_oauth_event(&app_handle, result.success, &result.message);
    });
}

fn wait_for_loopback_redirect(
    listener: TcpListener,
    expected_state: String,
    app_handle: tauri::AppHandle,
) -> LoopbackResult {
    if let Err(err) = listener.set_nonblocking(true) {
        return LoopbackResult {
            success: false,
            message: format!("Failed to prepare loopback listener: {}", err),
        };
    }
    let deadline = Instant::now() + OAUTH_LOOPBACK_TIMEOUT;
    loop {
        if Instant::now() >= deadline {
            return LoopbackResult {
                success: false,
                message: "Google did not finish authorization in time. Start the sync flow again."
                    .into(),
            };
        }
        match listener.accept() {
            Ok((stream, _)) => match handle_loopback_stream(stream, &expected_state, &app_handle) {
                Some(result) => return result,
                None => continue,
            },
            Err(err) if err.kind() == std::io::ErrorKind::WouldBlock => {
                thread::sleep(Duration::from_millis(200));
            }
            Err(err) => {
                return LoopbackResult {
                    success: false,
                    message: format!("Loopback listener failed: {}", err),
                };
            }
        }
    }
}

fn handle_loopback_stream(
    mut stream: TcpStream,
    expected_state: &str,
    app_handle: &tauri::AppHandle,
) -> Option<LoopbackResult> {
    let mut reader = match stream.try_clone() {
        Ok(clone) => BufReader::new(clone),
        Err(err) => {
            return Some(LoopbackResult {
                success: false,
                message: format!("Unable to inspect redirect request: {}", err),
            })
        }
    };
    let mut request_line = String::new();
    if reader.read_line(&mut request_line).is_err() {
        return Some(LoopbackResult {
            success: false,
            message: "Malformed HTTP request from browser".into(),
        });
    }
    let mut parts = request_line.split_whitespace();
    let method = parts.next().unwrap_or("");
    let target = parts.next().unwrap_or("/");
    if method.to_ascii_uppercase() != "GET" {
        let _ = respond_loopback_html(
            &mut stream,
            "405 Method Not Allowed",
            "FerrumVault expected a GET request from Google.",
        );
        return Some(LoopbackResult {
            success: false,
            message: "OAuth redirect used an unexpected HTTP verb.".into(),
        });
    }
    let url = format!("http://localhost{}", target);
    let parsed = match Url::parse(&url) {
        Ok(u) => u,
        Err(err) => {
            let _ = respond_loopback_html(
                &mut stream,
                "400 Bad Request",
                "FerrumVault could not parse the OAuth redirect URL.",
            );
            return Some(LoopbackResult {
                success: false,
                message: format!("Invalid redirect URL: {}", err),
            });
        }
    };
    if parsed.path() == "/favicon.ico" {
        let _ = respond_loopback_html(&mut stream, "204 No Content", "");
        return None;
    }
    if parsed.path() != "/" && parsed.path() != OAUTH_LOOPBACK_PATH {
        let _ = respond_loopback_html(
            &mut stream,
            "404 Not Found",
            "FerrumVault is waiting for Google's redirect...",
        );
        return None;
    }
    let mut code = None;
    let mut state = None;
    let mut error = None;
    let mut error_description = None;
    for (key, value) in parsed.query_pairs() {
        match key.as_ref() {
            "code" => code = Some(value.into_owned()),
            "state" => state = Some(value.into_owned()),
            "error" => error = Some(value.into_owned()),
            "error_description" => error_description = Some(value.into_owned()),
            _ => {}
        }
    }
    if let Some(err_code) = error {
        let mut message = format!("{}", err_code);
        if let Some(desc) = error_description {
            if !desc.is_empty() {
                message = format!("{}: {}", err_code, desc);
            }
        }
        let _ = respond_loopback_html(
            &mut stream,
            "400 Bad Request",
            &format!(
                "Google reported an error during authorization: {}",
                html_escape(&message)
            ),
        );
        return Some(LoopbackResult {
            success: false,
            message,
        });
    }
    let Some(state_value) = state else {
        let details = "Missing state parameter in OAuth redirect.".to_string();
        let _ = respond_loopback_html(&mut stream, "400 Bad Request", &details);
        return Some(LoopbackResult {
            success: false,
            message: details,
        });
    };
    if state_value != expected_state {
        let details =
            "FerrumVault rejected the redirect because the state token did not match. Start over."
                .to_string();
        let _ = respond_loopback_html(&mut stream, "400 Bad Request", &details);
        return Some(LoopbackResult {
            success: false,
            message: details,
        });
    }
    let Some(code) = code else {
        let details = "Google did not include an authorization code.".to_string();
        let _ = respond_loopback_html(&mut stream, "400 Bad Request", &details);
        return Some(LoopbackResult {
            success: false,
            message: details,
        });
    };
    let result = {
        let guard = app_handle.state::<AppState>();
        complete_sync_oauth(guard.inner(), &state_value, &code)
    };
    match result {
        Ok(()) => {
            let message = "Google Drive sync is ready. You may close this tab.".to_string();
            let _ = respond_loopback_html(&mut stream, "200 OK", &message);
            Some(LoopbackResult {
                success: true,
                message,
            })
        }
        Err(err) => {
            let _ = respond_loopback_html(
                &mut stream,
                "500 Internal Server Error",
                &format!(
                    "FerrumVault could not store the refresh token: {}",
                    html_escape(&err)
                ),
            );
            Some(LoopbackResult {
                success: false,
                message: err,
            })
        }
    }
}

fn respond_loopback_html(
    stream: &mut TcpStream,
    status_line: &str,
    body_message: &str,
) -> std::io::Result<()> {
    let body = if body_message.is_empty() {
        String::new()
    } else {
        format!(
            "<!DOCTYPE html><html lang=\"en\"><head><meta charset=\"utf-8\"><title>FerrumVault</title></head><body><h1>FerrumVault</h1><p>{}</p></body></html>",
            body_message
        )
    };
    if body.is_empty() {
        write!(
            stream,
            "HTTP/1.1 {}\r\nConnection: close\r\nContent-Length: 0\r\n\r\n",
            status_line
        )
    } else {
        write!(
            stream,
            "HTTP/1.1 {}\r\nContent-Type: text/html; charset=utf-8\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
            status_line,
            body.as_bytes().len(),
            body
        )
    }?;
    stream.flush()
}

fn html_escape(input: &str) -> String {
    input
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
}

fn emit_oauth_event(app: &tauri::AppHandle, success: bool, message: &str) {
    let payload = json!({
        "success": success,
        "message": message,
    });
    if let Err(err) = app.emit_all(OAUTH_DEEP_LINK_EVENT, payload) {
        eprintln!("Failed to emit OAuth event: {}", err);
    }
}

fn build_vault_status(context: &VaultContext) -> Result<VaultStatus> {
    let paths = VaultPaths::new(&context.base_dir, &context.profile);
    let profile_exists = paths.master_db.exists();
    let initialized = if profile_exists {
        vault_initialized(&paths)?
    } else {
        false
    };
    let available_profiles = discover_profiles(&context.base_dir);
    Ok(VaultStatus {
        initialized,
        profile_exists,
        profile: context.profile.clone(),
        base_dir: context.base_dir.display().to_string(),
        profile_path: paths.profile_root.display().to_string(),
        available_profiles,
    })
}

fn discover_profiles(base_dir: &Path) -> Vec<String> {
    let mut profiles = Vec::new();
    if let Ok(entries) = fs::read_dir(base_dir) {
        for entry in entries.flatten() {
            let path = entry.path();
            if !path.is_dir() {
                continue;
            }
            let Ok(name) = entry.file_name().into_string() else {
                continue;
            };
            if path.join("vault_master.db").exists() {
                profiles.push(name);
            }
        }
    }
    profiles.sort();
    profiles
}

#[tauri::command]
fn vault_status(state: tauri::State<AppState>) -> Result<VaultStatus, String> {
    println!("[DEBUG] vault_status command invoked");
    log_event("vault_status", "Checking vault status");
    let context = state.current_context().map_err(|e| e.to_string())?;
    build_vault_status(&context).map_err(|e| e.to_string())
}

#[tauri::command]
fn update_vault_context(
    state: tauri::State<AppState>,
    profile: Option<String>,
    base_dir: Option<String>,
) -> Result<VaultStatus, String> {
    println!("[DEBUG] update_vault_context command invoked");
    let mut context = state.current_context().map_err(|e| e.to_string())?;
    if let Some(name) = profile {
        let trimmed = name.trim();
        if trimmed.is_empty() {
            return Err("PROFILE_REQUIRED".into());
        }
        context.profile = trimmed.to_string();
    }
    if let Some(dir) = base_dir {
        let normalized = normalize_base_dir_input(&dir).map_err(|e| e.to_string())?;
        context.base_dir = normalized;
    }
    state.update_context(context).map_err(|e| e.to_string())?;
    let updated = state.current_context().map_err(|e| e.to_string())?;
    build_vault_status(&updated).map_err(|e| e.to_string())
}

#[tauri::command]
fn reset_vault_context(state: tauri::State<AppState>) -> Result<VaultStatus, String> {
    println!("[DEBUG] reset_vault_context command invoked");
    let context = default_context();
    state.update_context(context).map_err(|e| e.to_string())?;
    let updated = state.current_context().map_err(|e| e.to_string())?;
    build_vault_status(&updated).map_err(|e| e.to_string())
}

fn ensure_authenticated(state: &tauri::State<AppState>) -> Result<(), String> {
    println!("[DEBUG] ensure_authenticated called");
    log_event("ensure_authenticated", "Validating session freshness");
    let mut guard = state
        .session
        .lock()
        .map_err(|_| "SESSION_LOCK_FAILED".to_string())?;
    match guard.as_mut() {
        Some(session) if session.is_fresh() => {
            log_event("ensure_authenticated", "Session valid");
            Ok(())
        }
        _ => {
            log_event(
                "ensure_authenticated",
                "No valid session; rejecting request",
            );
            *guard = None;
            Err("NOT_AUTHENTICATED".into())
        }
    }
}

fn session_master_key(state: &tauri::State<AppState>) -> Result<[u8; 32], String> {
    println!("[DEBUG] session_master_key requested");
    let mut guard = state
        .session
        .lock()
        .map_err(|_| "SESSION_LOCK_FAILED".to_string())?;
    match guard.as_mut() {
        Some(session) if session.is_fresh() => {
            log_event("session_master_key", "Providing master key copy");
            Ok(session.master_key)
        }
        _ => {
            log_event("session_master_key", "Session missing or expired");
            *guard = None;
            Err("NOT_AUTHENTICATED".into())
        }
    }
}

fn check_session_inner(state: &AppState) -> Result<bool, String> {
    println!("[DEBUG] check_session command invoked");
    log_event("check_session", "Checking session state");
    let mut guard = state
        .session
        .lock()
        .map_err(|_| "SESSION_LOCK_FAILED".to_string())?;
    let fresh = match guard.as_mut() {
        Some(session) if session.is_fresh() => true,
        Some(_) => {
            *guard = None;
            false
        }
        None => false,
    };
    log_event("check_session", format!("Session fresh: {}", fresh));
    Ok(fresh)
}

#[tauri::command]
fn check_session(state: tauri::State<AppState>) -> Result<bool, String> {
    check_session_inner(state.inner())
}

#[tauri::command]
fn session_status_detail(state: tauri::State<AppState>) -> Result<SessionStatusPayload, String> {
    println!("[DEBUG] session_status_detail command invoked");
    let mut guard = state
        .session
        .lock()
        .map_err(|_| "SESSION_LOCK_FAILED".to_string())?;
    match guard.as_ref() {
        Some(session) if session.is_fresh() => Ok(SessionStatusPayload {
            authenticated: true,
            seconds_remaining: session.seconds_remaining(),
        }),
        Some(_) => {
            *guard = None;
            Ok(SessionStatusPayload {
                authenticated: false,
                seconds_remaining: 0,
            })
        }
        None => Ok(SessionStatusPayload {
            authenticated: false,
            seconds_remaining: 0,
        }),
    }
}

#[tauri::command]
fn login(state: tauri::State<AppState>, password: String) -> Result<(), String> {
    println!("[DEBUG] login command invoked");
    log_event("login", "Received password input");
    let paths = resolve_paths(&state).map_err(|e| e.to_string())?;
    if !vault_initialized(&paths).map_err(|e| e.to_string())? {
        log_event("login", "Vault not initialized; returning NEEDS_SETUP");
        return Err("NEEDS_SETUP".into());
    }
    let master_key = derive_master_key_for_profile(&paths, &password, PBKDF2_DEFAULT_ITERS)
        .map_err(|e| e.to_string())?;
    log_event("login", "Master key derived successfully");
    let mut guard = state
        .session
        .lock()
        .map_err(|_| "SESSION_LOCK_FAILED".to_string())?;
    *guard = Some(Session {
        master_key,
        authenticated_at: Instant::now(),
    });
    log_event("login", "Session established");
    Ok(())
}

#[tauri::command]
fn logout(state: tauri::State<AppState>) -> Result<(), String> {
    println!("[DEBUG] logout command invoked");
    log_event("logout", "Clearing session");
    let mut guard = state
        .session
        .lock()
        .map_err(|_| "SESSION_LOCK_FAILED".to_string())?;
    *guard = None;
    log_event("logout", "Session cleared");
    Ok(())
}

#[tauri::command]
fn load_snapshot(
    state: tauri::State<AppState>,
    folder: Option<String>,
    tag: Option<String>,
    search: Option<String>,
) -> Result<UiSnapshot, String> {
    println!("[DEBUG] load_snapshot command invoked");
    log_event(
        "load_snapshot",
        format!(
            "Requested snapshot with folder={:?}, tag={:?}, search={:?}",
            folder, tag, search
        ),
    );
    ensure_authenticated(&state)?;
    let paths = resolve_paths(&state).map_err(|e| e.to_string())?;
    initialize_vault(&paths).map_err(|e| e.to_string())?;
    let opts = UiOptions {
        folder,
        tag,
        search,
    };
    let snapshot = gather_snapshot(&paths, opts).map_err(|e| e.to_string())?;
    log_event(
        "load_snapshot",
        format!(
            "Loaded snapshot: {} folders, {} tags, {} credentials",
            snapshot.folders.len(),
            snapshot.tags.len(),
            snapshot.credentials.len()
        ),
    );
    Ok(snapshot)
}

#[tauri::command]
#[allow(non_snake_case)]
fn load_credential_detail(
    state: tauri::State<AppState>,
    credId: i64,
) -> Result<CredentialDetail, String> {
    println!("[DEBUG] load_credential_detail command invoked");
    log_event(
        "load_credential_detail",
        format!("Loading credential id {}", credId),
    );
    ensure_authenticated(&state)?;
    let paths = resolve_paths(&state).map_err(|e| e.to_string())?;
    initialize_vault(&paths).map_err(|e| e.to_string())?;
    let detail = load_detail_with_relations(&paths, credId).map_err(|e| e.to_string())?;
    log_event(
        "load_credential_detail",
        format!("Loaded credential {} ({})", credId, detail.app_name),
    );
    Ok(detail)
}

#[tauri::command]
fn create_credential_detail(
    state: tauri::State<AppState>,
    payload: CreateCredentialInput,
) -> Result<CredentialDetail, String> {
    println!("[DEBUG] create_credential_detail command invoked");
    let master_key = session_master_key(&state)?;
    let paths = resolve_paths(&state).map_err(|e| e.to_string())?;
    create_credential(&paths, payload, master_key).map_err(|e| e.to_string())
}

#[tauri::command]
fn reveal_password(state: tauri::State<AppState>, cred_id: i64) -> Result<String, String> {
    println!("[DEBUG] reveal_password command invoked");
    log_event(
        "reveal_password",
        format!("Attempting to reveal credential {}", cred_id),
    );
    let master_key = session_master_key(&state)?;
    let paths = resolve_paths(&state).map_err(|e| e.to_string())?;
    let mut engine =
        VaultEngine::resume_with_master_key(&paths, master_key).map_err(|e| e.to_string())?;
    let password = engine.fetch_plaintext(cred_id).map_err(|e| e.to_string())?;
    log_event("reveal_password", "Password decrypted successfully");
    Ok(password)
}

#[tauri::command]
fn setup_password(
    state: tauri::State<AppState>,
    password: String,
    confirm: String,
) -> Result<(), String> {
    println!("[DEBUG] setup_password command invoked");
    log_event("setup_password", "Received password inputs");
    if password.is_empty() {
        log_event("setup_password", "Password missing");
        return Err("PASSWORD_REQUIRED".into());
    }
    if password != confirm {
        log_event("setup_password", "Password mismatch");
        return Err("PASSWORD_MISMATCH".into());
    }
    let paths = resolve_paths(&state).map_err(|e| e.to_string())?;
    if vault_initialized(&paths).map_err(|e| e.to_string())? {
        log_event("setup_password", "Vault already initialized");
        return Err("ALREADY_INITIALIZED".into());
    }
    initialize_vault(&paths).map_err(|e| e.to_string())?;
    let master_key = derive_master_key_for_profile(&paths, &password, PBKDF2_DEFAULT_ITERS)
        .map_err(|e| e.to_string())?;
    log_event("setup_password", "Master key derived; creating session");
    let mut guard = state
        .session
        .lock()
        .map_err(|_| "SESSION_LOCK_FAILED".to_string())?;
    *guard = Some(Session {
        master_key,
        authenticated_at: Instant::now(),
    });
    log_event("setup_password", "Session established and password stored");
    Ok(())
}

#[tauri::command]
fn change_password(
    state: tauri::State<AppState>,
    current_password: String,
    new_password: String,
    confirm_password: String,
) -> Result<(), String> {
    println!("[DEBUG] change_password command invoked");
    log_event("change_password", "Initiating password rotation");
    ensure_authenticated(&state)?;
    if current_password.is_empty() {
        return Err("PASSWORD_REQUIRED".into());
    }
    if new_password.is_empty() {
        return Err("PASSWORD_REQUIRED".into());
    }
    if new_password != confirm_password {
        return Err("PASSWORD_MISMATCH".into());
    }
    if new_password.len() < MIN_SECRET_LEN {
        return Err("PASSWORD_TOO_SHORT".into());
    }
    let paths = resolve_paths(&state).map_err(|e| e.to_string())?;
    let master_key = change_master_password(
        &paths,
        &current_password,
        &new_password,
        PBKDF2_DEFAULT_ITERS,
    )
    .map_err(|e| e.to_string())?;
    let mut guard = state
        .session
        .lock()
        .map_err(|_| "SESSION_LOCK_FAILED".to_string())?;
    *guard = Some(Session {
        master_key,
        authenticated_at: Instant::now(),
    });
    log_event("change_password", "Master password rotated successfully");
    Ok(())
}

#[tauri::command]
fn update_credential_detail(
    state: tauri::State<AppState>,
    mut payload: UpdateCredentialInput,
) -> Result<CredentialDetail, String> {
    println!("[DEBUG] update_credential_detail command invoked");
    let cred_id = payload.cred_id;
    let password_update = payload.password.take();
    let mut password_reason = payload.password_reason.take();
    log_event(
        "update_credential_detail",
        format!("Updating credential {}", cred_id),
    );
    ensure_authenticated(&state)?;
    let paths = resolve_paths(&state).map_err(|e| e.to_string())?;
    let updated = update_credential(&paths, payload).map_err(|e| e.to_string())?;
    if let Some(password) = password_update {
        let trimmed = password.trim().to_string();
        if trimmed.len() < credmanager_app::crypto::MIN_SECRET_LEN {
            return Err("PASSWORD_TOO_SHORT".into());
        }
        let master_key = session_master_key(&state)?;
        let mut engine =
            VaultEngine::resume_with_master_key(&paths, master_key).map_err(|e| e.to_string())?;
        let comment = password_reason
            .take()
            .and_then(|value| {
                let trimmed = value.trim().to_string();
                if trimmed.is_empty() {
                    None
                } else {
                    Some(trimmed)
                }
            })
            .unwrap_or_default();
        engine
            .update_password(cred_id, &trimmed, comment.as_str())
            .map_err(|e| e.to_string())?;
    }
    log_event(
        "update_credential_detail",
        format!("Credential {} updated", cred_id),
    );
    Ok(updated)
}

#[tauri::command]
fn configure_sync(
    state: tauri::State<AppState>,
    refresh_token: String,
    client_id: Option<String>,
    client_secret: Option<String>,
    redirect_uri: Option<String>,
) -> Result<(), String> {
    let paths = resolve_paths(&state).map_err(|e| e.to_string())?;
    let service = SyncService::new(&paths);
    service
        .configure(refresh_token, client_id, client_secret, redirect_uri)
        .map_err(|e| e.to_string())
}

#[tauri::command]
fn sync_upload_command(state: tauri::State<AppState>) -> Result<(), String> {
    ensure_authenticated(&state)?;
    let master_key = session_master_key(&state)?;
    let paths = resolve_paths(&state).map_err(|e| e.to_string())?;
    let device = DeviceInfo::current().map_err(|e| e.to_string())?;
    let service = SyncService::new(&paths);
    let mut creds = service.load_credentials().map_err(|e| e.to_string())?;
    let config = creds.require_client_config().map_err(|e| e.to_string())?;
    let mut drive = GoogleDriveClient::new(config).map_err(|e| e.to_string())?;
    service
        .upload_bundle(&master_key, &device, &mut drive, &mut creds)
        .map_err(|e| e.to_string())?;
    Ok(())
}

#[tauri::command]
fn sync_download_command(state: tauri::State<AppState>) -> Result<(), String> {
    ensure_authenticated(&state)?;
    let master_key = session_master_key(&state)?;
    let paths = resolve_paths(&state).map_err(|e| e.to_string())?;
    let service = SyncService::new(&paths);
    let mut creds = service.load_credentials().map_err(|e| e.to_string())?;
    let config = creds.require_client_config().map_err(|e| e.to_string())?;
    let mut drive = GoogleDriveClient::new(config).map_err(|e| e.to_string())?;
    service
        .download_latest(&master_key, &mut drive, &mut creds)
        .map_err(|e| e.to_string())?;
    Ok(())
}

#[tauri::command]
fn sync_download_specific_command(
    state: tauri::State<AppState>,
    file_id: String,
) -> Result<(), String> {
    ensure_authenticated(&state)?;
    let master_key = session_master_key(&state)?;
    let paths = resolve_paths(&state).map_err(|e| e.to_string())?;
    let service = SyncService::new(&paths);
    let mut creds = service.load_credentials().map_err(|e| e.to_string())?;
    let config = creds.require_client_config().map_err(|e| e.to_string())?;
    let mut drive = GoogleDriveClient::new(config).map_err(|e| e.to_string())?;
    service
        .download_by_id(&master_key, &mut drive, &mut creds, &file_id)
        .map_err(|e| e.to_string())?;
    Ok(())
}

#[tauri::command]
fn sync_status_command(state: tauri::State<AppState>) -> Result<SyncUiStatus, String> {
    let paths = resolve_paths(&state).map_err(|e| e.to_string())?;
    let service = SyncService::new(&paths);
    let status = service.status().map_err(|e| e.to_string())?;
    let creds = service.load_credentials().map_err(|e| e.to_string())?;
    Ok(SyncUiStatus {
        last_revision: status.last_revision,
        last_uploaded_at: status.last_uploaded_at_utc,
        configured: creds.refresh_token.is_some(),
    })
}

#[tauri::command]
fn sync_config_snapshot_command(
    state: tauri::State<AppState>,
) -> Result<SyncConfigSnapshot, String> {
    let paths = resolve_paths(&state).map_err(|e| e.to_string())?;
    let service = SyncService::new(&paths);
    let creds = service.load_credentials().map_err(|e| e.to_string())?;
    Ok(SyncConfigSnapshot {
        client_id: creds.client_id,
        client_secret: creds.client_secret,
        refresh_token_present: creds.refresh_token.is_some(),
        folder_id: creds.folder_id,
    })
}

#[tauri::command]
fn sync_preferences_command(state: tauri::State<AppState>) -> Result<SyncPreferences, String> {
    let paths = resolve_paths(&state).map_err(|e| e.to_string())?;
    let service = SyncService::new(&paths);
    service.load_preferences().map_err(|e| e.to_string())
}

#[tauri::command]
fn update_sync_preferences_command(
    state: tauri::State<AppState>,
    auto_upload_on_exit: bool,
    auto_download_on_new: bool,
    keep_revisions: i64,
) -> Result<(), String> {
    let paths = resolve_paths(&state).map_err(|e| e.to_string())?;
    let service = SyncService::new(&paths);
    let prefs = SyncPreferences {
        auto_upload_on_exit,
        auto_download_on_new,
        keep_revisions,
    };
    service
        .update_preferences(&prefs)
        .map_err(|e| e.to_string())
}

#[tauri::command]
fn list_drive_bundles_command(
    state: tauri::State<AppState>,
) -> Result<Vec<DriveBundleInfo>, String> {
    ensure_authenticated(&state)?;
    let paths = resolve_paths(&state).map_err(|e| e.to_string())?;
    let service = SyncService::new(&paths);
    let mut creds = service.load_credentials().map_err(|e| e.to_string())?;
    let config = creds.require_client_config().map_err(|e| e.to_string())?;
    let mut drive = GoogleDriveClient::new(config).map_err(|e| e.to_string())?;
    drive.list_bundles(&mut creds).map_err(|e| e.to_string())
}

#[tauri::command]
fn begin_sync_oauth_command(
    app: tauri::AppHandle,
    state: tauri::State<AppState>,
) -> Result<OauthBegin, String> {
    let listener = TcpListener::bind((LOOPBACK_HOST, 0))
        .map_err(|e| format!("Failed to bind local redirect port: {}", e))?;
    let port = listener
        .local_addr()
        .map_err(|e| format!("Unable to determine loopback port: {}", e))?
        .port();
    let redirect_uri = format!(
        "http://{}:{}{}",
        LOOPBACK_REDIRECT_HOST, port, OAUTH_LOOPBACK_PATH
    );
    let paths = resolve_paths(&state).map_err(|e| e.to_string())?;
    let service = SyncService::new(&paths);
    let begin = service
        .begin_oauth_flow(Some(&redirect_uri))
        .map_err(|e| e.to_string())?;
    spawn_loopback_listener(listener, begin.state.clone(), app);
    Ok(begin)
}

#[tauri::command]
#[allow(non_snake_case)]
fn complete_sync_oauth_command(
    state: tauri::State<AppState>,
    stateToken: String,
    authCode: String,
) -> Result<(), String> {
    complete_sync_oauth(state.inner(), &stateToken, &authCode)
}

#[tauri::command]
#[allow(non_snake_case)]
fn list_password_history(
    state: tauri::State<AppState>,
    credId: i64,
) -> Result<Vec<PasswordHistoryMeta>, String> {
    ensure_authenticated(&state)?;
    let master_key = session_master_key(&state)?;
    let paths = resolve_paths(&state).map_err(|e| e.to_string())?;
    let engine =
        VaultEngine::resume_with_master_key(&paths, master_key).map_err(|e| e.to_string())?;
    engine
        .list_history_metadata(credId)
        .map_err(|e| e.to_string())
}

#[tauri::command]
#[allow(non_snake_case)]
fn reveal_password_history_entry(
    state: tauri::State<AppState>,
    historyId: i64,
) -> Result<String, String> {
    ensure_authenticated(&state)?;
    let master_key = session_master_key(&state)?;
    let paths = resolve_paths(&state).map_err(|e| e.to_string())?;
    let engine =
        VaultEngine::resume_with_master_key(&paths, master_key).map_err(|e| e.to_string())?;
    engine
        .reveal_history_entry(historyId)
        .map_err(|e| e.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        sync::Mutex,
        time::{Duration, Instant, SystemTime, UNIX_EPOCH},
    };

    fn temp_context() -> VaultContext {
        let mut base_dir = std::env::temp_dir();
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos();
        base_dir.push(format!("credmanager-tauri-session-{}", nanos));
        VaultContext {
            base_dir,
            profile: "test".into(),
        }
    }

    fn state_with_session(age: Duration) -> AppState {
        AppState {
            session: Mutex::new(Some(Session {
                master_key: [0u8; 32],
                authenticated_at: Instant::now() - age,
            })),
            context: Mutex::new(temp_context()),
        }
    }

    #[test]
    fn expired_sessions_are_cleared() {
        let state = state_with_session(SESSION_TIMEOUT + Duration::from_secs(1));
        assert!(!check_session_inner(&state).unwrap());
        assert!(state.session.lock().unwrap().is_none());
    }

    #[test]
    fn check_session_does_not_refresh_timestamp() {
        let state = state_with_session(Duration::from_secs(30));
        let before = {
            let guard = state.session.lock().unwrap();
            guard.as_ref().unwrap().authenticated_at
        };
        assert!(check_session_inner(&state).unwrap());
        let after = {
            let guard = state.session.lock().unwrap();
            guard.as_ref().unwrap().authenticated_at
        };
        assert_eq!(before, after);
        {
            let mut guard = state.session.lock().unwrap();
            if let Some(session) = guard.as_mut() {
                session.authenticated_at = Instant::now() - (SESSION_TIMEOUT + Duration::from_secs(1));
            }
        }
        assert!(!check_session_inner(&state).unwrap());
    }
}

fn main() {
    initialize_logging();
    tauri::Builder::default()
        .manage(AppState::new())
        .invoke_handler(tauri::generate_handler![
            vault_status,
            update_vault_context,
            reset_vault_context,
            check_session,
            session_status_detail,
            login,
            logout,
            setup_password,
            change_password,
            load_snapshot,
            load_credential_detail,
            create_credential_detail,
            reveal_password,
            update_credential_detail,
            configure_sync,
            sync_upload_command,
            sync_download_command,
            sync_download_specific_command,
            sync_status_command,
            sync_config_snapshot_command,
            sync_preferences_command,
            update_sync_preferences_command,
            list_drive_bundles_command,
            begin_sync_oauth_command,
            complete_sync_oauth_command,
            list_password_history,
            reveal_password_history_entry
        ])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
