use std::path::PathBuf;

use anyhow::{Context, Result, anyhow, ensure};
use clap::{Parser, Subcommand};
use credmanager_app::{
    crypto::PBKDF2_DEFAULT_ITERS,
    db::{VaultPaths, initialize_vault},
    default_base_dir,
    sync::{DeviceInfo, GoogleDriveClient, SyncService},
    ui::{UiOptions, run_ui},
    vault::{derive_master_key_for_profile, run_harness},
};
use rpassword::prompt_password;

#[derive(Parser, Debug)]
#[command(author, version, about = "FerrumVault CLI", long_about = None)]
struct Cli {
    /// Profile label to distinguish multiple vaults.
    #[arg(long, default_value = "default")]
    profile: String,

    /// Override the base directory used for vault storage.
    #[arg(long)]
    base_dir: Option<PathBuf>,

    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand, Debug)]
enum Commands {
    /// Initialize the SQLite vault schema.
    Init,
    /// Run the automated storage/retrieval harness.
    Harness {
        #[arg(long, default_value_t = 500)]
        total: usize,
        /// Override the profile used for harness runs.
        #[arg(long)]
        profile: Option<String>,
        /// Override the base directory just for harness runs.
        #[arg(long)]
        base_dir: Option<PathBuf>,
        /// Non-interactive password for harness runs (also reads CREDMANAGER_HARNESS_PASSWORD).
        #[arg(long, env = "CREDMANAGER_HARNESS_PASSWORD")]
        password: Option<String>,
    },
    /// Render the experimental CLI UI preview.
    Ui {
        #[arg(long)]
        folder: Option<String>,
        #[arg(long)]
        tag: Option<String>,
        #[arg(long)]
        search: Option<String>,
    },
    /// Manage Google Drive sync bundles.
    Sync {
        #[command(subcommand)]
        action: SyncCommands,
    },
}

#[derive(Subcommand, Debug)]
enum SyncCommands {
    Upload {
        #[arg(long)]
        profile: Option<String>,
        #[arg(long)]
        base_dir: Option<PathBuf>,
        #[arg(long, env = "CREDMANAGER_SYNC_PASSWORD")]
        password: Option<String>,
    },
    Download {
        #[arg(long)]
        profile: Option<String>,
        #[arg(long)]
        base_dir: Option<PathBuf>,
        #[arg(long, env = "CREDMANAGER_SYNC_PASSWORD")]
        password: Option<String>,
    },
    Status {
        #[arg(long)]
        profile: Option<String>,
        #[arg(long)]
        base_dir: Option<PathBuf>,
    },
    Configure {
        #[arg(long)]
        profile: Option<String>,
        #[arg(long)]
        base_dir: Option<PathBuf>,
        #[arg(long)]
        refresh_token: String,
        #[arg(long)]
        client_id: Option<String>,
        #[arg(long)]
        client_secret: Option<String>,
        #[arg(long)]
        redirect_uri: Option<String>,
    },
    BeginOauth {
        #[arg(long)]
        profile: Option<String>,
        #[arg(long)]
        base_dir: Option<PathBuf>,
    },
    CompleteOauth {
        #[arg(long)]
        profile: Option<String>,
        #[arg(long)]
        base_dir: Option<PathBuf>,
        #[arg(long)]
        state: String,
        #[arg(long)]
        code: String,
    },
}

fn main() -> Result<()> {
    let Cli {
        profile,
        base_dir,
        command,
    } = Cli::parse();

    match command {
        Commands::Init => {
            let paths = resolve_paths(base_dir.clone(), None, &profile)?;
            initialize_vault(&paths)?;
            println!("Initialized vault at {:?}", paths.profile_root);
        }
        Commands::Harness {
            total,
            profile: harness_profile,
            base_dir: harness_base,
            password: harness_password,
        } => {
            let profile = harness_profile.unwrap_or_else(|| profile.clone());
            let paths = resolve_paths(harness_base, base_dir.clone(), &profile)?;
            let harness_paths = reset_profile(paths)?;
            let password = match harness_password {
                Some(pw) => {
                    ensure!(!pw.is_empty(), "harness password cannot be empty");
                    pw
                }
                None => prompt_new_password()?,
            };
            run_harness(&harness_paths, &password, total)?;
        }
        Commands::Ui {
            folder,
            tag,
            search,
        } => {
            let paths = resolve_paths(base_dir.clone(), None, &profile)?;
            let needs_setup = !paths.master_db.exists();
            let password = if needs_setup {
                prompt_new_password()?
            } else {
                prompt_existing_password()?
            };
            initialize_vault(&paths)?;
            derive_master_key_for_profile(&paths, &password, PBKDF2_DEFAULT_ITERS)?;
            let options = UiOptions {
                folder,
                tag,
                search,
            };
            run_ui(&paths, options)?;
        }
        Commands::Sync { action } => match action {
            SyncCommands::Upload {
                profile: sync_profile,
                base_dir: sync_base,
                password,
            } => {
                let profile = sync_profile.unwrap_or_else(|| profile.clone());
                let paths = resolve_paths(sync_base, base_dir.clone(), &profile)?;
                let password = resolve_password_or_prompt(
                    password,
                    prompt_existing_password,
                    "sync password cannot be empty",
                )?;
                let master_key =
                    derive_master_key_for_profile(&paths, &password, PBKDF2_DEFAULT_ITERS)?;
                let device = DeviceInfo::current()?;
                let service = SyncService::new(&paths);
                let mut creds = service.load_credentials()?;
                let config = creds.require_client_config()?;
                let mut drive = GoogleDriveClient::new(config)?;
                let manifest =
                    service.upload_bundle(&master_key, &device, &mut drive, &mut creds)?;
                println!(
                    "Uploaded encrypted bundle {} (revision {}) from {}.",
                    manifest.bundle_id, manifest.revision, manifest.device_label
                );
            }
            SyncCommands::Download {
                profile: sync_profile,
                base_dir: sync_base,
                password,
            } => {
                let profile = sync_profile.unwrap_or_else(|| profile.clone());
                let paths = resolve_paths(sync_base, base_dir.clone(), &profile)?;
                let password = resolve_password_or_prompt(
                    password,
                    prompt_existing_password,
                    "sync password cannot be empty",
                )?;
                let master_key =
                    derive_master_key_for_profile(&paths, &password, PBKDF2_DEFAULT_ITERS)?;
                let service = SyncService::new(&paths);
                let mut creds = service.load_credentials()?;
                let config = creds.require_client_config()?;
                let mut drive = GoogleDriveClient::new(config)?;
                let manifest = service.download_latest(&master_key, &mut drive, &mut creds)?;
                println!(
                    "Restored bundle {} (revision {}) created at {}",
                    manifest.bundle_id, manifest.revision, manifest.created_at_utc
                );
            }
            SyncCommands::Status {
                profile: sync_profile,
                base_dir: sync_base,
            } => {
                let profile = sync_profile.unwrap_or_else(|| profile.clone());
                let paths = resolve_paths(sync_base, base_dir.clone(), &profile)?;
                let service = SyncService::new(&paths);
                let status = service.status()?;
                println!(
                    "Sync status -> last_revision: {}, last_bundle_id: {}, last_uploaded_at: {}",
                    status.last_revision,
                    status
                        .last_bundle_id
                        .as_deref()
                        .unwrap_or("<never uploaded>"),
                    status
                        .last_uploaded_at_utc
                        .as_deref()
                        .unwrap_or("<never uploaded>")
                );
            }
            SyncCommands::Configure {
                profile: sync_profile,
                base_dir: sync_base,
                refresh_token,
                client_id,
                client_secret,
                redirect_uri,
            } => {
                let profile = sync_profile.unwrap_or_else(|| profile.clone());
                let paths = resolve_paths(sync_base, base_dir.clone(), &profile)?;
                let service = SyncService::new(&paths);
                service.configure(refresh_token, client_id, client_secret, redirect_uri)?;
                println!(
                    "Stored Google Drive refresh token (client credentials use built-in defaults unless overridden)."
                );
            }
            SyncCommands::BeginOauth {
                profile: sync_profile,
                base_dir: sync_base,
            } => {
                let profile = sync_profile.unwrap_or_else(|| profile.clone());
                let paths = resolve_paths(sync_base, base_dir.clone(), &profile)?;
                let service = SyncService::new(&paths);
                let begin = service.begin_oauth_flow(None)?;
                println!("Open the following URL in a browser:\n{}", begin.auth_url);
                println!("State token: {}", begin.state);
            }
            SyncCommands::CompleteOauth {
                profile: sync_profile,
                base_dir: sync_base,
                state,
                code,
            } => {
                let profile = sync_profile.unwrap_or_else(|| profile.clone());
                let paths = resolve_paths(sync_base, base_dir.clone(), &profile)?;
                let service = SyncService::new(&paths);
                service.complete_oauth_flow(&state, &code)?;
                println!("OAuth flow completed; refresh token stored.");
            }
        },
    }

    Ok(())
}

fn resolve_paths(
    primary: Option<PathBuf>,
    fallback: Option<PathBuf>,
    profile: &str,
) -> Result<VaultPaths> {
    let base_dir = if let Some(dir) = primary {
        dir
    } else if let Some(dir) = fallback {
        dir
    } else {
        default_base_dir()?
    };
    Ok(VaultPaths::new(&base_dir, profile))
}

fn reset_profile(paths: VaultPaths) -> Result<VaultPaths> {
    if paths.profile_root.exists() {
        std::fs::remove_dir_all(&paths.profile_root)
            .with_context(|| format!("Clearing existing profile at {:?}", paths.profile_root))?;
    }
    Ok(paths)
}

fn prompt_existing_password() -> Result<String> {
    let password = prompt_password("Enter master password: ").context("reading password")?;
    ensure!(!password.is_empty(), "password cannot be empty");
    Ok(password)
}

fn prompt_new_password() -> Result<String> {
    let password = prompt_password("Create master password: ").context("reading password")?;
    ensure!(!password.is_empty(), "password cannot be empty");
    let confirm = prompt_password("Confirm master password: ").context("reading confirmation")?;
    ensure!(password == confirm, "passwords do not match");
    Ok(password)
}

fn resolve_password_or_prompt(
    provided: Option<String>,
    prompt_fn: fn() -> Result<String>,
    empty_msg: &str,
) -> Result<String> {
    match provided {
        Some(pw) => {
            if pw.is_empty() {
                return Err(anyhow!(empty_msg.to_string()));
            }
            Ok(pw)
        }
        None => prompt_fn(),
    }
}
