use std::{collections::HashMap, fs};

use crate::crypto::{
    CipherBlob, SplitSecret, decode_joined_shards, derive_master_key, encrypt_with_key,
    split_into_shards,
};
use crate::db::{VaultPaths, initialize_vault, open_connection};
use anyhow::{Result, anyhow, ensure};
#[cfg(debug_assertions)]
use base64::{Engine as _, engine::general_purpose::STANDARD};
use chrono::Utc;
use rand::{Rng, RngCore, rngs::OsRng, seq::SliceRandom};
use rusqlite::{Connection, OptionalExtension, Row, params};
use serde::Serialize;
use serde_json::json;

const VERIFIER_MAGIC: &[u8] = b"CREDMGR_VERIFIER_V1";
const SESSION_ITERATIONS: u32 = 10_000;
const STACY_BANK_PIN: &str = "3481";
const SLUSHINGFOXES_TOKEN_FRAGMENT: &str = "eyJ4NXQjUzI1NiI6ImJxTmcwT3cxQ1JvZmM3cFE3b1AzVkhFaG1xVllrUGUyc05uSGpkRTlFVm8iLCJ4NXQiOiJjRVJyN29CVUJpc0h6dnpNSk9jdUNVbXJZV1EiLCJraWQiOiJTSUdOSU5HX0tFWSIsImFsZyI6IlJTMjU2In0.eyJjbGllbnRfb2NpZCI6Im9jaWQxLmRvbWFpbmFwcC5vYzEuaWFkLmFtYWFhYWFhbHBvcmFhcWE0ZTNuM3UzbzI3Y2VxMnZvZ2VlZDNiaWU2cXFsZzRhdjdkaGNpenlvM3R2cSIsInVzZXJfdHoiOiJBbWVyaWNhXC9DaGljYWdvIiwic3ViIjoibXBlZGRvanUiLCJ1c2VyX2xvY2FsZSI6ImVuIiwic2lkbGUiOjQ4MCwiaWRwX25hbWUiOiJVc2VyTmFtZVBhc3N3b3JkIiwidXNlci50ZW5hbnQubmFtZSI6ImlkY3MtZWM2MWE1MjJhMTQ2NDE2Njk1MDM4ZDFlMDdhMDVmMTgiLCJpZHBfZ3VpZCI6IlVzZXJOYW1lUGFzc3dvcmQiLCJhbXIiOlsiVVNFUk5BTUVfUEFTU1dPUkQiXSwiaXNzIjoiaHR0cHM6XC9cL2lkZW50aXR5Lm9yYWNsZWNsb3VkLmNvbVwvIiwiZG9tYWluX2hvbWUiOiJ1cy1hc2hidXJuLTEiLCJjYV9vY2lkIjoib2NpZDEudGVuYW5jeS5vYzEuLmFhYWFhYWFhbGg2bmdzbDJocmN3NmJwcWc0ZGViMmoyd2Zzanduem1iNDZ1cmVoaW10bDV3cDVxbDM3YSIsInVzZXJfdGVuYW50bmFtZSI6ImlkY3MtZWM2MWE1MjJhMTQ2NDE2Njk1MDM4ZDFlMDdhMDVmMTgiLCJjbGllbnRfaWQiOiI3MGIzYjQ1Y2QxMDY0NDIzYmE4YTg2M2YxMWNkMTg0ZSIsInNpZCI6IjcwYjI4ZGU2ZTM3NzQyNDI5ZGE5YjViZmRjOGMwZDllOmFmNWJlYyIsImRvbWFpbl9pZCI6Im9jaWQxLmRvbWFpbi5vYzEuLmFhYWFhYWFhcmd5emxiem1tYjN4dG1ibmlvZWc1NjJnNTZudnpxbW00NDd3a3RuN2F3d2t0ZHozbWx4cSIsInN1Yl90eXBlIjoidXNlciIsInNjb3BlIjoiZmVlZGJhY2sgcXVlcnkiLCJ1c2VyX29jaWQiOiJvY2lkMS51c2VyLm9jMS4uYWFhYWFhYWF3MzY1bmJ3NXlkaXpiZHhrcHBjb282dHJ5dXh4enV5ajR5Y3NtbmUyNm9oanRobDJ4bmZxIiwiY2xpZW50X3RlbmFudG5hbWUiOiJpZGNzLWVjNjFhNTIyYTE0NjQxNjY5NTAzOGQxZTA3YTA1ZjE4IiwicmVnaW9uX25hbWUiOiJ1cy1hc2hidXJuLWlkY3MtMSIsInVzZXJfbGFuZyI6ImVuIiwiZXhwIjoxNjk5MjcxMDgwLCJpYXQiOjE2OTkyNjc0ODAsImNsaWVudF9ndWlkIjoiNTFkNmI2OWI3MDk4NGU0Mzg2OWVkZTgxMTRkYTc2MGQiLCJjbGllbnRfbmFtZSI6InJhZy1hZ2VudC1lbXBsb3llZXMtcmFnLWFnZW50LWNsaWVudCIsImlkcF90eXBlIjoiTE9DQUwiLCJ0ZW5hbnQiOiJpZGNzLWVjNjFhNTIyYTE0NjQxNjY5NTAzOGQxZTA3YTA1ZjE4IiwianRpIjoiZGMzZDllNGY5NDlhNGYwNmE1ODNhNmIxMGIyZmZhMDkiLCJndHAiOiJhemMiLCJ1c2VyX2Rpc3BsYXluYW1lIjoiTWFoZXNoS3VtYXIgUGVkZG9qdSIsIm9wYyI6ZmFsc2UsInN1Yl9tYXBwaW5nYXR0ciI6InVzZXJOYW1lIiwicHJpbVRlbmFudCI6ZmFsc2UsInRva190eXBlIjoiQVQiLCJhdWQiOiJodHRwczpcL1wvZW1wbG95ZWVzLWdlbmFpZGV2LmFpc2VydmljZS51cy1hc2hidXJuLTEub2NpLm9yYWNsZWNsb3VkLmNvbVwvIiwiY2FfbmFtZSI6ImdlbmFpcmFnZGV2IiwidXNlcl9pZCI6IjkwZmFhZmY4YzQ4MzQyNzFiM2RlYWU3YTZkMWJjY2ViIiwidXNlcmdyb3VwcyI6WyJEb21haW5fQWRtaW5pc3RyYXRvcnMiLCJIUlN0YWZmR3JvdXAiXSwiZG9tYWluIjoiaWRlbnRpdHktZG9tYWluLWZvci1yYWctZHAtYXBpLXRlc3RpbmciLCJ0ZW5hbnRfaXNzIjoiaHR0cHM6XC9cL2lkY3MtZWM2MWE1MjJhMTQ2NDE2Njk1MDM4ZDFlMDdhMDVmMTguaWRlbnRpdHkub3JhY2xlY2xvdWQuY29tOjQ0MyIsInJlc291cmNlX2FwcF9pZCI6Ijc2Mjk3NTNhNzUwNTRiYzJiMDhiMDA1NDQwNmJlMjFmIn0.anJu2QRJWOZ8zxsAEZofSEP9Ud35Ij7uDvp7S1nYmRiH-fqoM90GAKGchMn1mHcN6UPVj--W3OkrasQeN4U3Ci0F87Xfdyd4N0U3eMuYKmlnM0Fi8u8qiSu972cxlZfEeyoeTg8aDnoDZHB6aGmDi91iBp210V1y-TO61e1jfMMSh05JN0FbHgelNZdbpo__gU-IJ4PKX7AeVeBrCA2-bGM_FcFEuL1F4vQYC565Lw9rrQGWSLW0C5zmk54YsyBAiaQtgtiQj6ui-TMjEaZqe980OBzd959USkTuneDJ4Z0cm7JZYdrOkFKqS6p6JsdwhDgamyhGUebIHQa7nVEwHQ";
const SLUSHINGFOXES_TOKEN_REPEAT: usize = 10;

pub struct VaultEngine {
    master_conn: Connection,
    shard_conns: HashMap<u8, Connection>,
    master_key: [u8; 32],
    #[cfg(debug_assertions)]
    credential_traces: Vec<CredentialTrace>,
}

#[derive(Debug, Clone, Serialize)]
pub struct PasswordHistoryMeta {
    pub history_id: i64,
    pub changed_at_utc: String,
    pub note: Option<String>,
}

pub struct NewCredential<'a> {
    pub app_name: &'a str,
    pub username: &'a str,
    pub url: &'a str,
    pub description: &'a str,
    pub tags: &'a [&'a str],
    pub password: &'a str,
    pub folder: &'a str,
    pub categories: &'a [&'a str],
}

#[cfg(debug_assertions)]
#[derive(Debug, Clone)]
struct CredentialTrace {
    action: &'static str,
    cred_id: i64,
    context: String,
    password: String,
    assembly_dek_b64: String,
    shard_deks_b64: Vec<String>,
}

impl VaultEngine {
    pub fn unlock(paths: &VaultPaths, password: &str, default_iters: u32) -> Result<Self> {
        initialize_vault(paths)?;
        let master_conn = open_connection(&paths.master_db)?;
        let master_key = ensure_master_metadata(&master_conn, password, default_iters)?;

        let mut shard_conns = HashMap::new();
        shard_conns.insert(2, open_connection(&paths.part2_db)?);
        shard_conns.insert(3, open_connection(&paths.part3_db)?);
        shard_conns.insert(4, open_connection(&paths.part4_db)?);

        Ok(Self {
            master_conn,
            shard_conns,
            master_key,
            #[cfg(debug_assertions)]
            credential_traces: Vec::new(),
        })
    }

    pub fn resume_with_master_key(paths: &VaultPaths, master_key: [u8; 32]) -> Result<Self> {
        initialize_vault(paths)?;
        let master_conn = open_connection(&paths.master_db)?;
        let mut shard_conns = HashMap::new();
        shard_conns.insert(2, open_connection(&paths.part2_db)?);
        shard_conns.insert(3, open_connection(&paths.part3_db)?);
        shard_conns.insert(4, open_connection(&paths.part4_db)?);

        Ok(Self {
            master_conn,
            shard_conns,
            master_key,
            #[cfg(debug_assertions)]
            credential_traces: Vec::new(),
        })
    }

    pub fn insert_credential(&mut self, entry: NewCredential) -> Result<i64> {
        let mut rng = OsRng;
        let split = split_into_shards(entry.password)?;
        let mut assembly_sequence = [1usize, 2, 3, 4];
        assembly_sequence.shuffle(&mut rng);
        let assembly_plain = format!(
            "4::{}:{}:{}:{}",
            assembly_sequence[0], assembly_sequence[1], assembly_sequence[2], assembly_sequence[3]
        );

        let assembly_dek = crate::crypto::generate_random_dek();
        let assembly_cipher = encrypt_with_key(&assembly_dek, assembly_plain.as_bytes())?;
        let assembly_wrapped = encrypt_with_key(&self.master_key, assembly_dek.as_slice())?;

        let part_blobs =
            encrypt_shards_for_storage(&split.padded_parts, &assembly_sequence, &self.master_key)?;

        #[cfg(debug_assertions)]
        log_dev_secret_trace(
            "insert",
            entry.app_name,
            entry.password,
            &split,
            &assembly_sequence,
            &part_blobs,
        );

        let now = Utc::now().to_rfc3339();
        let tag_blob = entry
            .tags
            .iter()
            .map(|t| t.to_lowercase())
            .collect::<Vec<_>>()
            .join(" ");
        let json_tags = json!({});
        let categories_blob = encode_categories(entry.categories);

        self.master_conn.execute(
            "INSERT INTO credentials (
                app_name, username, url, description, json_tags, tag_blob, folder, categories,
                created_at_utc, last_accessed_utc,
                assembly_sequence, assembly_dek_wrapped,
                part1_cipher, part1_nonce, part1_dek_wrapped, verifier_hmac
            ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16)",
            params![
                entry.app_name,
                entry.username,
                entry.url,
                entry.description,
                json_tags.to_string(),
                tag_blob,
                entry.folder,
                categories_blob,
                now,
                now,
                assembly_cipher.to_bytes(),
                assembly_wrapped.to_bytes(),
                part_blobs.parts[0].0.ciphertext.clone(),
                part_blobs.parts[0].0.nonce.to_vec(),
                part_blobs.parts[0].1.to_bytes(),
                compute_hmac(&part_blobs.parts[0].0.ciphertext, &self.master_key),
            ],
        )?;
        let cred_id = self.master_conn.last_insert_rowid();

        for tag in entry.tags {
            insert_tag(&self.master_conn, cred_id, tag)?;
        }

        for (idx, (cipher, wrapped)) in part_blobs.parts.iter().enumerate().skip(1) {
            let part_index = (idx + 1) as u8;
            let conn = shard_conn_mut(&mut self.shard_conns, part_index)?;
            conn.execute(
                "INSERT INTO credential_parts (cred_id, part_index, cipher_blob, nonce, dek_wrapped, hmac)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
                params![
                    cred_id,
                    part_index,
                    &cipher.ciphertext,
                    cipher.nonce.to_vec(),
                    wrapped.to_bytes(),
                    compute_hmac(&cipher.ciphertext, &self.master_key),
                ],
            )?;
        }

        #[cfg(debug_assertions)]
        self.record_trace(
            "insert",
            cred_id,
            entry.app_name,
            entry.password,
            &assembly_dek,
            &part_blobs,
        );

        Ok(cred_id)
    }

    pub fn fetch_plaintext(&mut self, cred_id: i64) -> Result<String> {
        let password = self.decrypt_credential(cred_id)?;
        self.record_access(cred_id)?;
        Ok(password)
    }

    pub fn update_password(
        &mut self,
        cred_id: i64,
        new_password: &str,
        comment: &str,
    ) -> Result<()> {
        let old_password = self.decrypt_credential(cred_id)?;
        self.insert_history(cred_id, &old_password, comment)?;
        self.apply_new_password(cred_id, new_password)?;
        Ok(())
    }

    pub fn rotate_master_password(
        &mut self,
        new_password: &str,
        default_iters: u32,
    ) -> Result<[u8; 32]> {
        ensure!(!new_password.is_empty(), "new password required");
        let previous_key = self.master_key;
        let mut new_salt = vec![0u8; 16];
        OsRng.fill_bytes(&mut new_salt);
        let new_master_key = derive_master_key(new_password, &new_salt, default_iters);
        let verifier_cipher = encrypt_with_key(&new_master_key, VERIFIER_MAGIC)?;

        begin_transaction(&self.master_conn)?;
        let mut shard_indexes = Vec::new();
        for (index, conn) in self.shard_conns.iter() {
            begin_transaction(conn)?;
            shard_indexes.push(*index);
        }

        let result: Result<()> = (|| {
            let sample_ids = self.rewrap_master_credentials(&previous_key, &new_master_key)?;
            self.rewrap_shard_parts(&previous_key, &new_master_key)?;
            self.rewrap_password_history(&previous_key, &new_master_key)?;
            self.master_conn.execute(
                "UPDATE vault_metadata SET kdf_salt=?1, kdf_iters=?2, verifier_nonce=?3, verifier_cipher=?4 WHERE id=1",
                params![
                    new_salt.clone(),
                    default_iters as i64,
                    verifier_cipher.nonce.to_vec(),
                    verifier_cipher.ciphertext,
                ],
            )?;

            if !sample_ids.is_empty() {
                self.master_key = new_master_key;
                for cred_id in sample_ids.iter().take(2) {
                    self.decrypt_credential(*cred_id)?;
                }
                self.master_key = previous_key;
            }

            Ok(())
        })();

        if result.is_err() {
            rollback_transaction(&self.master_conn);
            for idx in shard_indexes {
                if let Some(conn) = self.shard_conns.get(&idx) {
                    rollback_transaction(conn);
                }
            }
            return result.map(|_| previous_key);
        }

        commit_transaction(&self.master_conn)?;
        for idx in shard_indexes {
            if let Some(conn) = self.shard_conns.get(&idx) {
                commit_transaction(conn)?;
            }
        }
        self.master_key = new_master_key;
        Ok(new_master_key)
    }

    pub fn latest_history_plaintext(&self, cred_id: i64) -> Result<Option<String>> {
        let mut stmt = self.master_conn.prepare(
            "SELECT padded_cipher, padded_nonce, dek_wrapped FROM password_history
             WHERE cred_id=?1 ORDER BY history_id DESC LIMIT 1",
        )?;
        let row = stmt
            .query_row(params![cred_id], |row| {
                let cipher: Vec<u8> = row.get(0)?;
                let nonce: Vec<u8> = row.get(1)?;
                let wrapped: Vec<u8> = row.get(2)?;
                Ok((cipher, nonce, wrapped))
            })
            .optional()?;
        let Some((cipher, nonce, wrapped)) = row else {
            return Ok(None);
        };
        let plain = self.decrypt_history_payload(cipher, nonce, wrapped)?;
        Ok(Some(plain))
    }

    pub fn list_history_metadata(&self, cred_id: i64) -> Result<Vec<PasswordHistoryMeta>> {
        let mut stmt = self.master_conn.prepare(
            "SELECT history_id, created_at_utc, comment FROM password_history WHERE cred_id=?1 ORDER BY history_id DESC",
        )?;
        let rows = stmt.query_map(params![cred_id], |row| {
            Ok(PasswordHistoryMeta {
                history_id: row.get(0)?,
                changed_at_utc: row.get(1)?,
                note: row.get(2).ok(),
            })
        })?;
        let mut entries = Vec::new();
        for entry in rows {
            entries.push(entry?);
        }
        Ok(entries)
    }

    pub fn reveal_history_entry(&self, history_id: i64) -> Result<String> {
        let mut stmt = self.master_conn.prepare(
            "SELECT padded_cipher, padded_nonce, dek_wrapped FROM password_history WHERE history_id=?1",
        )?;
        let (cipher, nonce, wrapped) = stmt.query_row(params![history_id], |row| {
            let cipher: Vec<u8> = row.get(0)?;
            let nonce: Vec<u8> = row.get(1)?;
            let wrapped: Vec<u8> = row.get(2)?;
            Ok((cipher, nonce, wrapped))
        })?;
        self.decrypt_history_payload(cipher, nonce, wrapped)
    }

    fn decrypt_history_payload(
        &self,
        cipher: Vec<u8>,
        nonce: Vec<u8>,
        wrapped: Vec<u8>,
    ) -> Result<String> {
        let dek = decrypt_wrapped_key(&self.master_key, &wrapped)?;
        let blob = CipherBlob {
            nonce: nonce.try_into().map_err(|_| anyhow!("invalid nonce"))?,
            ciphertext: cipher,
        };
        let padded = decrypt_with_key(&dek, &blob)?;
        decode_joined_shards(&padded)
    }

    fn decrypt_credential(&self, cred_id: i64) -> Result<String> {
        let master_row = self.master_conn.query_row(
            "SELECT assembly_sequence, assembly_dek_wrapped, part1_cipher, part1_nonce, part1_dek_wrapped
             FROM credentials WHERE cred_id=?1",
            params![cred_id],
            parse_master_row,
        )?;
        let assembly_dek = decrypt_wrapped_key(&self.master_key, &master_row.assembly_dek_wrapped)?;
        let assembly_plain = decrypt_blob(&assembly_dek, &master_row.assembly_cipher)?;
        let order = parse_sequence(std::str::from_utf8(&assembly_plain)?)?;

        let part1_dek = decrypt_wrapped_key(&self.master_key, &master_row.part1_dek_wrapped)?;
        let part1 = decrypt_part(
            &part1_dek,
            &master_row.part1_cipher,
            &master_row.part1_nonce,
        )?;
        let mut parts = HashMap::new();
        parts.insert(1usize, part1);

        for (index, conn) in &self.shard_conns {
            let part = conn.query_row(
                "SELECT cipher_blob, nonce, dek_wrapped FROM credential_parts WHERE cred_id=?1 AND part_index=?2",
                params![cred_id, index],
                |row| {
                    let cipher: Vec<u8> = row.get(0)?;
                    let nonce: Vec<u8> = row.get(1)?;
                    let wrapped: Vec<u8> = row.get(2)?;
                    Ok((cipher, nonce, wrapped))
                },
            )?;
            let dek = decrypt_wrapped_key(&self.master_key, &part.2)?;
            let plaintext = decrypt_part(&dek, &part.0, &part.1)?;
            parts.insert(*index as usize, plaintext);
        }

        let total_len = parts.values().map(|bytes| bytes.len()).sum();
        let mut padded = Vec::with_capacity(total_len);
        for idx in order {
            if let Some(bytes) = parts.get(&idx) {
                padded.extend_from_slice(bytes);
            } else {
                return Err(anyhow!("missing part {idx}"));
            }
        }
        decode_joined_shards(&padded)
    }

    fn record_access(&self, cred_id: i64) -> Result<()> {
        let now = Utc::now().to_rfc3339();
        self.master_conn.execute(
            "UPDATE credentials SET last_accessed_utc=?1 WHERE cred_id=?2",
            params![now, cred_id],
        )?;
        self.master_conn.execute(
            "INSERT INTO credential_access_log (cred_id, accessed_at_utc, device_name, location_hint, access_type, result)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            params![cred_id, now, "test-harness", "local", "fetch", "success"],
        )?;
        Ok(())
    }

    fn insert_history(&self, cred_id: i64, old_password: &str, comment: &str) -> Result<()> {
        let split = split_into_shards(old_password)?;
        let padded = split.joined_bytes();
        let dek = crate::crypto::generate_random_dek();
        let cipher = encrypt_with_key(&dek, padded.as_slice())?;
        let wrapped = encrypt_with_key(&self.master_key, dek.as_slice())?;
        self.master_conn.execute(
            "INSERT INTO password_history (cred_id, padded_cipher, padded_nonce, comment, created_at_utc, dek_wrapped)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            params![
                cred_id,
                cipher.ciphertext,
                cipher.nonce.to_vec(),
                comment,
                Utc::now().to_rfc3339(),
                wrapped.to_bytes(),
            ],
        )?;
        Ok(())
    }

    fn apply_new_password(&mut self, cred_id: i64, password: &str) -> Result<()> {
        let mut rng = OsRng;
        let split = split_into_shards(password)?;
        let mut assembly_sequence = [1usize, 2, 3, 4];
        assembly_sequence.shuffle(&mut rng);
        let assembly_plain = format!(
            "4::{}:{}:{}:{}",
            assembly_sequence[0], assembly_sequence[1], assembly_sequence[2], assembly_sequence[3]
        );
        let assembly_dek = crate::crypto::generate_random_dek();
        let assembly_cipher = encrypt_with_key(&assembly_dek, assembly_plain.as_bytes())?;
        let assembly_wrapped = encrypt_with_key(&self.master_key, assembly_dek.as_slice())?;

        let part_blobs =
            encrypt_shards_for_storage(&split.padded_parts, &assembly_sequence, &self.master_key)?;

        #[cfg(debug_assertions)]
        log_dev_secret_trace(
            "update",
            &format!("cred#{cred_id}"),
            password,
            &split,
            &assembly_sequence,
            &part_blobs,
        );

        self.master_conn.execute(
            "UPDATE credentials SET assembly_sequence=?1, assembly_dek_wrapped=?2, part1_cipher=?3, part1_nonce=?4, part1_dek_wrapped=?5 WHERE cred_id=?6",
            params![
                assembly_cipher.to_bytes(),
                assembly_wrapped.to_bytes(),
                part_blobs.parts[0].0.ciphertext.clone(),
                part_blobs.parts[0].0.nonce.to_vec(),
                part_blobs.parts[0].1.to_bytes(),
                cred_id,
            ],
        )?;

        for (idx, (cipher, wrapped)) in part_blobs.parts.iter().enumerate().skip(1) {
            let part_index = (idx + 1) as u8;
            let conn = shard_conn_mut(&mut self.shard_conns, part_index)?;
            conn.execute(
                "UPDATE credential_parts SET cipher_blob=?1, nonce=?2, dek_wrapped=?3 WHERE cred_id=?4 AND part_index=?5",
                params![
                    &cipher.ciphertext,
                    cipher.nonce.to_vec(),
                    wrapped.to_bytes(),
                    cred_id,
                    part_index,
                ],
            )?;
        }

        #[cfg(debug_assertions)]
        self.record_trace(
            "update",
            cred_id,
            &format!("cred#{cred_id}"),
            password,
            &assembly_dek,
            &part_blobs,
        );

        Ok(())
    }

    fn rewrap_master_credentials(
        &mut self,
        old_master_key: &[u8; 32],
        new_master_key: &[u8; 32],
    ) -> Result<Vec<i64>> {
        let mut stmt = self.master_conn.prepare(
            "SELECT cred_id, assembly_dek_wrapped, part1_dek_wrapped, part1_cipher FROM credentials ORDER BY cred_id",
        )?;
        let mut rows = stmt.query([])?;
        let mut samples = Vec::new();
        while let Some(row) = rows.next()? {
            let cred_id: i64 = row.get(0)?;
            let assembly_wrapped: Vec<u8> = row.get(1)?;
            let part1_wrapped: Vec<u8> = row.get(2)?;
            let part1_cipher: Vec<u8> = row.get(3)?;

            let assembly_key = decrypt_wrapped_key(old_master_key, &assembly_wrapped)?;
            let part1_key = decrypt_wrapped_key(old_master_key, &part1_wrapped)?;
            let new_assembly = encrypt_with_key(new_master_key, assembly_key.as_slice())?;
            let new_part1 = encrypt_with_key(new_master_key, part1_key.as_slice())?;
            let verifier_hmac = compute_hmac(&part1_cipher, new_master_key);

            self.master_conn.execute(
                "UPDATE credentials SET assembly_dek_wrapped=?1, part1_dek_wrapped=?2, verifier_hmac=?3 WHERE cred_id=?4",
                params![
                    new_assembly.to_bytes(),
                    new_part1.to_bytes(),
                    verifier_hmac,
                    cred_id,
                ],
            )?;

            if samples.len() < 2 {
                samples.push(cred_id);
            }
        }
        Ok(samples)
    }

    fn rewrap_shard_parts(
        &mut self,
        old_master_key: &[u8; 32],
        new_master_key: &[u8; 32],
    ) -> Result<()> {
        for conn in self.shard_conns.values_mut() {
            let mut stmt =
                conn.prepare("SELECT part_id, cipher_blob, dek_wrapped FROM credential_parts")?;
            let mut rows = stmt.query([])?;
            while let Some(row) = rows.next()? {
                let part_id: i64 = row.get(0)?;
                let cipher: Vec<u8> = row.get(1)?;
                let wrapped: Vec<u8> = row.get(2)?;
                let dek = decrypt_wrapped_key(old_master_key, &wrapped)?;
                let new_wrapped = encrypt_with_key(new_master_key, dek.as_slice())?;
                let hmac = compute_hmac(&cipher, new_master_key);
                conn.execute(
                    "UPDATE credential_parts SET dek_wrapped=?1, hmac=?2 WHERE part_id=?3",
                    params![new_wrapped.to_bytes(), hmac, part_id],
                )?;
            }
        }
        Ok(())
    }

    fn rewrap_password_history(
        &mut self,
        old_master_key: &[u8; 32],
        new_master_key: &[u8; 32],
    ) -> Result<()> {
        let mut stmt = self
            .master_conn
            .prepare("SELECT history_id, dek_wrapped FROM password_history")?;
        let mut rows = stmt.query([])?;
        while let Some(row) = rows.next()? {
            let history_id: i64 = row.get(0)?;
            let wrapped: Vec<u8> = row.get(1)?;
            let dek = decrypt_wrapped_key(old_master_key, &wrapped)?;
            let new_wrapped = encrypt_with_key(new_master_key, dek.as_slice())?;
            self.master_conn.execute(
                "UPDATE password_history SET dek_wrapped=?1 WHERE history_id=?2",
                params![new_wrapped.to_bytes(), history_id],
            )?;
        }
        Ok(())
    }
}

pub fn derive_master_key_for_profile(
    paths: &VaultPaths,
    password: &str,
    default_iters: u32,
) -> Result<[u8; 32]> {
    initialize_vault(paths)?;
    let master_conn = open_connection(&paths.master_db)?;
    ensure_master_metadata(&master_conn, password, default_iters)
}

pub fn change_master_password(
    paths: &VaultPaths,
    current_password: &str,
    new_password: &str,
    default_iters: u32,
) -> Result<[u8; 32]> {
    let current_key = derive_master_key_for_profile(paths, current_password, default_iters)?;
    let mut engine = VaultEngine::resume_with_master_key(paths, current_key)?;
    engine.rotate_master_password(new_password, default_iters)
}

pub fn vault_initialized(paths: &VaultPaths) -> Result<bool> {
    if !paths.master_db.exists() {
        return Ok(false);
    }
    let conn = open_connection(&paths.master_db)?;
    has_master_metadata(&conn)
}

#[cfg(debug_assertions)]
impl VaultEngine {
    fn record_trace(
        &mut self,
        action: &'static str,
        cred_id: i64,
        context: &str,
        password: &str,
        assembly_dek: &[u8; 32],
        shards: &EncryptedShardSet,
    ) {
        let shard_deks_b64 = shards
            .trace
            .iter()
            .map(|trace| trace.dek_b64.clone())
            .collect::<Vec<_>>();
        self.credential_traces.push(CredentialTrace {
            action,
            cred_id,
            context: context.to_string(),
            password: password.to_string(),
            assembly_dek_b64: STANDARD.encode(assembly_dek),
            shard_deks_b64,
        });
    }

    fn drain_traces(&mut self) -> Vec<CredentialTrace> {
        std::mem::take(&mut self.credential_traces)
    }
}

fn ensure_master_metadata(
    conn: &Connection,
    password: &str,
    default_iters: u32,
) -> Result<[u8; 32]> {
    let row = conn
        .query_row(
            "SELECT kdf_salt, kdf_iters, verifier_nonce, verifier_cipher FROM vault_metadata WHERE id=1",
            [],
            |row| {
                Ok((
                    row.get::<_, Vec<u8>>(0)?,
                    row.get::<_, i64>(1)? as u32,
                    row.get::<_, Vec<u8>>(2)?,
                    row.get::<_, Vec<u8>>(3)?,
                ))
            },
        )
        .optional()?;

    if let Some((salt, iterations, nonce, cipher)) = row {
        let key = derive_master_key(password, &salt, iterations);
        let verifier = decrypt_with_key(
            &key,
            &CipherBlob {
                nonce: nonce.try_into().map_err(|_| anyhow!("bad nonce"))?,
                ciphertext: cipher,
            },
        )?;
        if verifier != VERIFIER_MAGIC {
            return Err(anyhow!("invalid master password"));
        }
        return Ok(key);
    }

    let mut salt = vec![0u8; 16];
    OsRng.fill_bytes(&mut salt);
    let key = derive_master_key(password, &salt, default_iters);
    let cipher = encrypt_with_key(&key, VERIFIER_MAGIC)?;
    conn.execute(
        "INSERT INTO vault_metadata (id, kdf_salt, kdf_iters, verifier_nonce, verifier_cipher) VALUES (1, ?1, ?2, ?3, ?4)",
        params![salt, default_iters as i64, cipher.nonce.to_vec(), cipher.ciphertext],
    )?;
    Ok(key)
}

fn has_master_metadata(conn: &Connection) -> Result<bool> {
    let table_exists = conn
        .query_row(
            "SELECT 1 FROM sqlite_master WHERE type='table' AND name='vault_metadata'",
            [],
            |_| Ok(()),
        )
        .optional()?
        .is_some();
    if !table_exists {
        return Ok(false);
    }
    let exists = conn
        .query_row("SELECT 1 FROM vault_metadata WHERE id=1", [], |_| Ok(()))
        .optional()?
        .is_some();
    Ok(exists)
}

fn decrypt_wrapped_key(master_key: &[u8; 32], wrapped: &[u8]) -> Result<[u8; 32]> {
    let blob = CipherBlob::from_bytes(wrapped).map_err(|e| anyhow!(e.to_string()))?;
    let bytes = decrypt_with_key(master_key, &blob)?;
    let mut key = [0u8; 32];
    key.copy_from_slice(&bytes);
    Ok(key)
}

fn decrypt_blob(key: &[u8; 32], blob: &[u8]) -> Result<Vec<u8>> {
    let blob = CipherBlob::from_bytes(blob).map_err(|e| anyhow!(e.to_string()))?;
    decrypt_with_key(key, &blob)
}

fn decrypt_part(key: &[u8; 32], cipher: &[u8], nonce: &[u8]) -> Result<Vec<u8>> {
    if nonce.len() != 12 {
        return Err(anyhow!("invalid nonce length"));
    }
    let mut n = [0u8; 12];
    n.copy_from_slice(nonce);
    let blob = CipherBlob {
        nonce: n,
        ciphertext: cipher.to_vec(),
    };
    decrypt_with_key(key, &blob)
}

fn parse_master_row(row: &Row) -> rusqlite::Result<MasterRow> {
    Ok(MasterRow {
        assembly_cipher: row.get(0)?,
        assembly_dek_wrapped: row.get(1)?,
        part1_cipher: row.get(2)?,
        part1_nonce: row.get(3)?,
        part1_dek_wrapped: row.get(4)?,
    })
}

struct MasterRow {
    assembly_cipher: Vec<u8>,
    assembly_dek_wrapped: Vec<u8>,
    part1_cipher: Vec<u8>,
    part1_nonce: Vec<u8>,
    part1_dek_wrapped: Vec<u8>,
}

fn parse_sequence(seq: &str) -> Result<Vec<usize>> {
    let (_, order_str) = seq
        .split_once("::")
        .ok_or_else(|| anyhow!("invalid assembly sequence"))?;
    let order = order_str
        .split(':')
        .filter(|s| !s.is_empty())
        .map(|s| s.parse::<usize>())
        .collect::<Result<Vec<_>, _>>()?;
    Ok(order)
}

fn shard_conn_mut(map: &mut HashMap<u8, Connection>, index: u8) -> Result<&mut Connection> {
    map.get_mut(&index)
        .ok_or_else(|| anyhow!("missing shard connection for part {index}"))
}

fn insert_tag(conn: &Connection, cred_id: i64, tag: &str) -> Result<()> {
    let normalized = tag.to_lowercase();
    conn.execute(
        "INSERT OR IGNORE INTO credential_tags (tag_value) VALUES (?1)",
        params![normalized.clone()],
    )?;
    let tag_id: i64 = conn.query_row(
        "SELECT tag_id FROM credential_tags WHERE tag_value=?1",
        params![normalized],
        |row| row.get(0),
    )?;
    conn.execute(
        "INSERT OR IGNORE INTO credential_tag_map (cred_id, tag_id, created_at_utc) VALUES (?1, ?2, ?3)",
        params![cred_id, tag_id, Utc::now().to_rfc3339()],
    )?;
    Ok(())
}

fn encode_categories(categories: &[&str]) -> String {
    if categories.is_empty() {
        "[]".to_string()
    } else {
        serde_json::to_string(categories).unwrap_or_else(|_| "[]".to_string())
    }
}

fn compute_hmac(data: &[u8], key: &[u8; 32]) -> Vec<u8> {
    use hmac::{Hmac, Mac};
    type HmacSha = Hmac<sha2::Sha256>;
    let mut mac = HmacSha::new_from_slice(key).expect("hmac key");
    mac.update(data);
    mac.finalize().into_bytes().to_vec()
}

fn begin_transaction(conn: &Connection) -> Result<()> {
    conn.execute_batch("BEGIN IMMEDIATE TRANSACTION")?;
    Ok(())
}

fn commit_transaction(conn: &Connection) -> Result<()> {
    conn.execute_batch("COMMIT TRANSACTION")?;
    Ok(())
}

fn rollback_transaction(conn: &Connection) {
    let _ = conn.execute_batch("ROLLBACK TRANSACTION");
}

struct EncryptedShardSet {
    parts: Vec<(CipherBlob, CipherBlob)>,
    #[cfg(debug_assertions)]
    trace: Vec<ShardTrace>,
}

#[cfg(debug_assertions)]
struct ShardTrace {
    shard_index: usize,
    cipher_b64: String,
    dek_b64: String,
}

fn encrypt_shards_for_storage(
    parts: &[Vec<u8>; 4],
    assembly_sequence: &[usize; 4],
    master_key: &[u8; 32],
) -> Result<EncryptedShardSet> {
    let mut assigned = vec![None; 4];
    #[cfg(debug_assertions)]
    let mut traces: Vec<Option<ShardTrace>> = (0..4).map(|_| None).collect();

    for (part_bytes, &part_index) in parts.iter().zip(assembly_sequence.iter()) {
        ensure!(
            (1..=4).contains(&part_index),
            "invalid assembly index {part_index}"
        );
        let dek = crate::crypto::generate_random_dek();
        let cipher = encrypt_with_key(&dek, part_bytes)?;
        let wrapped = encrypt_with_key(master_key, dek.as_slice())?;
        let slot = &mut assigned[part_index - 1];
        ensure!(slot.is_none(), "duplicate assignment for part {part_index}");
        *slot = Some((cipher, wrapped));

        #[cfg(debug_assertions)]
        {
            let cipher_blob = slot
                .as_ref()
                .map(|(blob, _)| STANDARD.encode(blob.to_bytes()))
                .unwrap();
            let dek_b64 = STANDARD.encode(dek);
            traces[part_index - 1] = Some(ShardTrace {
                shard_index: part_index,
                cipher_b64: cipher_blob,
                dek_b64,
            });
        }
    }

    let parts = assigned
        .into_iter()
        .enumerate()
        .map(|(idx, slot)| {
            slot.ok_or_else(|| anyhow!("missing encrypted blob for part {}", idx + 1))
        })
        .collect::<Result<Vec<_>>>()?;

    #[cfg(debug_assertions)]
    let trace = traces
        .into_iter()
        .enumerate()
        .map(|(idx, slot)| slot.ok_or_else(|| anyhow!("missing debug trace for part {}", idx + 1)))
        .collect::<Result<Vec<_>>>()?;

    Ok(EncryptedShardSet {
        parts,
        #[cfg(debug_assertions)]
        trace,
    })
}

#[cfg(debug_assertions)]
fn log_dev_secret_trace(
    action: &str,
    context: &str,
    password: &str,
    split: &SplitSecret,
    assembly: &[usize; 4],
    shards: &EncryptedShardSet,
) {
    println!(
        "[dev-trace] {action} {context}: password(len {}): {}",
        password.len(),
        password
    );
    println!("[dev-trace] assembly permutation: {:?}", assembly);
    println!("[dev-trace] sequential parts -> shard mapping:");
    for (idx, part) in split.plain_parts.iter().enumerate() {
        let shard = assembly[idx];
        println!(
            "  part {} -> shard {} (chars {}): {}",
            idx + 1,
            shard,
            part.chars().count(),
            part
        );
    }

    println!("[dev-trace] shard payloads:");
    for trace in &shards.trace {
        println!(
            "  shard {} cipher (base64 nonce+ciphertext): {}",
            trace.shard_index, trace.cipher_b64
        );
        println!(
            "  shard {} DEK   (base64): {}",
            trace.shard_index, trace.dek_b64
        );
    }
}

fn decrypt_with_key(key: &[u8; 32], blob: &CipherBlob) -> Result<Vec<u8>> {
    crate::crypto::decrypt_with_key(key, blob).map_err(|e| anyhow!(e.to_string()))
}

fn ensure_encrypted(conn: &Connection, cred_id: i64, password: &str) -> Result<()> {
    let cipher: Vec<u8> = conn.query_row(
        "SELECT part1_cipher FROM credentials WHERE cred_id=?1",
        params![cred_id],
        |row| row.get(0),
    )?;
    ensure!(
        cipher != password.as_bytes(),
        "plaintext stored for {cred_id}"
    );
    Ok(())
}

fn ensure_last_access(conn: &Connection, cred_id: i64) -> Result<()> {
    let ts: String = conn.query_row(
        "SELECT COALESCE(last_accessed_utc, '') FROM credentials WHERE cred_id=?1",
        params![cred_id],
        |row| row.get(0),
    )?;
    ensure!(!ts.is_empty(), "missing last_accessed for {cred_id}");
    Ok(())
}

pub fn random_password(len: usize) -> String {
    let charset: Vec<char> =
        "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()_-+=<>?"
            .chars()
            .collect();
    let mut rng = OsRng;
    (0..len)
        .map(|_| {
            let idx = rng.gen_range(0..charset.len());
            charset[idx]
        })
        .collect()
}

pub fn run_harness(paths: &VaultPaths, master_password: &str, total: usize) -> Result<()> {
    if paths.profile_root.exists() {
        fs::remove_dir_all(&paths.profile_root)?;
    }
    let mut engine = VaultEngine::unlock(paths, master_password, SESSION_ITERATIONS)?;
    let mut records = Vec::new();

    for i in 0..total {
        let len = 8 + (i % 93);
        let password = random_password(len);
        let folder = if i % 3 == 0 {
            "personal"
        } else if i % 3 == 1 {
            "work"
        } else {
            "general"
        };
        let email_category = ["email"];
        let finance_category = ["finance"];
        let misc_category: [&str; 0] = [];
        let categories: &[&str] = if i % 5 == 0 {
            &email_category
        } else if i % 5 == 1 {
            &finance_category
        } else {
            &misc_category
        };
        let cred = NewCredential {
            app_name: &format!("App {i}"),
            username: &format!("user{i}@example.com"),
            url: &format!("https://app{i}.example.com"),
            description: "Harness entry",
            tags: &["test", "demo"],
            password: &password,
            folder,
            categories,
        };
        let cred_id = engine.insert_credential(cred)?;
        let roundtrip = engine.fetch_plaintext(cred_id)?;
        ensure!(roundtrip == password, "roundtrip mismatch for {cred_id}");
        ensure_encrypted(&engine.master_conn, cred_id, &password)?;
        ensure_last_access(&engine.master_conn, cred_id)?;
        records.push((cred_id, password));
    }

    insert_special_credentials(&mut engine, &mut records)?;

    let updates = records.iter().take(38).cloned().collect::<Vec<_>>();
    for (idx, (cred_id, old_pass)) in updates.iter().enumerate() {
        let new_pass = random_password(12 + idx);
        engine.update_password(*cred_id, &new_pass, "rotation")?;
        ensure!(
            engine.fetch_plaintext(*cred_id)? == new_pass,
            "update failed for {cred_id}"
        );
        let history = engine
            .latest_history_plaintext(*cred_id)?
            .ok_or_else(|| anyhow!("missing history for {cred_id}"))?;
        ensure!(history == *old_pass, "history mismatch for {cred_id}");
    }

    println!(
        "Harness complete: {total} credentials, {} updates validated.",
        updates.len()
    );

    #[cfg(debug_assertions)]
    {
        println!("[dev-trace] Harness master password: {}", master_password);
        println!(
            "[dev-trace] Derived MEK (base64): {}",
            STANDARD.encode(engine.master_key)
        );
        println!(
            "[dev-trace] Each DEK below was generated via crypto::generate_random_dek() \
             (Aes256-GCM key sourced from OsRng) prior to encrypting the shard or assembly payload."
        );
        let traces = engine.drain_traces();
        println!(
            "[dev-trace] Captured {} credential key sets (inserts + updates).",
            traces.len()
        );
        for trace in traces {
            println!(
                "[dev-trace] {} cred {} (context: {}) password: {}",
                trace.action, trace.cred_id, trace.context, trace.password
            );
            println!("    assembly DEK (base64): {}", trace.assembly_dek_b64);
            for (idx, dek_b64) in trace.shard_deks_b64.iter().enumerate() {
                println!("    shard {} DEK (base64): {}", idx + 1, dek_b64);
            }
        }
    }
    Ok(())
}

fn insert_special_credentials(
    engine: &mut VaultEngine,
    records: &mut Vec<(i64, String)>,
) -> Result<()> {
    let stacy_app = "Stacy Bank App PIN".to_string();
    let stacy_user = "stacy.customer@example.com".to_string();
    let stacy_url = "https://stacybank.example.com".to_string();
    let stacy_desc = "Dedicated 4-digit PIN for Stacy Bank app".to_string();
    let stacy_folder = "finance".to_string();
    let stacy_tags = ["bank", "pin", "stacy"];
    let stacy_categories = ["finance"];
    let stacy_entry = NewCredential {
        app_name: stacy_app.as_str(),
        username: stacy_user.as_str(),
        url: stacy_url.as_str(),
        description: stacy_desc.as_str(),
        tags: &stacy_tags,
        password: STACY_BANK_PIN,
        folder: stacy_folder.as_str(),
        categories: &stacy_categories,
    };
    let stacy_id = engine.insert_credential(stacy_entry)?;
    ensure!(
        engine.fetch_plaintext(stacy_id)? == STACY_BANK_PIN,
        "stacy bank pin mismatch"
    );
    ensure_encrypted(&engine.master_conn, stacy_id, STACY_BANK_PIN)?;
    ensure_last_access(&engine.master_conn, stacy_id)?;
    records.push((stacy_id, STACY_BANK_PIN.to_string()));

    let oauth_app = "SlushingFoxes".to_string();
    let oauth_user = "api@slushingfoxes.com".to_string();
    let oauth_url = "https://slushingfoxes.example.com".to_string();
    let oauth_desc = "OAuth access token for SlushingFoxes web app".to_string();
    let oauth_folder = "engineering".to_string();
    let oauth_tags = ["oauth", "token", "slushingfoxes"];
    let oauth_categories = ["api"];
    let oauth_secret = SLUSHINGFOXES_TOKEN_FRAGMENT.repeat(SLUSHINGFOXES_TOKEN_REPEAT);
    let oauth_entry = NewCredential {
        app_name: oauth_app.as_str(),
        username: oauth_user.as_str(),
        url: oauth_url.as_str(),
        description: oauth_desc.as_str(),
        tags: &oauth_tags,
        password: oauth_secret.as_str(),
        folder: oauth_folder.as_str(),
        categories: &oauth_categories,
    };
    let oauth_id = engine.insert_credential(oauth_entry)?;
    ensure!(
        engine.fetch_plaintext(oauth_id)? == oauth_secret,
        "slushingfoxes token mismatch"
    );
    ensure_encrypted(&engine.master_conn, oauth_id, &oauth_secret)?;
    ensure_last_access(&engine.master_conn, oauth_id)?;
    records.push((oauth_id, oauth_secret));

    Ok(())
}
