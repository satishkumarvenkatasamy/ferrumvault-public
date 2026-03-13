#![allow(dead_code)]

use aes_gcm::{
    Aes256Gcm, Nonce,
    aead::{Aead, KeyInit, OsRng, rand_core::RngCore},
};
use anyhow::{anyhow, ensure};
use pbkdf2::pbkdf2_hmac;
use rand::{SeedableRng, rngs::StdRng};
use sha2::Sha256;
use thiserror::Error;

pub const SHARD_COUNT: usize = 4;
pub const MIN_SECRET_LEN: usize = 4;
pub const SHARD_BEGIN_MARKER: &str = "[[BoP]]";
pub const SHARD_END_MARKER: &str = "[[EoP]]";
pub const PBKDF2_DEFAULT_ITERS: u32 = 10_000;

#[derive(Debug, Error)]
pub enum CryptoError {
    #[error("secret must contain at least {MIN_SECRET_LEN} characters")]
    SecretTooShort,
    #[error("encryption failure: {0}")]
    EncryptFailure(String),
    #[error("decryption failure: {0}")]
    DecryptFailure(String),
}

#[derive(Debug, Clone)]
pub struct SplitSecret {
    pub padded_parts: [Vec<u8>; SHARD_COUNT],
    pub plain_parts: [String; SHARD_COUNT],
}

impl SplitSecret {
    pub fn joined_bytes(&self) -> Vec<u8> {
        let total_len: usize = self.padded_parts.iter().map(|p| p.len()).sum();
        let mut buf = Vec::with_capacity(total_len);
        for shard in &self.padded_parts {
            buf.extend_from_slice(shard);
        }
        buf
    }
}

#[derive(Debug, Clone)]
pub struct CipherBlob {
    pub nonce: [u8; 12],
    pub ciphertext: Vec<u8>,
}

impl CipherBlob {
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(self.nonce.len() + self.ciphertext.len());
        buf.extend_from_slice(&self.nonce);
        buf.extend_from_slice(&self.ciphertext);
        buf
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self, CryptoError> {
        if bytes.len() < 13 {
            return Err(CryptoError::DecryptFailure("cipher blob too short".into()));
        }
        let (nonce_bytes, ciphertext) = bytes.split_at(12);
        let mut nonce = [0u8; 12];
        nonce.copy_from_slice(nonce_bytes);
        Ok(Self {
            nonce,
            ciphertext: ciphertext.to_vec(),
        })
    }
}

pub fn split_into_shards(secret: &str) -> Result<SplitSecret, CryptoError> {
    let chars: Vec<char> = secret.chars().collect();
    if chars.len() < MIN_SECRET_LEN {
        return Err(CryptoError::SecretTooShort);
    }

    let mut padded_parts = Vec::with_capacity(SHARD_COUNT);
    let mut plain_parts = Vec::with_capacity(SHARD_COUNT);
    let base = chars.len() / SHARD_COUNT;
    let remainder = chars.len() % SHARD_COUNT;
    let mut cursor = 0usize;

    for shard_idx in 0..SHARD_COUNT {
        let mut part_len = base + if shard_idx < remainder { 1 } else { 0 };
        if shard_idx == SHARD_COUNT - 1 {
            part_len = chars.len() - cursor;
        }
        let end = cursor + part_len;
        let slice = &chars[cursor..end];
        let plain = slice.iter().collect::<String>();
        let padded = format!("[[{:02}]][[BoP]]{}[[EoP]]", shard_idx + 1, plain);
        plain_parts.push(plain);
        padded_parts.push(padded.into_bytes());
        cursor = end;
    }

    Ok(SplitSecret {
        padded_parts: padded_parts.try_into().expect("shard count"),
        plain_parts: plain_parts.try_into().expect("shard count"),
    })
}

pub fn encode_assembly_sequence(order: &[usize; 4]) -> String {
    format!("4::{}:{}:{}:{}", order[0], order[1], order[2], order[3])
}

pub fn derive_master_key(password: &str, salt: &[u8], iterations: u32) -> [u8; 32] {
    let mut key = [0u8; 32];
    pbkdf2_hmac::<Sha256>(password.as_bytes(), salt, iterations, &mut key);
    key
}

pub fn generate_random_dek() -> [u8; 32] {
    let mut key = [0u8; 32];
    OsRng.fill_bytes(&mut key);
    key
}

pub fn encrypt_with_key(key: &[u8; 32], plaintext: &[u8]) -> Result<CipherBlob, CryptoError> {
    let cipher =
        Aes256Gcm::new_from_slice(key).map_err(|e| CryptoError::EncryptFailure(e.to_string()))?;
    let mut nonce = [0u8; 12];
    OsRng.fill_bytes(&mut nonce);
    let nonce_ga = Nonce::from_slice(&nonce);
    let ciphertext = cipher
        .encrypt(nonce_ga, plaintext)
        .map_err(|e| CryptoError::EncryptFailure(e.to_string()))?;
    Ok(CipherBlob { nonce, ciphertext })
}

pub fn decrypt_with_key(key: &[u8; 32], blob: &CipherBlob) -> Result<Vec<u8>, CryptoError> {
    let cipher =
        Aes256Gcm::new_from_slice(key).map_err(|e| CryptoError::DecryptFailure(e.to_string()))?;
    let nonce = Nonce::from_slice(&blob.nonce);
    cipher
        .decrypt(nonce, blob.ciphertext.as_ref())
        .map_err(|e| CryptoError::DecryptFailure(e.to_string()))
}

fn extract_original(padded: &[u8]) -> anyhow::Result<String> {
    let full = std::str::from_utf8(padded)?;
    let mut remaining = full;
    let mut plain = String::new();
    for idx in 0..SHARD_COUNT {
        let expected_prefix = format!("[[{:02}]]", idx + 1);
        ensure!(
            remaining.starts_with(&expected_prefix),
            "invalid prefix for shard {}",
            idx + 1
        );
        remaining = &remaining[expected_prefix.len()..];
        ensure!(
            remaining.starts_with(SHARD_BEGIN_MARKER),
            "missing begin marker for shard {}",
            idx + 1
        );
        remaining = &remaining[SHARD_BEGIN_MARKER.len()..];
        let end_pos = remaining
            .find(SHARD_END_MARKER)
            .ok_or_else(|| anyhow!("missing end marker for shard {}", idx + 1))?;
        let shard_plain = &remaining[..end_pos];
        plain.push_str(shard_plain);
        remaining = &remaining[end_pos + SHARD_END_MARKER.len()..];
    }
    ensure!(remaining.is_empty(), "unexpected trailing shard data");
    Ok(plain)
}

pub fn reconstruct_plaintext(parts: &[Vec<u8>; SHARD_COUNT]) -> anyhow::Result<String> {
    let mut buf = Vec::new();
    for part in parts {
        buf.extend_from_slice(part);
    }
    extract_original(&buf)
}

pub fn decode_joined_shards(padded: &[u8]) -> anyhow::Result<String> {
    extract_original(padded)
}

/// Helper to produce a deterministic RNG for tests.
pub fn test_rng() -> StdRng {
    StdRng::seed_from_u64(0xDEADBEEF)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn split_matches_examples() {
        let samples = vec![
            ("12345678", vec!["12", "34", "56", "78"]),
            ("123456789", vec!["123", "45", "67", "89"]),
            ("1234567890", vec!["123", "456", "78", "90"]),
            ("1234567890a", vec!["123", "456", "789", "0a"]),
            ("1234567890ab", vec!["123", "456", "789", "0ab"]),
        ];

        for (input, expected) in samples {
            let split = split_into_shards(input).unwrap();
            assert_eq!(split.plain_parts.to_vec(), expected);
            for (idx, shard) in split.padded_parts.iter().enumerate() {
                let shard_str = std::str::from_utf8(shard).unwrap();
                let expected_prefix = format!("[[{:02}]]", idx + 1);
                assert!(shard_str.starts_with(&expected_prefix));
                assert!(shard_str.contains(SHARD_BEGIN_MARKER));
                assert!(shard_str.contains(SHARD_END_MARKER));
            }
        }
    }

    #[test]
    fn split_rejects_short_secrets() {
        let err = split_into_shards("abc").unwrap_err();
        assert!(matches!(err, CryptoError::SecretTooShort));
    }

    #[test]
    fn extract_round_trip_var_len() {
        let input = "a".repeat(3000);
        let split = split_into_shards(&input).unwrap();
        let mut buf = Vec::new();
        for part in &split.padded_parts {
            buf.extend_from_slice(part);
        }
        let plain = extract_original(&buf).unwrap();
        assert_eq!(plain, input);
    }
}
