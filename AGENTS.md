# Repository Guidelines

## Project Structure & Module Organization
The CLI entry point in `src/main.rs` wires together the `crypto`, `db`, and `vault` modules. Persistent logic lives in `src/vault.rs`, which coordinates sharded SQLite storage defined in `src/db/mod.rs` and `src/db/schema.rs`. Cryptography helpers (padding, AES-GCM, PBKDF2) live in `src/crypto.rs` and expose test-only utilities such as `test_rng()`. Temporary vault instances are written under `tmp-credmanager*/`; avoid checking those artifacts in and use the `--profile` flag (or the harness-specific overrides) when you need isolated data. The harness always seeds two deterministic fixtures: the “Stacy Bank App PIN” entry and the SlushingFoxes OAuth token assembled by repeating a JWT blob ten times.

## Build, Test, and Development Commands
- `cargo fmt && cargo clippy --all-targets -- -D warnings` – formats and lints; denylints keep unsafe patterns out of the harness.
- `cargo test` – runs all unit tests (`crypto::tests` today); add module tests alongside new features.
- `cargo run -- --help` – confirms CLI wiring and validates Clap argument docs.
- `cargo run -- init` – creates or migrates the SQLite vaults for the active profile.
- `cargo run -- harness --total 500` – executes the storage/retrieval harness against a clean profile (reset happens automatically). Pass `--profile`/`--base-dir` when you need isolated vault roots, and use `--password` (or `CREDMANAGER_HARNESS_PASSWORD`) for non-interactive runs.

## Coding Style & Naming Conventions
Use stable `rustfmt` defaults (4-space indents, trailing commas, module-level imports). Prefer Rust snake_case for functions/files, CamelCase for types, and keep public structs small with documented fields. Propagate errors via `anyhow::Result` and `thiserror` enums; bubble context with `.with_context(...)`. Keep SQL snippets multiline strings with uppercase keywords, mirroring `schema.rs`.

## Testing Guidelines
Write `#[cfg(test)]` modules inside the file you are exercising, follow `mod tests` naming, and seed randomness via `crypto::test_rng()` for reproducibility. Extend coverage beyond crypto by introducing vault/db tests that spin up `tempfile::TempDir` paths and destroy them afterward. Run `cargo test -- --nocapture` when debugging harness output. Aim to touch new SQL branches with table-specific tests before wiring CLI flags.

## Commit & Pull Request Guidelines
The branch has no history yet, so start with concise, imperative commit subjects ("Add vault harness flag") plus context in the body when behavior changes or new schemas land. Reference related issues in the footer when applicable. Pull requests should describe the scenario, enumerate schema/CLI impacts, cite manual test commands, and include before/after screenshots whenever CLI help text or on-disk layout changes. EOF
