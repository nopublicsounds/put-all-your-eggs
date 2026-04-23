# PUT-ALL-YOUR-EGGS

Simple CLI password manager for Linux.
Stores site credentials in SQLite, protects master password with PBKDF2 hashing,
and encrypts saved site passwords with AES-256-GCM.

**Building with GitHub Copilot**

## Features

- Master password setup and authentication
- Per-site credential save/read/delete
- Password generator (upper/lower/digit/special)
- Password encryption at rest (`enc:v1` format)
- Legacy/plain entry migration command

## Requirements

- Linux
- `gcc`
- `make`
- `sqlite3`
- OpenSSL development library (`libcrypto`)

Ubuntu/Debian:

```bash
sudo apt update
sudo apt install -y build-essential sqlite3 libsqlite3-dev libssl-dev
```

## Build & Install

```bash
make
make install
```

Binary is installed to `~/.local/bin/pwmgr` by default.

## Quick Start

```bash
# 1) Initialize vault and set master password
pwmgr init

# 2) Add credentials
pwmgr add github

# 3) Read credentials (asks master password)
pwmgr get github
```

DB path resolution priority is:

1. Command argument (`[db_path]`)
2. Environment variable `PWMGR_DB_PATH`
3. Saved config value (`pwmgr config set db <path>`)
4. Fallback `vault.db` in current directory

## Commands

| Command | Description |
|---|---|
| `pwmgr init [db_path]` | Initialize vault DB and create/set master password. |
| `pwmgr add <site> [db_path]` | Save username/password. If site exists, asks overwrite confirmation and master auth. |
| `pwmgr get <site> [db_path]` | Show credentials for site (requires master password). |
| `pwmgr delete <site> [db_path]` | Delete a site entry with confirmation (requires master password). |
| `pwmgr list [db_path]` | List all saved sites. |
| `pwmgr generate <length> [options] [db_path]` | Generate random password with optional charset flags (`--digits`, `--alpha`, `--lowercase`). |
| `pwmgr change-master [db_path]` | Change master password (requires current master password). |
| `pwmgr migrate [db_path]` | Migrate legacy/plain or old encrypted entries to `enc:v1` encrypted format. |
| `pwmgr config get db` | Show effective default DB path after applying priority rules. |
| `pwmgr config set db <path>` | Save default DB path (`~/.config/pwmgr/config` or `$XDG_CONFIG_HOME/pwmgr/config`). |

## Security Model (Current)

### 1) Master password hashing

- Stored in table `master_auth`
- Format: `salthex:hashhex`
- Algorithm: PBKDF2-HMAC-SHA256 (100,000 iterations)

### 2) Entry password encryption

- Stored in table `entries.password`
- Format: `enc:v1:ivhex:cipherhex:taghex`
- Cipher: AES-256-GCM
- Encryption key: derived from current stored master hash value

## Migration Guide

If you used older versions that stored plaintext or older cipher format:

```bash
pwmgr migrate [db_path]
```

Behavior:

- Reads all `entries`
- Converts legacy/plain values to `enc:v1` format
- Skips entries already in `enc:v1`
- Runs in a transaction (rollback on failure)

## Password Generator

```bash
pwmgr generate 20
pwmgr generate 20 --digits
pwmgr generate 20 --alpha
pwmgr generate 20 --lowercase
pwmgr generate 20 --alpha --digits
pwmgr generate 20 --alpha --lowercase
```

- Default (no flags): uses uppercase/lowercase/digits/specials.
- `--digits`: digits only (`0-9`).
- `--alpha`: letters only (uppercase + lowercase).
- `--lowercase`: removes uppercase from selected groups.
	- `--lowercase` -> lowercase only
	- `--alpha --lowercase` -> lowercase only
	- `--digits --lowercase` -> lowercase + digits
- Minimum length depends on selected groups (at least one char per group):
	- default: `4`
	- `--alpha`: `2`
	- `--digits`: `1`
	- `--lowercase`: `1`

## Notes

- `get`, `delete`, `change-master`, `migrate` require master authentication.
- DB schema is created by `pwmgr init`.
- Keep secure backups of your vault DB file.