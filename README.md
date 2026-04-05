# PUT-ALL-YOUR-EGGS
Password Manager tool for Linux. 

## Quick Start
```bash
make
make install
pwmgr init
```

## Commands
| Command | Description |
|---|---|
| `pwmgr init [db_path]` | Initialize the vault DB and set master password. |
| `pwmgr add <site> [db_path]` | Save username and password for a site. If the site already exists, asks whether to overwrite it. |
| `pwmgr get <site> [db_path]` | Show saved credentials for a site (requires master password). |
| `pwmgr delete <site> [db_path]` | Delete a site entry with confirmation (requires master password). |
| `pwmgr list [db_path]` | List all saved site names. |

