# Source Format Guide

This document describes how to prepare and use each supported credential source with cxporter.

## KeePass (.kdbx)

### Supported Versions
- KeePass 2.x KDBX format

### Export Instructions
KeePass databases can be used directly without exporting:

```bash
cxporter convert -s keepass -i vault.kdbx -o credentials.cxf
```

### Supported Features
- Password entries with URL, username, password
- TOTP (configured via otp:// in entry fields)
- Notes and custom fields
- Attachments (binary files)
- Folder hierarchy (groups)
- Entry timestamps (created, modified)

### Authentication
KeePass databases require a password:

```bash
cxporter convert -s keepass -i vault.kdbx -p "password"
# Or with key file:
cxporter convert -s keepass -i vault.kdbx -k keyfile.key
```

---

## Chrome (CSV)

### Export Instructions
1. Open Chrome and navigate to `chrome://settings/passwords`
2. Click the three dots menu next to "Saved Passwords"
3. Select "Export passwords"
4. Save the CSV file

### CSV Format
Chrome exports passwords in this format:
```csv
name,url,username,password,note
Site Name,https://example.com,user,pass123,optional note
```

### Supported Features
- Website name
- URL
- Username and password
- Notes (newer Chrome versions)

### Usage
```bash
cxporter convert -s chrome -i passwords.csv -o chrome-creds.cxf
```

---

## Firefox (CSV)

### Export Instructions
1. Open Firefox and navigate to `about:logins`
2. Click the three dots menu in the top right
3. Select "Export Logins..."
4. Save the CSV file

### CSV Format
Firefox exports passwords in this format:
```csv
"url","username","password","httpRealm","formActionOrigin","guid","timeCreated","timeLastUsed","timePasswordChanged"
"https://example.com","user","pass123","","https://example.com/login","{guid}","1704067200000","1704067200000","1704067200000"
```

### Supported Features
- URL and form action origin
- Username and password
- HTTP Basic Auth realm
- GUID preservation
- Timestamps (created, last used, password changed)

### Usage
```bash
cxporter convert -s firefox -i logins.csv -o firefox-creds.cxf
```

---

## Bitwarden (JSON)

### Export Instructions
1. Log in to the Bitwarden web vault or desktop app
2. Go to Tools > Export Vault
3. Select "JSON" format (not encrypted)
4. Enter master password and export

**Important**: Only unencrypted JSON exports are supported. Encrypted exports will be rejected with a clear error message.

### JSON Format
Bitwarden exports in a comprehensive JSON structure with folders and items:
```json
{
  "encrypted": false,
  "folders": [
    {"id": "folder-id", "name": "Folder Name"}
  ],
  "items": [
    {
      "id": "item-id",
      "type": 1,
      "name": "Entry Name",
      "login": { "username": "user", "password": "pass", "totp": "secret" }
    }
  ]
}
```

### Supported Item Types
| Type | Value | CXF Mapping |
|------|-------|-------------|
| Login | 1 | basic-auth + totp (if TOTP present) |
| Secure Note | 2 | note |
| Card | 3 | credit-card |
| Identity | 4 | identity |

### Supported Features
- Login credentials with TOTP
- Secure notes
- Credit cards (number, expiry, CVV)
- Identities (name, address, SSN, passport, etc.)
- Folders mapped to collections
- Custom fields
- Favorites (mapped to tags)
- Timestamps

### Usage
```bash
cxporter convert -s bitwarden -i export.json -o bitwarden-creds.cxf
```

---

## SSH Keys

### Directory Structure
SSH keys are read from a directory (typically `~/.ssh`):
```
~/.ssh/
├── id_ed25519
├── id_ed25519.pub
├── id_rsa
├── id_rsa.pub
├── config
└── known_hosts
```

### Supported Key Types
- Ed25519 (recommended)
- RSA
- ECDSA
- DSA (deprecated)

### Supported Features
- Private key (PEM format)
- Public key (OpenSSH format)
- Key fingerprint (SHA256)
- Key comment
- Encrypted key detection

### Usage
```bash
cxporter convert -s ssh -i ~/.ssh -o ssh-keys.cxf
```

### Notes
- Encrypted private keys are preserved as-is
- Public keys are included when available
- Config file is not processed

---

## Auto-Detection

cxporter can automatically detect the source format:

```bash
cxporter convert -i passwords.csv -o output.cxf
```

Detection is based on:
- File extension (.kdbx, .csv, .json)
- File header/structure analysis
- Source-specific column names or JSON keys

Detection confidence levels:
- 100: Perfect match (all expected markers found)
- 80: High confidence (most markers found)
- 50: Possible match (some indicators)
- 0: No match

---

## Common Options

All sources support these options:

| Option | Description |
|--------|-------------|
| `-i, --input` | Input file or directory path |
| `-o, --output` | Output file path |
| `-s, --source` | Force specific source type |
| `-f, --filter` | Filter by tag, folder, or pattern |
| `-v, --verbose` | Show detailed output |
| `-q, --quiet` | Suppress all output except errors |
| `--dry-run` | Preview without writing output |
