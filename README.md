# cxporter

[![Build Status](https://github.com/nvinuesa/cxporter/workflows/CI/badge.svg)](https://github.com/nvinuesa/cxporter/actions)
[![Go Report Card](https://goreportcard.com/badge/github.com/nvinuesa/cxporter)](https://goreportcard.com/report/github.com/nvinuesa/cxporter)
[![License: AGPL-3.0](https://img.shields.io/badge/License-AGPL%203.0-blue.svg)](https://www.gnu.org/licenses/agpl-3.0)

Convert credentials from legacy password managers to the FIDO Alliance CXF format.

## Overview

`cxporter` is a command-line tool that converts credentials from legacy password manager formats (KeePass, Chrome, Firefox, Bitwarden) and local credential stores (SSH keys) into the FIDO Alliance's Credential Exchange Format (CXF). It enables secure, encrypted credential migration to any CXP-compliant password manager.

## Features

- **Multi-source support**: Import from KeePass (.kdbx), Chrome CSV, Firefox CSV, Bitwarden JSON, and SSH keys
- **CXF output**: Export to the standardized FIDO Alliance CXF format
- **HPKE encryption**: Optional encryption for secure credential transfers
- **Metadata preservation**: Maintains timestamps, folders, tags, and custom fields
- **Preview mode**: Inspect conversions before exporting

## Installation

### From Source

```bash
go install github.com/nvinuesa/cxporter/cmd/cxporter@latest
```

### Build from Source

```bash
git clone https://github.com/nvinuesa/cxporter.git
cd cxporter
make build
```

## Usage

### Convert KeePass to CXF

```bash
cxporter convert -s keepass -i vault.kdbx -o vault.cxf
```

### Convert Chrome Passwords

```bash
cxporter convert -s chrome -i passwords.csv -o chrome.cxf
```

### Convert SSH Keys

```bash
cxporter convert -s ssh -i ~/.ssh -o ssh-keys.cxf
```

### Preview Before Converting

```bash
cxporter preview -s keepass -i vault.kdbx
```

### Encrypted Export

```bash
cxporter convert -s keepass -i vault.kdbx -o vault.cxp --encrypt --recipient-key <base64-pubkey>
```

## Supported Sources

| Source    | Format    | Credential Types                          |
|-----------|-----------|-------------------------------------------|
| KeePass   | .kdbx     | passwords, TOTP, notes, attachments       |
| Chrome    | CSV       | passwords                                 |
| Firefox   | CSV       | passwords                                 |
| Bitwarden | JSON      | passwords, TOTP, notes, cards, identities |
| SSH       | directory | SSH keys                                  |

## Requirements

- Go 1.23 or later (for building from source)

## License

AGPL-3.0 - See [LICENSE](LICENSE) for details.

## Related Projects

- [go-cxf](https://github.com/nvinuesa/go-cxf) - Go implementation of CXF types
- [go-cxp](https://github.com/nvinuesa/go-cxp) - Go implementation of CXP protocol

## References

- [CXP Specification](https://fidoalliance.org/specs/cx/cxp-v1.0-wd-20240522.html)
- [CXF Specification](https://fidoalliance.org/specs/cx/cxf-v1.0-rd-20250313.html)
