# Encryption Guide

cxporter supports HPKE (Hybrid Public Key Encryption) for secure credential transfer using the CXP (Credential Exchange Protocol) specification.

## Overview

When encryption is enabled, cxporter creates a CXP archive (`.cxp`) instead of a plain JSON file. The CXP archive is a ZIP file containing:

```
output.cxp
├── index.jwe          # JWE-encrypted CXF header
└── documents/         # Encrypted attachments (if any)
```

## HPKE Parameters

cxporter uses the following HPKE configuration (per CXP specification):

| Parameter | Value | Description |
|-----------|-------|-------------|
| Mode | Base | No pre-shared key |
| KEM | DHKEM(X25519, HKDF-SHA256) | Key encapsulation |
| KDF | HKDF-SHA256 | Key derivation |
| AEAD | AES-256-GCM | Authenticated encryption |

## Generating Keys

### Using OpenSSL

Generate an X25519 keypair:

```bash
# Generate private key
openssl genpkey -algorithm X25519 -out private.pem

# Extract public key
openssl pkey -in private.pem -pubout -out public.pem

# Convert public key to raw base64 for cxporter
openssl pkey -in public.pem -pubin -outform DER | tail -c 32 | base64
```

### Using Go

```go
package main

import (
    "crypto/rand"
    "encoding/base64"
    "fmt"

    "golang.org/x/crypto/curve25519"
)

func main() {
    // Generate private key
    var privateKey [32]byte
    rand.Read(privateKey[:])

    // Derive public key
    var publicKey [32]byte
    curve25519.ScalarBaseMult(&publicKey, &privateKey)

    fmt.Println("Private:", base64.StdEncoding.EncodeToString(privateKey[:]))
    fmt.Println("Public:", base64.StdEncoding.EncodeToString(publicKey[:]))
}
```

### Using cxporter (future)

```bash
# Generate keypair
cxporter keygen -o keypair.json
```

## Encrypting Exports

### Basic Encryption

```bash
# With base64-encoded public key
cxporter convert -s keepass -i vault.kdbx -o vault.cxp \
    --encrypt --recipient-key "base64-encoded-public-key"

# With key file
cxporter convert -s keepass -i vault.kdbx -o vault.cxp \
    --encrypt --recipient-key @public.key
```

### Key File Format

Key files can be in two formats:

1. **Raw base64**: Just the 32-byte public key encoded as base64
2. **PEM format**: Standard PEM-encoded public key

## Decrypting Exports

CXP archives can be decrypted by any CXP-compliant password manager. The receiving application needs the private key corresponding to the public key used for encryption.

### Manual Decryption (for testing)

```go
package main

import (
    "archive/zip"
    "encoding/base64"
    "encoding/json"
    "fmt"
    "io"
    "os"

    "github.com/cloudflare/circl/hpke"
)

func main() {
    // Read CXP archive
    r, _ := zip.OpenReader("vault.cxp")
    defer r.Close()

    for _, f := range r.File {
        if f.Name == "index.jwe" {
            rc, _ := f.Open()
            jwe, _ := io.ReadAll(rc)
            rc.Close()

            // Parse JWE and decrypt with private key
            // (implementation depends on JWE library)
        }
    }
}
```

## Security Considerations

### Key Management
- **Never share private keys**: Only distribute public keys
- **Secure storage**: Store private keys securely (e.g., in a hardware security module)
- **Key rotation**: Use fresh keypairs for each transfer

### Transport Security
- Even with HPKE encryption, use secure channels (HTTPS) when transferring CXP files
- Verify the recipient's public key through an out-of-band mechanism

### Plaintext Handling
- CXF JSON files contain plaintext credentials
- Delete plaintext files after encryption
- Use `--encrypt` for any transfer over untrusted networks

## Troubleshooting

### Invalid Key Error

```
Error: failed to load recipient key: invalid base64 key encoding
```

Ensure the key is properly base64-encoded. Try both standard and URL-safe base64.

### Key Length Error

```
Error: invalid public key length
```

X25519 public keys must be exactly 32 bytes. Verify the key extraction process.

### Archive Verification

To verify a CXP archive is valid:

```bash
# Check it's a valid ZIP
unzip -l vault.cxp

# Verify index.jwe exists
unzip -p vault.cxp index.jwe | head -c 100
```

## References

- [CXP Specification](https://fidoalliance.org/specs/cx/cxp-v1.0-wd-20240522.html)
- [RFC 9180: HPKE](https://www.rfc-editor.org/rfc/rfc9180.html)
- [RFC 7516: JWE](https://www.rfc-editor.org/rfc/rfc7516.html)
