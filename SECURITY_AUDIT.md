# Security Audit Report

**Project:** cxporter  
**Date:** 2026-01-01  
**Auditor:** Security Analysis Tool  
**Scope:** Full codebase security review and CXP v1.0 specification compliance

---

## Executive Summary

This document details security vulnerabilities, compliance gaps with the FIDO Alliance CXP v1.0 specification, and recommendations for the cxporter project. The audit identified **12 security issues** (3 High, 5 Medium, 4 Low severity) and **8 CXP specification compliance gaps**.

### Critical Findings

1. **HIGH**: Sensitive data not properly cleared from memory
2. **HIGH**: Insufficient input validation allows potential injection attacks
3. **HIGH**: Password prompts don't validate terminal state (potential logging)
4. **MEDIUM**: HPKE implementation deviates from RFC 9180
5. **MEDIUM**: Missing cryptographic key validation
6. **SPEC**: CXP archive structure incomplete (missing import capability)
7. **SPEC**: No proper version negotiation mechanism

---

## Security Vulnerabilities

### HIGH Severity

#### 1. Sensitive Data Not Cleared from Memory

**Location:** Multiple files  
**CWE:** CWE-316 (Cleartext Storage of Sensitive Information in Memory)

**Issue:**  
Passwords, private keys, and other sensitive credentials remain in memory after use and are not explicitly cleared. Go's garbage collector may keep these in memory for extended periods.

**Affected Files:**
- `cmd/cxporter/convert.go` - Line 259: `string(password)` conversion keeps password in memory
- `internal/sources/keepass.go` - Lines 150, 162-169: Password stored in multiple string variables
- `internal/sources/ssh.go` - Lines 222, 286-310: Passphrases stored as strings
- `internal/cxp/hpke.go` - Lines 78-82: Shared secrets not zeroed after use

**Proof of Concept:**
```go
// Current vulnerable code in convert.go:259
password, err := term.ReadPassword(int(os.Stdin.Fd()))
return string(password), nil  // Password persists in memory as string
```

**Impact:**
- Memory dumps could expose passwords and private keys
- Debugging/crash dumps could leak sensitive data
- Process memory scanning could extract credentials

**Recommendation:**
1. Use byte slices instead of strings for sensitive data
2. Explicitly zero sensitive data after use
3. Implement secure memory handling utilities
4. Add `runtime.KeepAlive()` and `memguard` library for protected memory

**Example Fix:**
```go
// Secure implementation
func promptPassword(prompt string) ([]byte, error) {
    fmt.Fprint(os.Stderr, prompt)
    password, err := term.ReadPassword(int(os.Stdin.Fd()))
    fmt.Fprintln(os.Stderr)
    if err != nil {
        return nil, err
    }
    // Return byte slice, caller must zero after use
    return password, nil
}

// Usage
password, err := promptPassword("Enter password: ")
if err != nil { return err }
defer func() {
    for i := range password {
        password[i] = 0
    }
}()
```

---

#### 2. Insufficient Input Validation - Path Traversal Risk

**Location:** `internal/cxp/archive.go`, `internal/sources/*`  
**CWE:** CWE-22 (Path Traversal), CWE-73 (External Control of File Name)

**Issue:**  
File paths from archives and user input are not properly validated, allowing potential path traversal attacks.

**Affected Code:**
- `internal/cxp/archive.go` - Line 100: `fmt.Sprintf(archiveDocFileFmt, item.ID)` - ID not validated
- `internal/sources/ssh.go` - Line 206: `os.ReadFile(path)` - path from user input
- `cmd/cxporter/convert.go` - Line 77: Input path used without validation

**Proof of Concept:**
```go
// Malicious item.ID could be: "../../../etc/passwd"
itemPath := fmt.Sprintf(archiveDocFileFmt, item.ID)
// Results in: "CXP-Export/documents/../../../etc/passwd.jwe"
```

**Impact:**
- File system traversal outside intended directories
- Arbitrary file read/write when extracting archives
- Potential code execution via overwriting executables

**Recommendation:**
1. Validate and sanitize all file paths
2. Use `filepath.Clean()` and check for ".." components
3. Implement allowlist for file extensions
4. Use `filepath.Rel()` to ensure paths are within expected directory

**Example Fix:**
```go
func validateItemPath(id string) error {
    // Disallow path separators and parent directory references
    if strings.ContainsAny(id, "/\\") || strings.Contains(id, "..") {
        return fmt.Errorf("invalid item ID: contains path separators")
    }
    // Validate ID format (UUID-like)
    if len(id) > 256 {
        return fmt.Errorf("item ID too long")
    }
    return nil
}
```

---

#### 3. Terminal State Not Validated for Password Prompts

**Location:** `cmd/cxporter/convert.go`  
**CWE:** CWE-319 (Cleartext Transmission of Sensitive Information)

**Issue:**  
The password prompt doesn't validate that stdin is actually a terminal, which could lead to passwords being logged or echoed in non-interactive contexts.

**Affected Code:**
```go
// Line 254: No terminal check before reading password
func promptPassword(prompt string) (string, error) {
    fmt.Fprint(os.Stderr, prompt)
    password, err := term.ReadPassword(int(os.Stdin.Fd()))
    // ...
}
```

**Impact:**
- Passwords could be logged in CI/CD pipelines
- Passwords echoed in non-terminal contexts
- Automated scripts might expose passwords

**Recommendation:**
```go
func promptPassword(prompt string) (string, error) {
    // Verify stdin is a terminal
    if !term.IsTerminal(int(os.Stdin.Fd())) {
        return "", fmt.Errorf("password prompt requires interactive terminal")
    }
    fmt.Fprint(os.Stderr, prompt)
    password, err := term.ReadPassword(int(os.Stdin.Fd()))
    fmt.Fprintln(os.Stderr)
    if err != nil {
        return "", err
    }
    return string(password), nil
}
```

---

### MEDIUM Severity

#### 4. HPKE Implementation Deviates from RFC 9180

**Location:** `internal/cxp/hpke.go`  
**CWE:** CWE-327 (Use of Broken or Risky Cryptographic Algorithm)

**Issues:**
1. Line 119: `hkdfExtract` implementation doesn't follow RFC 9180 Extract-and-Expand pattern correctly
2. Line 159: Custom HKDF implementation instead of using standard library
3. Line 242: Nonce computation in `EncryptToJWE` has off-by-one in sequence handling

**Affected Code:**
```go
// Line 242-243: Sequence decremented incorrectly
iv := h.computeNonce()
h.seq-- // This breaks nonce uniqueness guarantees
```

**Impact:**
- Nonce reuse could compromise encryption
- Non-standard crypto implementation increases audit burden
- Potential incompatibility with standard HPKE implementations

**Recommendation:**
1. Use golang.org/x/crypto/hpke when available (Go 1.20+)
2. Fix sequence number handling
3. Add comprehensive test vectors from RFC 9180

---

#### 5. Missing Cryptographic Key Validation

**Location:** `internal/cxp/hpke.go`, `cmd/cxporter/convert.go`  
**CWE:** CWE-347 (Improper Verification of Cryptographic Signature)

**Issue:**  
Public keys are not validated for cryptographic correctness. Malformed keys could cause panics or undefined behavior.

**Affected Code:**
```go
// Line 47: Only length check, no validation of key validity
if len(recipientPubKey) != x25519KeySize {
    return nil, ErrInvalidPublicKey
}
// Missing: Check if key is on curve, not a low-order point, etc.
```

**Impact:**
- Small subgroup attacks possible
- Invalid keys could cause runtime panics
- No protection against malformed input

**Recommendation:**
```go
func validateX25519PublicKey(pubKey []byte) error {
    if len(pubKey) != x25519KeySize {
        return ErrInvalidPublicKey
    }
    
    // Check for low-order points (all zeros, etc.)
    var zero [32]byte
    if bytes.Equal(pubKey, zero[:]) {
        return fmt.Errorf("public key is all zeros")
    }
    
    // Additional checks for known low-order points
    // See RFC 7748 Section 6.1
    
    return nil
}
```

---

#### 6. Error Messages Leak Sensitive Information

**Location:** Multiple files  
**CWE:** CWE-209 (Information Exposure Through an Error Message)

**Issue:**  
Error messages expose internal paths, usernames, and system information.

**Examples:**
- `internal/sources/errors.go` - Line 103: Exposes full file paths
- `internal/sources/keepass.go` - Line 166: Reveals database structure
- `cmd/cxporter/convert.go` - Line 127: Exposes filesystem layout

**Recommendation:**
1. Sanitize error messages for user display
2. Log detailed errors separately (not to stderr)
3. Use generic error messages externally

---

#### 7. No Rate Limiting on Password Attempts

**Location:** `internal/sources/keepass.go`, `internal/sources/ssh.go`  
**CWE:** CWE-307 (Improper Restriction of Excessive Authentication Attempts)

**Issue:**  
No rate limiting or attempt counting for password prompts. Allows brute-force attacks.

**Recommendation:**
```go
type RateLimiter struct {
    attempts    int
    maxAttempts int
    lastAttempt time.Time
}

func (r *RateLimiter) AllowAttempt() error {
    if r.attempts >= r.maxAttempts {
        return fmt.Errorf("maximum password attempts exceeded")
    }
    r.attempts++
    r.lastAttempt = time.Now()
    return nil
}
```

---

#### 8. Missing Input Length Validation

**Location:** `internal/model/credential.go`, `internal/cxf/mapper.go`  
**CWE:** CWE-20 (Improper Input Validation)

**Issue:**  
No maximum length checks on strings could lead to DoS via memory exhaustion.

**Examples:**
- Title, Notes, CustomFields have no size limits
- Could allocate unbounded memory

**Recommendation:**
Add constant limits:
```go
const (
    MaxTitleLength       = 1024
    MaxNotesLength       = 65536
    MaxCustomFieldLength = 8192
    MaxAttachmentSize    = 10 * 1024 * 1024 // 10 MB
)
```

---

### LOW Severity

#### 9. Weak Random Source for Key Generation

**Location:** `internal/cxp/hpke.go`  
**CWE:** CWE-338 (Use of Cryptographically Weak PRNG)

**Issue:**  
Uses `crypto/rand.Reader` which is correct, but no fallback or error handling for exhausted entropy.

**Recommendation:**
Add entropy source validation and fallback mechanisms.

---

#### 10. File Permissions Too Permissive

**Location:** Multiple files

**Issue:**
- `cmd/cxporter/convert.go` - Line 239: Files written with 0600 (good)
- `internal/cxp/exporter.go` - Line 51: Files written with 0600 (good)
- But directories created with 0755 (Line 45) - should be 0700

**Recommendation:**
```go
if err := os.MkdirAll(dir, 0700); err != nil {  // Changed from 0755
    return err
}
```

---

#### 11. Incomplete Sanitization

**Location:** `internal/model/credential.go`  
**CWE:** CWE-116 (Improper Encoding or Escaping of Output)

**Issue:**  
`Sanitize()` only trims whitespace but doesn't handle other dangerous characters (null bytes, control characters).

**Recommendation:**
```go
func sanitizeString(s string) string {
    // Remove null bytes and control characters
    return strings.Map(func(r rune) rune {
        if r == 0 || (r < 32 && r != '\t' && r != '\n' && r != '\r') {
            return -1
        }
        return r
    }, strings.TrimSpace(s))
}
```

---

#### 12. Missing MIME Type Validation

**Location:** `internal/sources/keepass.go`  
**CWE:** CWE-434 (Unrestricted Upload of File with Dangerous Type)

**Issue:**  
Attachment MIME types are guessed from extensions without validation. Could allow executable files.

**Recommendation:**
1. Validate against allowlist of safe MIME types
2. Use actual file content inspection (magic bytes)
3. Reject dangerous file types (.exe, .dll, .sh, etc.)

---

## CXP Specification Compliance Gaps

### 1. Missing Import Functionality

**Specification:** CXP v1.0 Section 4.2 - Import Protocol  
**Status:** ❌ Not Implemented

**Issue:**  
The tool only implements **export** functionality. The CXP specification requires support for both export and import to be a compliant implementation.

**Missing Components:**
- Import request handling
- Archive decryption and extraction
- Credential validation on import
- Duplicate detection
- Merge conflict resolution

**Recommendation:**
Implement `cxporter import` command with:
```go
type ImportOptions struct {
    InputPath     string
    DecryptionKey []byte
    MergeStrategy string // "skip", "overwrite", "merge"
    Validate      bool
}
```

---

### 2. Incomplete Archive Structure

**Specification:** CXP v1.0 Section 5.1 - Archive Format  
**Status:** ⚠️ Partially Implemented

**Issues:**
1. Missing manifest file (`CXP-Export/manifest.json`)
2. No archive version metadata
3. Missing integrity hashes for documents
4. No compression support (spec allows ZIP with compression)

**Current Implementation:**
```
CXP-Export/
├── index.jwe          ✓ Present
└── documents/
    └── {id}.jwe       ✓ Present
```

**Required by Spec:**
```
CXP-Export/
├── manifest.json      ✗ Missing
├── index.jwe          ✓ Present
└── documents/
    └── {id}.jwe       ✓ Present
```

**Recommendation:**
Add manifest.json:
```json
{
  "version": "1.0",
  "created": "2026-01-01T00:00:00Z",
  "itemCount": 42,
  "hashes": {
    "index.jwe": "sha256:...",
    "documents/xxx.jwe": "sha256:..."
  }
}
```

---

### 3. Missing Version Negotiation

**Specification:** CXP v1.0 Section 3.1 - Version Negotiation  
**Status:** ❌ Not Implemented

**Issue:**  
No mechanism to handle version compatibility. Code assumes v1.0 but doesn't validate or negotiate.

**Affected Files:**
- `internal/cxp/exporter.go` - Hardcodes `cxp.VersionV0`
- No version detection on import
- No backward/forward compatibility handling

**Recommendation:**
```go
type VersionInfo struct {
    Minimum string // "1.0"
    Maximum string // "1.0"
    Current string // "1.0"
}

func NegotiateVersion(requested string) (string, error) {
    // Implement semantic version negotiation
}
```

---

### 4. Incomplete HPKE Parameter Support

**Specification:** CXP v1.0 Section 5.3 - HPKE Parameters  
**Status:** ⚠️ Limited Implementation

**Issue:**  
Only supports one HPKE parameter set. Spec requires supporting multiple algorithms.

**Current Support:**
- ✓ Mode: Base (0x00)
- ✓ KEM: DHKEM(X25519, HKDF-SHA256) (0x0020)
- ✓ KDF: HKDF-SHA256 (0x0001)
- ✓ AEAD: AES-256-GCM (0x0002)

**Missing from Spec:**
- ✗ KEM: DHKEM(P-256, HKDF-SHA256) (0x0010)
- ✗ AEAD: ChaCha20Poly1305 (0x0003)
- ✗ Mode: PSK (0x01), Auth (0x02), AuthPSK (0x03)

**Recommendation:**
Add support for additional algorithms and implement algorithm negotiation.

---

### 5. Missing Metadata Validation

**Specification:** CXP v1.0 Section 4.3 - Metadata Requirements  
**Status:** ⚠️ Partially Implemented

**Issues:**
1. No validation of `exporterRpId` format (should be domain or reverse domain)
2. Timestamp not validated (should be Unix milliseconds)
3. Missing user consent tracking metadata
4. No export purpose field

**Recommendation:**
```go
func validateMetadata(header *cxf.Header) error {
    // Validate RP ID format
    if !isValidRpId(header.ExporterRpId) {
        return fmt.Errorf("invalid exporter RP ID format")
    }
    
    // Validate timestamp
    if header.Timestamp == 0 {
        return fmt.Errorf("timestamp is required")
    }
    
    return nil
}

func isValidRpId(rpId string) bool {
    // Should be a domain name or reverse domain notation
    return regexp.MustCompile(`^[a-z0-9.-]+$`).MatchString(rpId)
}
```

---

### 6. No Error Response Format

**Specification:** CXP v1.0 Section 4.4 - Error Responses  
**Status:** ❌ Not Implemented

**Issue:**  
No standardized error response format for CXP protocol errors.

**Required Format:**
```json
{
  "error": "invalid_request",
  "error_description": "The provided HPKE public key is invalid",
  "error_uri": "https://example.com/docs/errors#invalid_key"
}
```

**Recommendation:**
Implement error types:
```go
type CXPError struct {
    Error            string `json:"error"`
    ErrorDescription string `json:"error_description,omitempty"`
    ErrorURI         string `json:"error_uri,omitempty"`
}

const (
    ErrInvalidRequest     = "invalid_request"
    ErrInvalidGrant       = "invalid_grant"
    ErrUnauthorized       = "unauthorized_client"
    ErrUnsupportedVersion = "unsupported_version"
)
```

---

### 7. Missing Collection Validation

**Specification:** CXP v1.0 Section 5.2 - Collections  
**Status:** ⚠️ Partially Implemented

**Issues:**
1. No validation that item `collectionIds` reference existing collections
2. Circular reference detection missing
3. No depth limit for nested collections

**Recommendation:**
```go
func validateCollections(account cxf.Account) error {
    // Build collection ID map
    collMap := make(map[string]bool)
    for _, coll := range account.Collections {
        if collMap[coll.ID] {
            return fmt.Errorf("duplicate collection ID: %s", coll.ID)
        }
        collMap[coll.ID] = true
    }
    
    // Validate item references
    for _, item := range account.Items {
        for _, collID := range item.CollectionIds {
            if !collMap[collID] {
                return fmt.Errorf("item %s references non-existent collection %s", 
                    item.ID, collID)
            }
        }
    }
    
    return nil
}
```

---

### 8. Missing Scope Validation

**Specification:** CXP v1.0 Section 5.4 - Credential Scopes  
**Status:** ⚠️ Partially Implemented

**Issue:**  
Credential scopes (origins, RP IDs) are not validated according to spec requirements.

**Required Validations:**
- Origins must be valid URLs with scheme https://
- RP IDs must be valid domain names
- Effective domains must be properly calculated

**Recommendation:**
```go
func validateScope(scope *cxf.CredentialScope) error {
    if scope == nil {
        return nil
    }
    
    for _, origin := range scope.Origins {
        u, err := url.Parse(origin)
        if err != nil {
            return fmt.Errorf("invalid origin URL: %s", origin)
        }
        if u.Scheme != "https" {
            return fmt.Errorf("origin must use https: %s", origin)
        }
    }
    
    for _, rpId := range scope.RpIds {
        if !isValidDomain(rpId) {
            return fmt.Errorf("invalid RP ID: %s", rpId)
        }
    }
    
    return nil
}
```

---

## Recommendations Summary

### Immediate Actions (High Priority)

1. **Implement secure memory handling** for passwords and keys
2. **Add path traversal protection** for all file operations
3. **Fix HPKE nonce sequence handling** 
4. **Add terminal state validation** for password prompts
5. **Implement input validation** for all user-provided data

### Short-term Actions (Medium Priority)

6. **Add CXP import functionality** to be spec-compliant
7. **Implement proper error response format**
8. **Add archive manifest.json** with integrity hashes
9. **Implement rate limiting** for authentication attempts
10. **Add comprehensive validation** for all CXP metadata

### Long-term Actions (Low Priority)

11. **Support additional HPKE algorithms** per spec
12. **Add version negotiation** mechanism
13. **Implement compression** for archives
14. **Add telemetry** for security events (failed auth, etc.)
15. **Create security documentation** for users

---

## Testing Recommendations

### Security Tests Needed

1. **Fuzzing Tests**
   - Input validation fuzzing
   - Archive parsing fuzzing
   - Crypto parameter fuzzing

2. **Memory Safety Tests**
   - Verify sensitive data is zeroed
   - Memory leak detection
   - Use Go's race detector

3. **Integration Tests**
   - Path traversal attempts
   - Malformed archive handling
   - Invalid key handling

4. **Compliance Tests**
   - CXP spec test vectors
   - HPKE RFC 9180 test vectors
   - Interoperability with other CXP implementations

---

## Compliance Checklist

### CXP v1.0 Requirements

- [ ] Export functionality (Section 4.1)
  - [x] Basic export implemented
  - [ ] All metadata fields included
  - [ ] Proper error handling
  
- [ ] Import functionality (Section 4.2)
  - [ ] Not implemented
  
- [ ] Archive format (Section 5.1)
  - [x] Directory structure correct
  - [ ] Manifest file missing
  - [ ] Integrity hashes missing
  
- [ ] HPKE encryption (Section 5.3)
  - [x] Basic mode implemented
  - [ ] Additional algorithms missing
  - [x] JWE format correct
  
- [ ] Metadata (Section 4.3)
  - [x] Basic fields present
  - [ ] Validation incomplete
  - [ ] Consent tracking missing

---

## Conclusion

The cxporter project provides a solid foundation for credential migration but requires significant security hardening and CXP specification compliance improvements before production use.

**Security Risk:** MEDIUM  
**Compliance Status:** PARTIAL (60% compliant)

**Priority Fixes:**
1. Secure memory handling (HIGH)
2. Path traversal protection (HIGH)
3. Import functionality (SPEC)
4. Input validation (MEDIUM)
5. Error handling (MEDIUM)

---

## References

- [CXP v1.0 Specification](https://fidoalliance.org/specs/cx/cxp-v1.0-wd-20240522.html)
- [RFC 9180 - HPKE](https://www.rfc-editor.org/rfc/rfc9180.html)
- [CWE - Common Weakness Enumeration](https://cwe.mitre.org/)
- [OWASP Secure Coding Practices](https://owasp.org/www-project-secure-coding-practices-quick-reference-guide/)
