package sources

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/crypto/ssh"

	"github.com/nvinuesa/cxporter/internal/model"
)

// SSHSource implements the Source interface for SSH private keys.
type SSHSource struct {
	dirPath     string
	opts        OpenOptions
	isOpen      bool
	credentials []model.Credential
}

// NewSSHSource creates a new SSH source adapter.
func NewSSHSource() *SSHSource {
	return &SSHSource{}
}

// Name returns the unique identifier for this source.
func (s *SSHSource) Name() string {
	return "ssh"
}

// Description returns a human-readable description.
func (s *SSHSource) Description() string {
	return "SSH private keys from filesystem"
}

// SupportedExtensions returns empty as SSH source works with directories.
func (s *SSHSource) SupportedExtensions() []string {
	return []string{} // Directory-based, not file extension based
}

// Detect checks if the given path contains SSH keys.
// Returns confidence 0-100 based on whether SSH keys are found.
func (s *SSHSource) Detect(path string) (int, error) {
	info, err := os.Stat(path)
	if err != nil {
		if os.IsNotExist(err) {
			return 0, &ErrFileNotFound{Path: path}
		}
		return 0, err
	}

	// Must be a directory
	if !info.IsDir() {
		return 0, nil
	}

	// Check for SSH key files
	entries, err := os.ReadDir(path)
	if err != nil {
		return 0, err
	}

	keyCount := 0
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		name := entry.Name()
		if isSSHPrivateKeyFilename(name) {
			keyCount++
		}
	}

	if keyCount == 0 {
		return 0, nil
	}

	// Higher confidence if it looks like ~/.ssh
	baseName := filepath.Base(path)
	if baseName == ".ssh" {
		return 100, nil
	}

	// Some confidence based on number of keys found
	confidence := 50 + min(keyCount*10, 40)
	return confidence, nil
}

// Open initializes the source with the given directory path.
func (s *SSHSource) Open(path string, opts OpenOptions) error {
	if s.isOpen {
		return ErrAlreadyOpen
	}

	info, err := os.Stat(path)
	if err != nil {
		if os.IsNotExist(err) {
			return &ErrFileNotFound{Path: path}
		}
		return &ErrPermissionDenied{Path: path, Op: "stat", Err: err}
	}

	if !info.IsDir() {
		return &ErrInvalidFormat{
			Source:  s.Name(),
			Path:    path,
			Details: "path must be a directory",
		}
	}

	s.dirPath = path
	s.opts = opts
	s.isOpen = true
	s.credentials = nil

	return nil
}

// Read discovers and parses all SSH keys in the directory.
func (s *SSHSource) Read() ([]model.Credential, error) {
	if !s.isOpen {
		return nil, ErrNotOpen
	}

	// Return cached results if available
	if s.credentials != nil {
		return s.credentials, nil
	}

	var credentials []model.Credential
	partialErr := &ErrPartialRead{
		Source: s.Name(),
	}

	// Walk directory
	walkFn := func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return nil // Skip files we can't access
		}

		// Skip directories in non-recursive mode
		if d.IsDir() {
			if path != s.dirPath && !s.opts.Recursive {
				return filepath.SkipDir
			}
			return nil
		}

		// Skip non-key files
		name := d.Name()
		if !isSSHPrivateKeyFilename(name) {
			return nil
		}

		// Skip hidden files unless explicitly included
		if strings.HasPrefix(name, ".") && !s.opts.IncludeHidden {
			return nil
		}

		partialErr.TotalItems++

		// Try to read and parse the key
		cred, err := s.parseKeyFile(path)
		if err != nil {
			partialErr.AddFailure(fmt.Sprintf("%s: %v", filepath.Base(path), err), err)
			return nil
		}

		credentials = append(credentials, *cred)
		partialErr.ReadItems++
		return nil
	}

	if err := filepath.WalkDir(s.dirPath, walkFn); err != nil {
		return nil, err
	}

	s.credentials = credentials

	if partialErr.HasFailures() {
		return credentials, partialErr
	}

	return credentials, nil
}

// Close releases resources.
func (s *SSHSource) Close() error {
	s.isOpen = false
	s.dirPath = ""
	s.credentials = nil
	return nil
}

// parseKeyFile reads and parses a single SSH private key file.
func (s *SSHSource) parseKeyFile(path string) (*model.Credential, error) {
	// Read file content
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read file: %w", err)
	}

	// Check if it looks like a PEM file
	if !strings.Contains(string(data), "-----BEGIN") {
		return nil, fmt.Errorf("not a PEM-encoded key")
	}

	// Get file info for timestamps
	info, err := os.Stat(path)
	if err != nil {
		return nil, err
	}

	// Try to parse the key
	privateKey, keyType, encrypted, err := parsePrivateKey(data, s.opts.Password, s.opts.PasswordFunc)
	if err != nil {
		return nil, err
	}

	// Derive public key
	publicKey, fingerprint, err := derivePublicKeyInfo(privateKey)
	if err != nil {
		return nil, fmt.Errorf("failed to derive public key: %w", err)
	}

	// Try to read comment from .pub file
	comment := readCommentFromPubFile(path)
	if comment == "" {
		comment = filepath.Base(path)
	}

	// Build credential
	cred := &model.Credential{
		ID:         generateKeyID(fingerprint),
		Type:       model.TypeSSHKey,
		Title:      comment,
		FolderPath: filepath.Dir(path),
		Created:    info.ModTime(), // Best we can do without parsing key metadata
		Modified:   info.ModTime(),
		SSHKey: &model.SSHKeyData{
			PrivateKey:  string(data),
			PublicKey:   publicKey,
			Fingerprint: fingerprint,
			KeyType:     model.SSHKeyType(keyType),
			Comment:     comment,
			Encrypted:   encrypted,
		},
	}

	return cred, nil
}

// parsePrivateKey attempts to parse a private key, handling encryption.
func parsePrivateKey(data []byte, password string, promptFunc func(string) (string, error)) (interface{}, string, bool, error) {
	// Check if the key is encrypted
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, "", false, fmt.Errorf("failed to decode PEM block")
	}

	encrypted := strings.Contains(block.Type, "ENCRYPTED") ||
		strings.Contains(string(block.Headers["Proc-Type"]), "ENCRYPTED")

	// Try to parse without password first
	signer, err := ssh.ParsePrivateKey(data)
	if err == nil {
		keyType := getKeyType(signer.PublicKey())
		return signer, keyType, false, nil
	}

	// Check if it's a passphrase error
	if !isPassphraseError(err) {
		return nil, "", encrypted, fmt.Errorf("failed to parse key: %w", err)
	}

	// Key is encrypted, try with password
	encrypted = true

	if password != "" {
		signer, err = ssh.ParsePrivateKeyWithPassphrase(data, []byte(password))
		if err == nil {
			keyType := getKeyType(signer.PublicKey())
			return signer, keyType, true, nil
		}
		if !isPassphraseError(err) {
			return nil, "", true, fmt.Errorf("failed to parse key: %w", err)
		}
		return nil, "", true, &ErrAuthenticationFailed{
			Source: "ssh",
			Path:   "",
			Reason: "wrong password",
			Err:    err,
		}
	}

	// Try interactive prompt
	if promptFunc != nil {
		passwd, err := promptFunc("Enter passphrase for SSH key: ")
		if err != nil {
			return nil, "", true, err
		}

		signer, err = ssh.ParsePrivateKeyWithPassphrase(data, []byte(passwd))
		if err != nil {
			if isPassphraseError(err) {
				return nil, "", true, &ErrAuthenticationFailed{
					Source: "ssh",
					Path:   "",
					Reason: "wrong password",
					Err:    err,
				}
			}
			return nil, "", true, fmt.Errorf("failed to parse key: %w", err)
		}

		keyType := getKeyType(signer.PublicKey())
		return signer, keyType, true, nil
	}

	return nil, "", true, &ErrAuthenticationFailed{
		Source: "ssh",
		Path:   "",
		Reason: "key is encrypted and no password provided",
	}
}

// derivePublicKeyInfo extracts the public key and fingerprint from a signer.
func derivePublicKeyInfo(key interface{}) (string, string, error) {
	var sshPubKey ssh.PublicKey
	var err error

	switch k := key.(type) {
	case ssh.Signer:
		sshPubKey = k.PublicKey()
	case *rsa.PrivateKey:
		sshPubKey, err = ssh.NewPublicKey(&k.PublicKey)
	case *ecdsa.PrivateKey:
		sshPubKey, err = ssh.NewPublicKey(&k.PublicKey)
	case ed25519.PrivateKey:
		sshPubKey, err = ssh.NewPublicKey(k.Public())
	default:
		return "", "", fmt.Errorf("unsupported key type: %T", key)
	}

	if err != nil {
		return "", "", err
	}

	// Format public key in OpenSSH format
	pubKeyStr := string(ssh.MarshalAuthorizedKey(sshPubKey))
	pubKeyStr = strings.TrimSpace(pubKeyStr)

	// Calculate fingerprint
	fingerprint := calculateFingerprint(sshPubKey)

	return pubKeyStr, fingerprint, nil
}

// calculateFingerprint computes the SHA256 fingerprint of a public key.
func calculateFingerprint(pubKey ssh.PublicKey) string {
	hash := sha256.Sum256(pubKey.Marshal())
	return "SHA256:" + base64.RawStdEncoding.EncodeToString(hash[:])
}

// getKeyType returns the key type string from a public key.
func getKeyType(pubKey ssh.PublicKey) string {
	keyType := pubKey.Type()
	switch keyType {
	case "ssh-ed25519":
		return "ed25519"
	case "ssh-rsa":
		return "rsa"
	case "ecdsa-sha2-nistp256", "ecdsa-sha2-nistp384", "ecdsa-sha2-nistp521":
		return "ecdsa"
	case "ssh-dss":
		return "dsa"
	default:
		return keyType
	}
}

// readCommentFromPubFile tries to read the comment from the corresponding .pub file.
func readCommentFromPubFile(privateKeyPath string) string {
	pubPath := privateKeyPath + ".pub"
	data, err := os.ReadFile(pubPath)
	if err != nil {
		return ""
	}

	// Public key format: type base64-key comment
	parts := strings.SplitN(strings.TrimSpace(string(data)), " ", 3)
	if len(parts) >= 3 {
		return parts[2]
	}

	return ""
}

// isSSHPrivateKeyFilename checks if a filename looks like an SSH private key.
func isSSHPrivateKeyFilename(name string) bool {
	// Skip public keys
	if strings.HasSuffix(name, ".pub") {
		return false
	}

	// Skip known non-key files
	skipFiles := []string{
		"known_hosts",
		"authorized_keys",
		"config",
		"environment",
	}
	for _, skip := range skipFiles {
		if name == skip {
			return false
		}
	}

	// Common private key patterns
	patterns := []string{
		"id_",      // id_rsa, id_ed25519, etc.
		"_key",     // some_key
		"identity", // identity file
	}

	nameLower := strings.ToLower(name)
	for _, p := range patterns {
		if strings.Contains(nameLower, p) {
			return true
		}
	}

	// Check for .pem extension
	if strings.HasSuffix(nameLower, ".pem") {
		return true
	}

	return false
}

// isPassphraseError checks if an error indicates a passphrase is needed.
func isPassphraseError(err error) bool {
	if err == nil {
		return false
	}
	errStr := strings.ToLower(err.Error())
	return strings.Contains(errStr, "passphrase") ||
		strings.Contains(errStr, "password") ||
		strings.Contains(errStr, "encrypted") ||
		strings.Contains(errStr, "decryption")
}

// generateKeyID creates a unique ID from a fingerprint.
func generateKeyID(fingerprint string) string {
	// Remove "SHA256:" prefix and use first 16 chars
	id := strings.TrimPrefix(fingerprint, "SHA256:")
	if len(id) > 16 {
		id = id[:16]
	}
	return "ssh-" + id
}

// init registers the SSH source with the default registry.
func init() {
	RegisterDefault(NewSSHSource())
}

// Helper for go 1.21+
func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// Ensure SSHSource implements Source interface
var _ Source = (*SSHSource)(nil)
