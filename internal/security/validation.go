// Package security provides input validation utilities.
package security

import (
	"fmt"
	"path/filepath"
	"strings"
	"unicode"
)

// Input size limits to prevent DoS attacks
const (
	MaxTitleLength       = 1024
	MaxUsernameLength    = 512
	MaxPasswordLength    = 1024
	MaxURLLength         = 2048
	MaxNotesLength       = 65536
	MaxCustomFieldKey    = 256
	MaxCustomFieldValue  = 8192
	MaxTagLength         = 128
	MaxTagCount          = 100
	MaxFolderPathLength  = 2048
	MaxAttachmentSize    = 10 * 1024 * 1024 // 10 MB
	MaxAttachmentCount   = 100
	MaxCredentialIDLength = 256
)

// ValidateStringLength validates that a string is within allowed length.
func ValidateStringLength(s string, maxLen int, fieldName string) error {
	if len(s) > maxLen {
		return fmt.Errorf("%s exceeds maximum length of %d bytes", fieldName, maxLen)
	}
	return nil
}

// SanitizeString removes dangerous characters from a string.
func SanitizeString(s string) string {
	// Remove null bytes and most control characters
	return strings.Map(func(r rune) rune {
		// Allow tab, newline, carriage return
		if r == '\t' || r == '\n' || r == '\r' {
			return r
		}
		// Remove null and other control characters
		if r == 0 || (r < 32) {
			return -1
		}
		// Remove other potentially dangerous Unicode
		if r == '\ufeff' { // BOM
			return -1
		}
		return r
	}, strings.TrimSpace(s))
}

// ValidateCredentialID ensures a credential ID is safe and valid.
func ValidateCredentialID(id string) error {
	if id == "" {
		return fmt.Errorf("credential ID cannot be empty")
	}
	
	if err := ValidateStringLength(id, MaxCredentialIDLength, "credential ID"); err != nil {
		return err
	}
	
	// Disallow path separators and dangerous characters
	if strings.ContainsAny(id, "/\\:*?\"<>|") {
		return fmt.Errorf("credential ID contains invalid characters")
	}
	
	// Disallow parent directory references
	if strings.Contains(id, "..") {
		return fmt.Errorf("credential ID cannot contain '..'")
	}
	
	return nil
}

// ValidateFilePath ensures a file path is safe (no traversal).
func ValidateFilePath(path string, allowAbsolute bool) error {
	if path == "" {
		return fmt.Errorf("path cannot be empty")
	}
	
	// Clean the path
	cleaned := filepath.Clean(path)
	
	// Check for path traversal
	if strings.Contains(cleaned, "..") {
		return fmt.Errorf("path contains parent directory reference")
	}
	
	// Check for absolute paths if not allowed
	if !allowAbsolute && filepath.IsAbs(cleaned) {
		return fmt.Errorf("absolute paths not allowed")
	}
	
	return nil
}

// ValidateRelativePath ensures a path is relative and safe.
func ValidateRelativePath(path, baseDir string) error {
	if err := ValidateFilePath(path, false); err != nil {
		return err
	}
	
	// Ensure the path would be within baseDir
	fullPath := filepath.Join(baseDir, path)
	cleanedFull := filepath.Clean(fullPath)
	cleanedBase := filepath.Clean(baseDir)
	
	// Check if cleanedFull starts with cleanedBase
	relPath, err := filepath.Rel(cleanedBase, cleanedFull)
	if err != nil {
		return fmt.Errorf("invalid path relationship: %w", err)
	}
	
	if strings.HasPrefix(relPath, "..") {
		return fmt.Errorf("path escapes base directory")
	}
	
	return nil
}

// ValidateURL performs basic URL validation.
func ValidateURL(urlStr string) error {
	if err := ValidateStringLength(urlStr, MaxURLLength, "URL"); err != nil {
		return err
	}
	
	// Basic validation - just check for common issues
	if strings.Contains(urlStr, "\x00") {
		return fmt.Errorf("URL contains null byte")
	}
	
	return nil
}

// ValidateDomainName validates a domain name format.
func ValidateDomainName(domain string) error {
	if domain == "" {
		return fmt.Errorf("domain cannot be empty")
	}
	
	if len(domain) > 253 {
		return fmt.Errorf("domain exceeds maximum length of 253")
	}
	
	// Split into labels
	labels := strings.Split(domain, ".")
	if len(labels) < 1 {
		return fmt.Errorf("invalid domain format")
	}
	
	for _, label := range labels {
		if len(label) == 0 || len(label) > 63 {
			return fmt.Errorf("domain label length must be 1-63 characters")
		}
		
		// Check label characters
		for i, r := range label {
			if !unicode.IsLetter(r) && !unicode.IsDigit(r) && r != '-' {
				return fmt.Errorf("invalid character in domain label: %c", r)
			}
			// Hyphen cannot be first or last
			if r == '-' && (i == 0 || i == len(label)-1) {
				return fmt.Errorf("domain label cannot start or end with hyphen")
			}
		}
	}
	
	return nil
}

// ValidateRPID validates a relying party identifier.
func ValidateRPID(rpID string) error {
	if rpID == "" {
		return fmt.Errorf("RP ID cannot be empty")
	}
	
	// RP ID should be a valid domain or reverse domain notation
	// For simplicity, we validate as a domain
	return ValidateDomainName(rpID)
}

// ValidateAttachmentSize validates attachment size.
func ValidateAttachmentSize(size int) error {
	if size < 0 {
		return fmt.Errorf("attachment size cannot be negative")
	}
	if size > MaxAttachmentSize {
		return fmt.Errorf("attachment exceeds maximum size of %d bytes", MaxAttachmentSize)
	}
	return nil
}

// ValidateCollectionCount validates the number of collections.
func ValidateCollectionCount(count int) error {
	const maxCollections = 1000
	if count > maxCollections {
		return fmt.Errorf("too many collections: %d (max %d)", count, maxCollections)
	}
	return nil
}

// ValidateItemCount validates the number of items.
func ValidateItemCount(count int) error {
	const maxItems = 100000
	if count > maxItems {
		return fmt.Errorf("too many items: %d (max %d)", count, maxItems)
	}
	return nil
}

// HasDangerousFileExtension checks if a filename has a dangerous extension.
func HasDangerousFileExtension(filename string) bool {
	dangerousExts := []string{
		".exe", ".dll", ".so", ".dylib",
		".sh", ".bat", ".cmd", ".ps1",
		".app", ".deb", ".rpm", ".msi",
		".vbs", ".js", ".jar", ".apk",
	}
	
	lowerName := strings.ToLower(filename)
	for _, ext := range dangerousExts {
		if strings.HasSuffix(lowerName, ext) {
			return true
		}
	}
	return false
}
