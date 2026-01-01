package sources

import (
	"encoding/base64"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/tobischo/gokeepasslib/v3"
	"github.com/tobischo/gokeepasslib/v3/wrappers"

	"github.com/nvinuesa/cxporter/internal/model"
)

// KeePass file signature (first 4 bytes).
var kdbxSignature = []byte{0x03, 0xd9, 0xa2, 0x9a}

// KeePassSource implements the Source interface for KeePass .kdbx files.
//
// Security Note: This implementation uses gokeepasslib which relies on
// Go's standard library encoding/xml for XML parsing. Go's XML parser is safe from
// XML External Entity (XXE) attacks by design - it does not resolve external entities
// or support DTD processing. See: https://github.com/golang/go/issues/14107
type KeePassSource struct {
	filePath    string
	opts        OpenOptions
	db          *gokeepasslib.Database
	isOpen      bool
	credentials []model.Credential
}

// NewKeePassSource creates a new KeePass source adapter.
func NewKeePassSource() *KeePassSource {
	return &KeePassSource{}
}

// Name returns the unique identifier for this source.
func (s *KeePassSource) Name() string {
	return "keepass"
}

// Description returns a human-readable description.
func (s *KeePassSource) Description() string {
	return "KeePass 2.x database files (.kdbx)"
}

// SupportedExtensions returns file extensions this source handles.
func (s *KeePassSource) SupportedExtensions() []string {
	return []string{".kdbx"}
}

// Detect checks if the given path is a KeePass database.
func (s *KeePassSource) Detect(path string) (int, error) {
	info, err := os.Stat(path)
	if err != nil {
		if os.IsNotExist(err) {
			return 0, &ErrFileNotFound{Path: path}
		}
		return 0, err
	}

	if info.IsDir() {
		return 0, nil
	}

	// Check extension
	ext := strings.ToLower(filepath.Ext(path))
	if ext != ".kdbx" {
		return 0, nil
	}

	// Check file signature
	f, err := os.Open(path)
	if err != nil {
		return 0, err
	}
	defer f.Close()

	sig := make([]byte, 4)
	if _, err := f.Read(sig); err != nil {
		return 0, nil
	}

	// Compare signature
	for i := 0; i < 4; i++ {
		if sig[i] != kdbxSignature[i] {
			return 0, nil
		}
	}

	return 100, nil // Definite match
}

// Open initializes the source with the given file path and options.
func (s *KeePassSource) Open(path string, opts OpenOptions) error {
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

	if info.IsDir() {
		return &ErrInvalidFormat{
			Source:  s.Name(),
			Path:    path,
			Details: "path must be a file, not a directory",
		}
	}

	// Get password
	password := opts.Password
	if password == "" && opts.Interactive && opts.PasswordFunc != nil {
		var err error
		password, err = opts.PasswordFunc("Enter KeePass database password: ")
		if err != nil {
			return err
		}
	}

	// Open and decrypt the database
	f, err := os.Open(path)
	if err != nil {
		return &ErrPermissionDenied{Path: path, Op: "open", Err: err}
	}
	defer f.Close()

	db := gokeepasslib.NewDatabase()

	// Set credentials
	if opts.KeyFilePath != "" {
		keyData, err := os.ReadFile(opts.KeyFilePath)
		if err != nil {
			return &ErrFileNotFound{Path: opts.KeyFilePath}
		}
		creds, err := gokeepasslib.NewPasswordAndKeyDataCredentials(password, keyData)
		if err != nil {
			return &ErrInvalidFormat{
				Source:  s.Name(),
				Path:    opts.KeyFilePath,
				Details: "failed to parse key file",
				Err:     err,
			}
		}
		db.Credentials = creds
	} else {
		db.Credentials = gokeepasslib.NewPasswordCredentials(password)
	}

	// Decode the database
	if err := gokeepasslib.NewDecoder(f).Decode(db); err != nil {
		// Check if it's an authentication error
		errStr := strings.ToLower(err.Error())
		if strings.Contains(errStr, "password") ||
			strings.Contains(errStr, "credential") ||
			strings.Contains(errStr, "invalid") ||
			strings.Contains(errStr, "hmac") {
			return &ErrAuthenticationFailed{
				Source: s.Name(),
				Path:   path,
				Reason: "incorrect password or key file",
				Err:    err,
			}
		}
		return &ErrInvalidFormat{
			Source:  s.Name(),
			Path:    path,
			Details: "failed to decode database",
			Err:     err,
		}
	}

	// Unlock protected entries
	if err := db.UnlockProtectedEntries(); err != nil {
		return &ErrInvalidFormat{
			Source:  s.Name(),
			Path:    path,
			Details: "failed to unlock protected entries",
			Err:     err,
		}
	}

	s.filePath = path
	s.opts = opts
	s.db = db
	s.isOpen = true
	s.credentials = nil

	return nil
}

// Read extracts all entries from the KeePass database.
func (s *KeePassSource) Read() ([]model.Credential, error) {
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

	// Process all groups recursively
	for _, group := range s.db.Content.Root.Groups {
		creds, err := s.processGroup(group, "", partialErr)
		if err != nil {
			return nil, err
		}
		credentials = append(credentials, creds...)
	}

	s.credentials = credentials

	if partialErr.HasFailures() {
		return credentials, partialErr
	}

	return credentials, nil
}

// Close releases resources and locks protected entries.
func (s *KeePassSource) Close() error {
	if s.db != nil {
		// Lock protected entries to clear sensitive data
		_ = s.db.LockProtectedEntries()
	}

	s.isOpen = false
	s.filePath = ""
	s.db = nil
	s.credentials = nil
	return nil
}

// processGroup recursively processes a group and its entries.
func (s *KeePassSource) processGroup(group gokeepasslib.Group, parentPath string, partialErr *ErrPartialRead) ([]model.Credential, error) {
	var credentials []model.Credential

	// Build current path
	currentPath := group.Name
	if parentPath != "" {
		currentPath = parentPath + "/" + group.Name
	}

	// Process entries in this group
	for _, entry := range group.Entries {
		partialErr.TotalItems++

		cred, err := s.convertEntry(entry, currentPath)
		if err != nil {
			title := entry.GetTitle()
			partialErr.AddFailure(fmt.Sprintf("Entry '%s': %v", title, err), err)
			continue
		}

		if cred != nil {
			credentials = append(credentials, *cred)
			partialErr.ReadItems++
		}
	}

	// Process subgroups
	for _, subgroup := range group.Groups {
		creds, err := s.processGroup(subgroup, currentPath, partialErr)
		if err != nil {
			return nil, err
		}
		credentials = append(credentials, creds...)
	}

	return credentials, nil
}

// convertEntry converts a KeePass entry to a model.Credential.
func (s *KeePassSource) convertEntry(entry gokeepasslib.Entry, folderPath string) (*model.Credential, error) {
	// Get basic fields
	title := entry.GetTitle()
	username := entry.GetContent("UserName")
	password := entry.GetPassword()
	urlStr := entry.GetContent("URL")
	notes := entry.GetContent("Notes")

	// Skip empty entries
	if title == "" && username == "" && password == "" && urlStr == "" && notes == "" {
		return nil, nil
	}

	// Generate ID from UUID
	id := base64.RawURLEncoding.EncodeToString(entry.UUID[:])

	// Parse timestamps
	created := parseKeePassTime(entry.Times.CreationTime)
	modified := parseKeePassTime(entry.Times.LastModificationTime)

	// Parse tags
	var tags []string
	if entry.Tags != "" {
		for _, tag := range strings.Split(entry.Tags, ",") {
			tag = strings.TrimSpace(tag)
			if tag != "" {
				tags = append(tags, tag)
			}
		}
	}

	// Build credential
	cred := &model.Credential{
		ID:           id,
		Type:         model.TypeBasicAuth,
		Title:        title,
		Username:     username,
		Password:     password,
		URL:          urlStr,
		Notes:        notes,
		Tags:         tags,
		FolderPath:   folderPath,
		Created:      created,
		Modified:     modified,
		CustomFields: make(map[string]string),
	}

	// Extract custom fields and check for TOTP
	var totpData *model.TOTPData
	for _, value := range entry.Values {
		key := value.Key

		// Skip standard fields
		if key == "Title" || key == "UserName" || key == "Password" || key == "URL" || key == "Notes" {
			continue
		}

		content := value.Value.Content

		// Check for TOTP fields
		keyLower := strings.ToLower(key)
		if keyLower == "otp" || keyLower == "totp" || keyLower == "2fa" ||
			strings.Contains(keyLower, "authenticator") {
			if strings.HasPrefix(content, "otpauth://") {
				totp, err := parseOTPAuthURI(content)
				if err == nil {
					totpData = totp
				}
			} else if content != "" {
				// Might be a raw secret
				totpData = model.NewTOTPData(content)
			}
		} else if content != "" {
			cred.CustomFields[key] = content
		}
	}

	// If TOTP was found, set type
	if totpData != nil {
		cred.Type = model.TypeTOTP
		cred.TOTP = totpData
	}

	// Extract attachments (binaries)
	for _, binary := range entry.Binaries {
		// Find the binary data in the database
		for _, meta := range s.db.Content.Meta.Binaries {
			if meta.ID == binary.Value.ID {
				var data []byte
				if meta.Content != nil {
					data = meta.Content
				}

				cred.Attachments = append(cred.Attachments, model.Attachment{
					Name:     binary.Name,
					Data:     data,
					MimeType: guessMimeType(binary.Name),
				})
				break
			}
		}
	}

	return cred, nil
}

// parseKeePassTime converts a KeePass Time to time.Time.
func parseKeePassTime(t *wrappers.TimeWrapper) time.Time {
	if t == nil {
		return time.Time{}
	}
	return t.Time
}

// parseOTPAuthURI parses an otpauth:// URI into TOTPData.
func parseOTPAuthURI(uri string) (*model.TOTPData, error) {
	u, err := url.Parse(uri)
	if err != nil {
		return nil, err
	}

	if u.Scheme != "otpauth" {
		return nil, fmt.Errorf("not an otpauth URI")
	}

	if u.Host != "totp" {
		return nil, fmt.Errorf("not a TOTP URI")
	}

	query := u.Query()

	totp := &model.TOTPData{
		Secret:    query.Get("secret"),
		Algorithm: model.TOTPAlgorithmSHA1,
		Digits:    6,
		Period:    30,
		Issuer:    query.Get("issuer"),
	}

	// Parse label for account name
	label := strings.TrimPrefix(u.Path, "/")
	if strings.Contains(label, ":") {
		parts := strings.SplitN(label, ":", 2)
		if totp.Issuer == "" {
			totp.Issuer = parts[0]
		}
		totp.AccountName = parts[1]
	} else {
		totp.AccountName = label
	}

	// Parse algorithm
	if algo := query.Get("algorithm"); algo != "" {
		switch strings.ToUpper(algo) {
		case "SHA256":
			totp.Algorithm = model.TOTPAlgorithmSHA256
		case "SHA512":
			totp.Algorithm = model.TOTPAlgorithmSHA512
		default:
			totp.Algorithm = model.TOTPAlgorithmSHA1
		}
	}

	// Parse digits
	if digits := query.Get("digits"); digits != "" {
		if digits == "8" {
			totp.Digits = 8
		}
	}

	// Parse period
	if period := query.Get("period"); period != "" {
		var p int
		if _, err := fmt.Sscanf(period, "%d", &p); err == nil && p > 0 {
			totp.Period = p
		}
	}

	return totp, nil
}

// guessMimeType guesses the MIME type from a filename.
func guessMimeType(filename string) string {
	ext := strings.ToLower(filepath.Ext(filename))
	switch ext {
	case ".txt":
		return "text/plain"
	case ".pdf":
		return "application/pdf"
	case ".png":
		return "image/png"
	case ".jpg", ".jpeg":
		return "image/jpeg"
	case ".gif":
		return "image/gif"
	case ".doc":
		return "application/msword"
	case ".docx":
		return "application/vnd.openxmlformats-officedocument.wordprocessingml.document"
	case ".xls":
		return "application/vnd.ms-excel"
	case ".xlsx":
		return "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"
	case ".zip":
		return "application/zip"
	case ".json":
		return "application/json"
	case ".xml":
		return "application/xml"
	default:
		return "application/octet-stream"
	}
}

// init registers the KeePass source with the default registry.
func init() {
	RegisterDefault(NewKeePassSource())
}

// Ensure KeePassSource implements Source interface
var _ Source = (*KeePassSource)(nil)
