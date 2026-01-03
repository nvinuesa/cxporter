package sources

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/tobischo/gokeepasslib/v3"
	"github.com/tobischo/gokeepasslib/v3/wrappers"

	"github.com/nvinuesa/cxporter/internal/model"
)

const testKeePassPassword = "testpassword123"

func TestKeePassSource_Interface(t *testing.T) {
	s := NewKeePassSource()

	if s.Name() != "keepass" {
		t.Errorf("Name() = %v, want keepass", s.Name())
	}

	if s.Description() == "" {
		t.Error("Description() should not be empty")
	}

	exts := s.SupportedExtensions()
	if len(exts) != 1 || exts[0] != ".kdbx" {
		t.Errorf("SupportedExtensions() = %v, want [.kdbx]", exts)
	}
}

func TestKeePassSource_Detect(t *testing.T) {
	s := NewKeePassSource()

	t.Run("Non-existent path", func(t *testing.T) {
		_, err := s.Detect("/nonexistent/path.kdbx")
		if err == nil {
			t.Error("Expected error for non-existent path")
		}
	})

	t.Run("Directory instead of file", func(t *testing.T) {
		dir, err := os.MkdirTemp("", "keepasstest")
		if err != nil {
			t.Fatal(err)
		}
		defer os.RemoveAll(dir)

		confidence, err := s.Detect(dir)
		if err != nil {
			t.Fatalf("Detect() error = %v", err)
		}
		if confidence != 0 {
			t.Errorf("Detect() on directory should return 0, got %d", confidence)
		}
	})

	t.Run("Wrong extension", func(t *testing.T) {
		f, err := os.CreateTemp("", "test*.txt")
		if err != nil {
			t.Fatal(err)
		}
		defer os.Remove(f.Name())
		f.Close()

		confidence, err := s.Detect(f.Name())
		if err != nil {
			t.Fatalf("Detect() error = %v", err)
		}
		if confidence != 0 {
			t.Errorf("Detect() on .txt file should return 0, got %d", confidence)
		}
	})

	t.Run("Valid KDBX file", func(t *testing.T) {
		dbPath := createTestKeePassDB(t)
		defer os.Remove(dbPath)

		confidence, err := s.Detect(dbPath)
		if err != nil {
			t.Fatalf("Detect() error = %v", err)
		}
		if confidence != 100 {
			t.Errorf("Detect() on valid KDBX should return 100, got %d", confidence)
		}
	})
}

func TestKeePassSource_Open(t *testing.T) {
	t.Run("Non-existent file", func(t *testing.T) {
		s := NewKeePassSource()
		err := s.Open("/nonexistent.kdbx", OpenOptions{})
		if err == nil {
			t.Error("Expected error for non-existent file")
		}
	})

	t.Run("Directory instead of file", func(t *testing.T) {
		dir, err := os.MkdirTemp("", "keepasstest")
		if err != nil {
			t.Fatal(err)
		}
		defer os.RemoveAll(dir)

		s := NewKeePassSource()
		err = s.Open(dir, OpenOptions{})
		if err == nil {
			t.Error("Expected error when opening directory")
		}
	})

	t.Run("Wrong password", func(t *testing.T) {
		dbPath := createTestKeePassDB(t)
		defer os.Remove(dbPath)

		s := NewKeePassSource()
		err := s.Open(dbPath, OpenOptions{Password: "wrongpassword"})
		if err == nil {
			t.Error("Expected error for wrong password")
		}
		if !IsAuthError(err) {
			t.Errorf("Expected auth error, got %v", err)
		}
	})

	t.Run("Correct password", func(t *testing.T) {
		dbPath := createTestKeePassDB(t)
		defer os.Remove(dbPath)

		s := NewKeePassSource()
		err := s.Open(dbPath, OpenOptions{Password: testKeePassPassword})
		if err != nil {
			t.Fatalf("Open() error = %v", err)
		}
		defer s.Close()

		// Double open should fail
		err = s.Open(dbPath, OpenOptions{Password: testKeePassPassword})
		if err != ErrAlreadyOpen {
			t.Errorf("Double Open() error = %v, want ErrAlreadyOpen", err)
		}
	})
}

func TestKeePassSource_Read(t *testing.T) {
	t.Run("Read before Open", func(t *testing.T) {
		s := NewKeePassSource()
		_, err := s.Read()
		if err != ErrNotOpen {
			t.Errorf("Read() before Open() error = %v, want ErrNotOpen", err)
		}
	})

	t.Run("Read entries", func(t *testing.T) {
		dbPath := createTestKeePassDB(t)
		defer os.Remove(dbPath)

		s := NewKeePassSource()
		err := s.Open(dbPath, OpenOptions{Password: testKeePassPassword})
		if err != nil {
			t.Fatalf("Open() error = %v", err)
		}
		defer s.Close()

		creds, err := s.Read()
		if err != nil {
			t.Fatalf("Read() error = %v", err)
		}

		if len(creds) < 2 {
			t.Errorf("Read() returned %d credentials, want at least 2", len(creds))
		}

		// Verify credentials have expected fields
		for _, cred := range creds {
			if cred.ID == "" {
				t.Error("Credential ID should not be empty")
			}
			if cred.Title == "" {
				t.Error("Credential Title should not be empty")
			}
		}
	})

	t.Run("Cached results", func(t *testing.T) {
		dbPath := createTestKeePassDB(t)
		defer os.Remove(dbPath)

		s := NewKeePassSource()
		_ = s.Open(dbPath, OpenOptions{Password: testKeePassPassword})
		defer s.Close()

		creds1, _ := s.Read()
		creds2, _ := s.Read()

		if len(creds1) != len(creds2) {
			t.Error("Cached results should be the same")
		}
	})
}

func TestKeePassSource_TOTP(t *testing.T) {
	dbPath := createTestKeePassDBWithTOTP(t)
	defer os.Remove(dbPath)

	s := NewKeePassSource()
	err := s.Open(dbPath, OpenOptions{Password: testKeePassPassword})
	if err != nil {
		t.Fatalf("Open() error = %v", err)
	}
	defer s.Close()

	creds, err := s.Read()
	if err != nil {
		t.Fatalf("Read() error = %v", err)
	}

	// Find the TOTP entry
	var totpCred *model.Credential
	for i := range creds {
		if creds[i].Type == model.TypeTOTP {
			totpCred = &creds[i]
			break
		}
	}

	if totpCred == nil {
		t.Fatal("Should have found a TOTP credential")
	}

	if totpCred.TOTP == nil {
		t.Fatal("TOTP data should not be nil")
	}

	if totpCred.TOTP.Secret == "" {
		t.Error("TOTP secret should not be empty")
	}
}

func TestKeePassSource_FolderPath(t *testing.T) {
	dbPath := createTestKeePassDBWithGroups(t)
	defer os.Remove(dbPath)

	s := NewKeePassSource()
	err := s.Open(dbPath, OpenOptions{Password: testKeePassPassword})
	if err != nil {
		t.Fatalf("Open() error = %v", err)
	}
	defer s.Close()

	creds, err := s.Read()
	if err != nil {
		t.Fatalf("Read() error = %v", err)
	}

	// Check that we have credentials in nested folders
	foundNested := false
	for _, cred := range creds {
		if cred.FolderPath != "" && cred.FolderPath != "Root" {
			foundNested = true
			break
		}
	}

	if !foundNested {
		t.Error("Should have found credentials in nested folders")
	}
}

func TestKeePassSource_Close(t *testing.T) {
	dbPath := createTestKeePassDB(t)
	defer os.Remove(dbPath)

	s := NewKeePassSource()

	// Close without open should not error
	err := s.Close()
	if err != nil {
		t.Errorf("Close() without Open() error = %v", err)
	}

	_ = s.Open(dbPath, OpenOptions{Password: testKeePassPassword})
	_, _ = s.Read()

	err = s.Close()
	if err != nil {
		t.Errorf("Close() error = %v", err)
	}

	// Read after close should fail
	_, err = s.Read()
	if err != ErrNotOpen {
		t.Errorf("Read() after Close() error = %v, want ErrNotOpen", err)
	}
}

func TestParseOTPAuthURI(t *testing.T) {
	tests := []struct {
		name      string
		uri       string
		wantErr   bool
		checkFunc func(*model.TOTPData) bool
	}{
		{
			name:    "Basic TOTP URI",
			uri:     "otpauth://totp/Example:alice@example.com?secret=JBSWY3DPEHPK3PXP&issuer=Example",
			wantErr: false,
			checkFunc: func(t *model.TOTPData) bool {
				return t.Secret == "JBSWY3DPEHPK3PXP" &&
					t.Issuer == "Example" &&
					t.AccountName == "alice@example.com" &&
					t.Digits == 6 &&
					t.Period == 30
			},
		},
		{
			name:    "TOTP with SHA256",
			uri:     "otpauth://totp/Test?secret=ABCD&algorithm=SHA256&digits=8&period=60",
			wantErr: false,
			checkFunc: func(t *model.TOTPData) bool {
				return t.Algorithm == model.TOTPAlgorithmSHA256 &&
					t.Digits == 8 &&
					t.Period == 60
			},
		},
		{
			name:    "Invalid scheme",
			uri:     "http://example.com",
			wantErr: true,
		},
		{
			name:    "HOTP instead of TOTP",
			uri:     "otpauth://hotp/Test?secret=ABCD",
			wantErr: true,
		},
		{
			name:    "Malformed URI",
			uri:     "not-a-uri",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			totp, err := parseOTPAuthURI(tt.uri)
			if (err != nil) != tt.wantErr {
				t.Errorf("parseOTPAuthURI() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !tt.wantErr && tt.checkFunc != nil && !tt.checkFunc(totp) {
				t.Error("parseOTPAuthURI() returned unexpected values")
			}
		})
	}
}

func TestGuessMimeType(t *testing.T) {
	tests := []struct {
		filename string
		want     string
	}{
		{"document.txt", "text/plain"},
		{"document.pdf", "application/pdf"},
		{"image.png", "image/png"},
		{"image.jpg", "image/jpeg"},
		{"image.jpeg", "image/jpeg"},
		{"image.gif", "image/gif"},
		{"doc.doc", "application/msword"},
		{"unknown.xyz", "application/octet-stream"},
	}

	for _, tt := range tests {
		t.Run(tt.filename, func(t *testing.T) {
			if got := guessMimeType(tt.filename); got != tt.want {
				t.Errorf("guessMimeType(%q) = %v, want %v", tt.filename, got, tt.want)
			}
		})
	}
}

func TestDefaultRegistryHasKeePass(t *testing.T) {
	reg := DefaultRegistry()
	source, ok := reg.Get("keepass")
	if !ok {
		t.Error("Default registry should have keepass source")
	}
	if source.Name() != "keepass" {
		t.Errorf("Source name = %v, want keepass", source.Name())
	}
}

// Helper functions to create test databases

func createTestKeePassDB(t *testing.T) string {
	t.Helper()

	db := gokeepasslib.NewDatabase()
	db.Credentials = gokeepasslib.NewPasswordCredentials(testKeePassPassword)

	rootGroup := gokeepasslib.NewGroup()
	rootGroup.Name = "Root"

	// Add test entries
	entry1 := gokeepasslib.NewEntry()
	entry1.Values = append(entry1.Values,
		mkValue("Title", "Test Entry 1"),
		mkValue("UserName", "testuser1"),
		mkProtectedValue("Password", "testpass1"),
		mkValue("URL", "https://example.com"),
		mkValue("Notes", "Test notes"),
	)

	entry2 := gokeepasslib.NewEntry()
	entry2.Values = append(entry2.Values,
		mkValue("Title", "Test Entry 2"),
		mkValue("UserName", "testuser2"),
		mkProtectedValue("Password", "testpass2"),
	)

	rootGroup.Entries = append(rootGroup.Entries, entry1, entry2)
	db.Content.Root.Groups = append(db.Content.Root.Groups, rootGroup)

	return saveTestDB(t, db)
}

func createTestKeePassDBWithTOTP(t *testing.T) string {
	t.Helper()

	db := gokeepasslib.NewDatabase()
	db.Credentials = gokeepasslib.NewPasswordCredentials(testKeePassPassword)

	rootGroup := gokeepasslib.NewGroup()
	rootGroup.Name = "Root"

	// Add entry with TOTP
	entry := gokeepasslib.NewEntry()
	entry.Values = append(entry.Values,
		mkValue("Title", "TOTP Entry"),
		mkValue("UserName", "totpuser"),
		mkProtectedValue("Password", "totppass"),
		mkValue("otp", "otpauth://totp/Example:user@example.com?secret=JBSWY3DPEHPK3PXP&issuer=Example"),
	)

	rootGroup.Entries = append(rootGroup.Entries, entry)
	db.Content.Root.Groups = append(db.Content.Root.Groups, rootGroup)

	return saveTestDB(t, db)
}

func createTestKeePassDBWithGroups(t *testing.T) string {
	t.Helper()

	db := gokeepasslib.NewDatabase()
	db.Credentials = gokeepasslib.NewPasswordCredentials(testKeePassPassword)

	rootGroup := gokeepasslib.NewGroup()
	rootGroup.Name = "Root"

	// Create nested groups
	workGroup := gokeepasslib.NewGroup()
	workGroup.Name = "Work"

	serversGroup := gokeepasslib.NewGroup()
	serversGroup.Name = "Servers"

	serverEntry := gokeepasslib.NewEntry()
	serverEntry.Values = append(serverEntry.Values,
		mkValue("Title", "Server Login"),
		mkValue("UserName", "admin"),
		mkProtectedValue("Password", "serverpass"),
	)

	serversGroup.Entries = append(serversGroup.Entries, serverEntry)
	workGroup.Groups = append(workGroup.Groups, serversGroup)
	rootGroup.Groups = append(rootGroup.Groups, workGroup)

	// Add entry in root
	rootEntry := gokeepasslib.NewEntry()
	rootEntry.Values = append(rootEntry.Values,
		mkValue("Title", "Root Entry"),
		mkValue("UserName", "rootuser"),
		mkProtectedValue("Password", "rootpass"),
	)
	rootGroup.Entries = append(rootGroup.Entries, rootEntry)

	db.Content.Root.Groups = append(db.Content.Root.Groups, rootGroup)

	return saveTestDB(t, db)
}

func mkValue(key, value string) gokeepasslib.ValueData {
	return gokeepasslib.ValueData{
		Key:   key,
		Value: gokeepasslib.V{Content: value},
	}
}

func mkProtectedValue(key, value string) gokeepasslib.ValueData {
	return gokeepasslib.ValueData{
		Key: key,
		Value: gokeepasslib.V{
			Content:   value,
			Protected: wrappers.NewBoolWrapper(true),
		},
	}
}

func saveTestDB(t *testing.T, db *gokeepasslib.Database) string {
	t.Helper()

	// Set timestamps
	now := time.Now()
	db.Content.Meta.DatabaseName = "Test Database"
	db.Content.Meta.DatabaseNameChanged = &wrappers.TimeWrapper{Time: now}

	// Lock protected entries before saving
	if err := db.LockProtectedEntries(); err != nil {
		t.Fatalf("Failed to lock entries: %v", err)
	}

	// Create temp file
	f, err := os.CreateTemp("", "test*.kdbx")
	if err != nil {
		t.Fatalf("Failed to create temp file: %v", err)
	}
	path := f.Name()

	// Encode database
	enc := gokeepasslib.NewEncoder(f)
	if err := enc.Encode(db); err != nil {
		f.Close()
		os.Remove(path)
		t.Fatalf("Failed to encode database: %v", err)
	}
	f.Close()

	return path
}

// Tests using testdata files

func TestKeePassSource_Testdata_Basic(t *testing.T) {
	dbPath := filepath.Join(getTestdataPath(), "keepass", "basic.kdbx")
	if _, err := os.Stat(dbPath); os.IsNotExist(err) {
		t.Skip("testdata/keepass/basic.kdbx not found")
	}

	s := NewKeePassSource()

	// Test detection
	confidence, err := s.Detect(dbPath)
	if err != nil {
		t.Fatalf("Detect() error = %v", err)
	}
	if confidence != 100 {
		t.Errorf("Detect() = %d, want 100", confidence)
	}

	// Test opening
	err = s.Open(dbPath, OpenOptions{Password: testKeePassPassword})
	if err != nil {
		t.Fatalf("Open() error = %v", err)
	}
	defer s.Close()

	// Test reading
	creds, err := s.Read()
	if err != nil {
		t.Fatalf("Read() error = %v", err)
	}

	// basic.kdbx should have at least 3 entries: GitHub, Gmail, AWS Console
	// (may include a default "Sample Entry" from gokeepasslib)
	if len(creds) < 3 {
		t.Errorf("Read() returned %d credentials, want at least 3", len(creds))
	}

	// Verify our entries have expected data
	titles := make(map[string]bool)
	for _, cred := range creds {
		titles[cred.Title] = true
		// Skip checking Sample Entry (default from library)
		if cred.Title == "Sample Entry" {
			continue
		}
		if cred.Type != model.TypeBasicAuth {
			t.Errorf("Credential %q type = %v, want basic-auth", cred.Title, cred.Type)
		}
		if cred.Username == "" {
			t.Errorf("Credential %q should have username", cred.Title)
		}
		if cred.Password == "" {
			t.Errorf("Credential %q should have password", cred.Title)
		}
	}

	expectedTitles := []string{"GitHub", "Gmail", "AWS Console"}
	for _, title := range expectedTitles {
		if !titles[title] {
			t.Errorf("Missing expected entry: %s", title)
		}
	}
}

func TestKeePassSource_Testdata_TOTP(t *testing.T) {
	dbPath := filepath.Join(getTestdataPath(), "keepass", "totp.kdbx")
	if _, err := os.Stat(dbPath); os.IsNotExist(err) {
		t.Skip("testdata/keepass/totp.kdbx not found")
	}

	s := NewKeePassSource()
	err := s.Open(dbPath, OpenOptions{Password: testKeePassPassword})
	if err != nil {
		t.Fatalf("Open() error = %v", err)
	}
	defer s.Close()

	creds, err := s.Read()
	if err != nil {
		t.Fatalf("Read() error = %v", err)
	}

	// totp.kdbx should have at least 4 entries with TOTP data
	// (may include a default "Sample Entry" from gokeepasslib)
	if len(creds) < 4 {
		t.Errorf("Read() returned %d credentials, want at least 4", len(creds))
	}

	// Count TOTP entries
	totpCount := 0
	for _, cred := range creds {
		if cred.Type == model.TypeTOTP {
			totpCount++
			if cred.TOTP == nil {
				t.Errorf("Credential %q has TypeTOTP but nil TOTP data", cred.Title)
				continue
			}
			if cred.TOTP.Secret == "" {
				t.Errorf("Credential %q TOTP secret is empty", cred.Title)
			}
		}
	}

	if totpCount < 4 {
		t.Errorf("Found %d TOTP credentials, want at least 4", totpCount)
	}

	// Test specific TOTP configuration
	for _, cred := range creds {
		if cred.Title == "Steam Guard" && cred.TOTP != nil {
			if cred.TOTP.Digits != 8 {
				t.Errorf("Steam Guard TOTP digits = %d, want 8", cred.TOTP.Digits)
			}
			if cred.TOTP.Period != 60 {
				t.Errorf("Steam Guard TOTP period = %d, want 60", cred.TOTP.Period)
			}
		}
		if cred.Title == "Dropbox 2FA" && cred.TOTP != nil {
			if cred.TOTP.Algorithm != model.TOTPAlgorithmSHA256 {
				t.Errorf("Dropbox 2FA TOTP algorithm = %v, want SHA256", cred.TOTP.Algorithm)
			}
		}
	}
}

func TestKeePassSource_Testdata_NestedGroups(t *testing.T) {
	dbPath := filepath.Join(getTestdataPath(), "keepass", "nested_groups.kdbx")
	if _, err := os.Stat(dbPath); os.IsNotExist(err) {
		t.Skip("testdata/keepass/nested_groups.kdbx not found")
	}

	s := NewKeePassSource()
	err := s.Open(dbPath, OpenOptions{Password: testKeePassPassword})
	if err != nil {
		t.Fatalf("Open() error = %v", err)
	}
	defer s.Close()

	creds, err := s.Read()
	if err != nil {
		t.Fatalf("Read() error = %v", err)
	}

	// nested_groups.kdbx should have at least 6 entries in various groups
	// (may include a default "Sample Entry" from gokeepasslib)
	if len(creds) < 6 {
		t.Errorf("Read() returned %d credentials, want at least 6", len(creds))
	}

	// Check folder paths
	folderPaths := make(map[string]bool)
	for _, cred := range creds {
		folderPaths[cred.FolderPath] = true
	}

	expectedPaths := []string{
		"Root",
		"Root/Work",
		"Root/Work/Servers",
		"Root/Work/Servers/Databases",
		"Root/Personal",
	}

	for _, path := range expectedPaths {
		if !folderPaths[path] {
			t.Errorf("Missing expected folder path: %s", path)
		}
	}

	// Find specific entry in deep nesting
	var dbEntry *model.Credential
	for i := range creds {
		if creds[i].Title == "PostgreSQL Production" {
			dbEntry = &creds[i]
			break
		}
	}

	if dbEntry == nil {
		t.Fatal("Should have found PostgreSQL Production entry")
	}
	if dbEntry.FolderPath != "Root/Work/Servers/Databases" {
		t.Errorf("PostgreSQL Production folder = %q, want Root/Work/Servers/Databases", dbEntry.FolderPath)
	}
}

func TestKeePassSource_Testdata_Complete(t *testing.T) {
	dbPath := filepath.Join(getTestdataPath(), "keepass", "complete.kdbx")
	if _, err := os.Stat(dbPath); os.IsNotExist(err) {
		t.Skip("testdata/keepass/complete.kdbx not found")
	}

	s := NewKeePassSource()
	err := s.Open(dbPath, OpenOptions{Password: testKeePassPassword})
	if err != nil {
		t.Fatalf("Open() error = %v", err)
	}
	defer s.Close()

	creds, err := s.Read()
	if err != nil {
		t.Fatalf("Read() error = %v", err)
	}

	// complete.kdbx should have at least 5 entries
	// (may include a default "Sample Entry" from gokeepasslib)
	if len(creds) < 5 {
		t.Errorf("Read() returned %d credentials, want at least 5", len(creds))
	}

	// Find entry with custom fields
	var serverEntry *model.Credential
	for i := range creds {
		if creds[i].Title == "Server with Custom Fields" {
			serverEntry = &creds[i]
			break
		}
	}

	if serverEntry == nil {
		t.Fatal("Should have found 'Server with Custom Fields' entry")
	}

	// Check custom fields
	if serverEntry.CustomFields == nil {
		t.Fatal("Custom fields should not be nil")
	}
	if serverEntry.CustomFields["API Key"] != "sk-abc123def456" {
		t.Errorf("API Key = %q, want sk-abc123def456", serverEntry.CustomFields["API Key"])
	}
	if serverEntry.CustomFields["Environment"] != "production" {
		t.Errorf("Environment = %q, want production", serverEntry.CustomFields["Environment"])
	}

	// Check tags
	if len(serverEntry.Tags) == 0 {
		t.Error("Server entry should have tags")
	}

	// Find entry with TOTP and custom fields
	var fullEntry *model.Credential
	for i := range creds {
		if creds[i].Title == "Full Featured Entry" {
			fullEntry = &creds[i]
			break
		}
	}

	if fullEntry == nil {
		t.Fatal("Should have found 'Full Featured Entry' entry")
	}
	if fullEntry.Type != model.TypeTOTP {
		t.Errorf("Full Featured Entry type = %v, want TypeTOTP", fullEntry.Type)
	}
	if fullEntry.TOTP == nil {
		t.Fatal("Full Featured Entry should have TOTP data")
	}
	if fullEntry.CustomFields["Recovery Email"] != "recovery@example.com" {
		t.Errorf("Recovery Email = %q, want recovery@example.com", fullEntry.CustomFields["Recovery Email"])
	}

	// Check entry with minimal data
	var legacyEntry *model.Credential
	for i := range creds {
		if creds[i].Title == "Legacy System" {
			legacyEntry = &creds[i]
			break
		}
	}

	if legacyEntry == nil {
		t.Fatal("Should have found 'Legacy System' entry")
	}
	if legacyEntry.Password != "" {
		t.Errorf("Legacy System should have no password, got %q", legacyEntry.Password)
	}
	if legacyEntry.Username != "legacy_admin" {
		t.Errorf("Legacy System username = %q, want legacy_admin", legacyEntry.Username)
	}
}

func TestKeePassSource_Testdata_WrongPassword(t *testing.T) {
	dbPath := filepath.Join(getTestdataPath(), "keepass", "basic.kdbx")
	if _, err := os.Stat(dbPath); os.IsNotExist(err) {
		t.Skip("testdata/keepass/basic.kdbx not found")
	}

	s := NewKeePassSource()
	err := s.Open(dbPath, OpenOptions{Password: "wrongpassword"})
	if err == nil {
		s.Close()
		t.Fatal("Open() should fail with wrong password")
	}
	if !IsAuthError(err) {
		t.Errorf("Expected auth error, got %v", err)
	}
}
