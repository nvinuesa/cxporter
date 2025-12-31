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

func init() {
	// Create testdata/keepass directory
	keepassDir := filepath.Join(getTestdataPath(), "keepass")
	_ = os.MkdirAll(keepassDir, 0755)
}
