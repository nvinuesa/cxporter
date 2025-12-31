package sources

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/nvinuesa/cxporter/internal/model"
)

func TestBitwardenSource_Interface(t *testing.T) {
	s := NewBitwardenSource()

	if s.Name() != "bitwarden" {
		t.Errorf("Name() = %v, want bitwarden", s.Name())
	}

	if s.Description() == "" {
		t.Error("Description() should not be empty")
	}

	exts := s.SupportedExtensions()
	if len(exts) != 1 || exts[0] != ".json" {
		t.Errorf("SupportedExtensions() = %v, want [.json]", exts)
	}
}

func TestBitwardenSource_Detect(t *testing.T) {
	s := NewBitwardenSource()

	t.Run("Non-existent path", func(t *testing.T) {
		_, err := s.Detect("/nonexistent/export.json")
		if err == nil {
			t.Error("Expected error for non-existent path")
		}
	})

	t.Run("Directory instead of file", func(t *testing.T) {
		dir, err := os.MkdirTemp("", "bitwardentest")
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

	t.Run("Valid Bitwarden JSON", func(t *testing.T) {
		jsonPath := filepath.Join(getTestdataPath(), "bitwarden", "export.json")
		if _, err := os.Stat(jsonPath); os.IsNotExist(err) {
			t.Skip("testdata/bitwarden/export.json not found")
		}

		confidence, err := s.Detect(jsonPath)
		if err != nil {
			t.Fatalf("Detect() error = %v", err)
		}
		if confidence != 100 {
			t.Errorf("Detect() on valid Bitwarden JSON should return 100, got %d", confidence)
		}
	})

	t.Run("Invalid JSON", func(t *testing.T) {
		f, err := os.CreateTemp("", "test*.json")
		if err != nil {
			t.Fatal(err)
		}
		defer os.Remove(f.Name())
		f.WriteString("not valid json")
		f.Close()

		confidence, err := s.Detect(f.Name())
		if err != nil {
			t.Fatalf("Detect() error = %v", err)
		}
		if confidence != 0 {
			t.Errorf("Detect() on invalid JSON should return 0, got %d", confidence)
		}
	})

	t.Run("Non-Bitwarden JSON", func(t *testing.T) {
		f, err := os.CreateTemp("", "test*.json")
		if err != nil {
			t.Fatal(err)
		}
		defer os.Remove(f.Name())
		f.WriteString(`{"name": "test", "value": 123}`)
		f.Close()

		confidence, err := s.Detect(f.Name())
		if err != nil {
			t.Fatalf("Detect() error = %v", err)
		}
		if confidence != 0 {
			t.Errorf("Detect() on non-Bitwarden JSON should return 0, got %d", confidence)
		}
	})
}

func TestBitwardenSource_Open(t *testing.T) {
	t.Run("Non-existent file", func(t *testing.T) {
		s := NewBitwardenSource()
		err := s.Open("/nonexistent.json", OpenOptions{})
		if err == nil {
			t.Error("Expected error for non-existent file")
		}
	})

	t.Run("Directory instead of file", func(t *testing.T) {
		dir, err := os.MkdirTemp("", "bitwardentest")
		if err != nil {
			t.Fatal(err)
		}
		defer os.RemoveAll(dir)

		s := NewBitwardenSource()
		err = s.Open(dir, OpenOptions{})
		if err == nil {
			t.Error("Expected error when opening directory")
		}
	})

	t.Run("Invalid JSON file", func(t *testing.T) {
		f, err := os.CreateTemp("", "test*.json")
		if err != nil {
			t.Fatal(err)
		}
		defer os.Remove(f.Name())
		f.WriteString("not valid json")
		f.Close()

		s := NewBitwardenSource()
		err = s.Open(f.Name(), OpenOptions{})
		if err == nil {
			t.Error("Expected error for invalid JSON")
		}
	})

	t.Run("Encrypted export", func(t *testing.T) {
		jsonPath := filepath.Join(getTestdataPath(), "bitwarden", "encrypted.json")
		if _, err := os.Stat(jsonPath); os.IsNotExist(err) {
			t.Skip("testdata/bitwarden/encrypted.json not found")
		}

		s := NewBitwardenSource()
		err := s.Open(jsonPath, OpenOptions{})
		if err == nil {
			t.Error("Expected error for encrypted export")
		}
		if !strings.Contains(err.Error(), "encrypted") {
			t.Errorf("Error should mention encryption: %v", err)
		}
	})

	t.Run("Valid JSON file", func(t *testing.T) {
		jsonPath := filepath.Join(getTestdataPath(), "bitwarden", "export.json")
		if _, err := os.Stat(jsonPath); os.IsNotExist(err) {
			t.Skip("testdata/bitwarden/export.json not found")
		}

		s := NewBitwardenSource()
		err := s.Open(jsonPath, OpenOptions{})
		if err != nil {
			t.Fatalf("Open() error = %v", err)
		}
		defer s.Close()

		// Double open should fail
		err = s.Open(jsonPath, OpenOptions{})
		if err != ErrAlreadyOpen {
			t.Errorf("Double Open() error = %v, want ErrAlreadyOpen", err)
		}
	})
}

func TestBitwardenSource_Read(t *testing.T) {
	t.Run("Read before Open", func(t *testing.T) {
		s := NewBitwardenSource()
		_, err := s.Read()
		if err != ErrNotOpen {
			t.Errorf("Read() before Open() error = %v, want ErrNotOpen", err)
		}
	})

	t.Run("Read standard export", func(t *testing.T) {
		jsonPath := filepath.Join(getTestdataPath(), "bitwarden", "export.json")
		if _, err := os.Stat(jsonPath); os.IsNotExist(err) {
			t.Skip("testdata/bitwarden/export.json not found")
		}

		s := NewBitwardenSource()
		err := s.Open(jsonPath, OpenOptions{})
		if err != nil {
			t.Fatalf("Open() error = %v", err)
		}
		defer s.Close()

		creds, err := s.Read()
		if err != nil {
			t.Fatalf("Read() error = %v", err)
		}

		// Should have multiple credentials from the test file
		if len(creds) < 4 {
			t.Errorf("Read() returned %d credentials, want at least 4", len(creds))
		}

		// Verify each credential has expected fields
		for _, cred := range creds {
			if cred.ID == "" {
				t.Error("Credential ID should not be empty")
			}
			if cred.Title == "" {
				t.Error("Credential title should not be empty")
			}
		}
	})

	t.Run("Login type parsing", func(t *testing.T) {
		jsonPath := filepath.Join(getTestdataPath(), "bitwarden", "export.json")
		if _, err := os.Stat(jsonPath); os.IsNotExist(err) {
			t.Skip("testdata/bitwarden/export.json not found")
		}

		s := NewBitwardenSource()
		_ = s.Open(jsonPath, OpenOptions{})
		defer s.Close()

		creds, _ := s.Read()

		// Find login credential
		var loginCred *model.Credential
		for i := range creds {
			if creds[i].Type == model.TypeBasicAuth && strings.Contains(creds[i].Title, "GitHub") {
				loginCred = &creds[i]
				break
			}
		}

		if loginCred == nil {
			t.Fatal("Should have found GitHub login entry")
		}

		if loginCred.Username == "" {
			t.Error("Login should have username")
		}
		if loginCred.Password == "" {
			t.Error("Login should have password")
		}
		if loginCred.URL == "" {
			t.Error("Login should have URL")
		}
	})

	t.Run("TOTP extraction", func(t *testing.T) {
		jsonPath := filepath.Join(getTestdataPath(), "bitwarden", "export.json")
		if _, err := os.Stat(jsonPath); os.IsNotExist(err) {
			t.Skip("testdata/bitwarden/export.json not found")
		}

		s := NewBitwardenSource()
		_ = s.Open(jsonPath, OpenOptions{})
		defer s.Close()

		creds, _ := s.Read()

		// Find TOTP credential
		var totpCred *model.Credential
		for i := range creds {
			if creds[i].Type == model.TypeTOTP {
				totpCred = &creds[i]
				break
			}
		}

		if totpCred == nil {
			t.Fatal("Should have found TOTP entry")
		}

		if totpCred.TOTP == nil {
			t.Fatal("TOTP credential should have TOTP data")
		}
		if totpCred.TOTP.Secret == "" {
			t.Error("TOTP should have secret")
		}
	})

	t.Run("Secure note parsing", func(t *testing.T) {
		jsonPath := filepath.Join(getTestdataPath(), "bitwarden", "export.json")
		if _, err := os.Stat(jsonPath); os.IsNotExist(err) {
			t.Skip("testdata/bitwarden/export.json not found")
		}

		s := NewBitwardenSource()
		_ = s.Open(jsonPath, OpenOptions{})
		defer s.Close()

		creds, _ := s.Read()

		// Find note credential
		var noteCred *model.Credential
		for i := range creds {
			if creds[i].Type == model.TypeNote {
				noteCred = &creds[i]
				break
			}
		}

		if noteCred == nil {
			t.Fatal("Should have found secure note entry")
		}

		if noteCred.Notes == "" {
			t.Error("Secure note should have notes content")
		}
	})

	t.Run("Credit card parsing", func(t *testing.T) {
		jsonPath := filepath.Join(getTestdataPath(), "bitwarden", "export.json")
		if _, err := os.Stat(jsonPath); os.IsNotExist(err) {
			t.Skip("testdata/bitwarden/export.json not found")
		}

		s := NewBitwardenSource()
		_ = s.Open(jsonPath, OpenOptions{})
		defer s.Close()

		creds, _ := s.Read()

		// Find card credential
		var cardCred *model.Credential
		for i := range creds {
			if creds[i].Type == model.TypeCreditCard {
				cardCred = &creds[i]
				break
			}
		}

		if cardCred == nil {
			t.Fatal("Should have found credit card entry")
		}

		if cardCred.CreditCard == nil {
			t.Fatal("Credit card credential should have card data")
		}
		if cardCred.CreditCard.Number == "" {
			t.Error("Credit card should have number")
		}
		if cardCred.CreditCard.Holder == "" {
			t.Error("Credit card should have holder name")
		}
	})

	t.Run("Identity parsing", func(t *testing.T) {
		jsonPath := filepath.Join(getTestdataPath(), "bitwarden", "export.json")
		if _, err := os.Stat(jsonPath); os.IsNotExist(err) {
			t.Skip("testdata/bitwarden/export.json not found")
		}

		s := NewBitwardenSource()
		_ = s.Open(jsonPath, OpenOptions{})
		defer s.Close()

		creds, _ := s.Read()

		// Find identity credential
		var identityCred *model.Credential
		for i := range creds {
			if creds[i].Type == model.TypeIdentity {
				identityCred = &creds[i]
				break
			}
		}

		if identityCred == nil {
			t.Fatal("Should have found identity entry")
		}

		if identityCred.Notes == "" {
			t.Error("Identity should have notes with structured data")
		}
	})

	t.Run("Folder resolution", func(t *testing.T) {
		jsonPath := filepath.Join(getTestdataPath(), "bitwarden", "export.json")
		if _, err := os.Stat(jsonPath); os.IsNotExist(err) {
			t.Skip("testdata/bitwarden/export.json not found")
		}

		s := NewBitwardenSource()
		_ = s.Open(jsonPath, OpenOptions{})
		defer s.Close()

		creds, _ := s.Read()

		// At least one credential should have a folder path
		foundFolder := false
		for _, cred := range creds {
			if cred.FolderPath != "" {
				foundFolder = true
				break
			}
		}

		if !foundFolder {
			t.Error("At least one credential should have a folder path")
		}
	})

	t.Run("Favorite tag", func(t *testing.T) {
		jsonPath := filepath.Join(getTestdataPath(), "bitwarden", "export.json")
		if _, err := os.Stat(jsonPath); os.IsNotExist(err) {
			t.Skip("testdata/bitwarden/export.json not found")
		}

		s := NewBitwardenSource()
		_ = s.Open(jsonPath, OpenOptions{})
		defer s.Close()

		creds, _ := s.Read()

		// At least one credential should be a favorite
		foundFavorite := false
		for _, cred := range creds {
			for _, tag := range cred.Tags {
				if tag == "favorite" {
					foundFavorite = true
					break
				}
			}
		}

		if !foundFavorite {
			t.Error("At least one credential should have favorite tag")
		}
	})

	t.Run("Custom fields", func(t *testing.T) {
		jsonPath := filepath.Join(getTestdataPath(), "bitwarden", "export.json")
		if _, err := os.Stat(jsonPath); os.IsNotExist(err) {
			t.Skip("testdata/bitwarden/export.json not found")
		}

		s := NewBitwardenSource()
		_ = s.Open(jsonPath, OpenOptions{})
		defer s.Close()

		creds, _ := s.Read()

		// At least one credential should have custom fields
		foundCustomField := false
		for _, cred := range creds {
			if len(cred.CustomFields) > 0 {
				foundCustomField = true
				break
			}
		}

		if !foundCustomField {
			t.Error("At least one credential should have custom fields")
		}
	})

	t.Run("Cached results", func(t *testing.T) {
		jsonPath := filepath.Join(getTestdataPath(), "bitwarden", "export.json")
		if _, err := os.Stat(jsonPath); os.IsNotExist(err) {
			t.Skip("testdata/bitwarden/export.json not found")
		}

		s := NewBitwardenSource()
		_ = s.Open(jsonPath, OpenOptions{})
		defer s.Close()

		creds1, _ := s.Read()
		creds2, _ := s.Read()

		if len(creds1) != len(creds2) {
			t.Error("Cached results should be the same")
		}
	})
}

func TestBitwardenSource_Close(t *testing.T) {
	jsonPath := filepath.Join(getTestdataPath(), "bitwarden", "export.json")
	if _, err := os.Stat(jsonPath); os.IsNotExist(err) {
		t.Skip("testdata/bitwarden/export.json not found")
	}

	s := NewBitwardenSource()

	// Close without open should not error
	err := s.Close()
	if err != nil {
		t.Errorf("Close() without Open() error = %v", err)
	}

	_ = s.Open(jsonPath, OpenOptions{})
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

func TestDetectBitwardenStructure(t *testing.T) {
	tests := []struct {
		name   string
		export *BitwardenExport
		want   int
	}{
		{
			name:   "Empty export",
			export: &BitwardenExport{},
			want:   0,
		},
		{
			name: "Encrypted export",
			export: &BitwardenExport{
				Encrypted: true,
			},
			want: 50,
		},
		{
			name: "Valid items",
			export: &BitwardenExport{
				Items: []BitwardenItem{
					{
						Type:         1,
						RevisionDate: "2024-01-01T00:00:00Z",
						Login: &BitwardenLogin{
							URIs: []BitwardenURI{{URI: "https://example.com"}},
						},
					},
				},
			},
			want: 100,
		},
		{
			name: "Minimal valid",
			export: &BitwardenExport{
				Items: []BitwardenItem{
					{Type: 1, RevisionDate: "2024-01-01"},
				},
			},
			want: 80,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := detectBitwardenStructure(tt.export); got != tt.want {
				t.Errorf("detectBitwardenStructure() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestParseISOTimestamp(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		wantErr bool
	}{
		{"RFC3339", "2024-01-01T00:00:00Z", false},
		{"RFC3339 with offset", "2024-01-01T00:00:00+00:00", false},
		{"RFC3339 Nano", "2024-01-01T00:00:00.000000000Z", false},
		{"ISO with millis", "2024-01-01T00:00:00.000Z", false},
		{"Date only", "2024-01-01", false},
		{"Empty", "", true},
		{"Invalid", "not-a-date", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := parseISOTimestamp(tt.input)
			if tt.wantErr && !got.IsZero() {
				t.Errorf("parseISOTimestamp(%q) should return zero time for invalid input", tt.input)
			}
			if !tt.wantErr && got.IsZero() {
				t.Errorf("parseISOTimestamp(%q) returned zero time for valid input", tt.input)
			}
		})
	}

	// Test specific timestamp
	t.Run("Specific timestamp", func(t *testing.T) {
		got := parseISOTimestamp("2024-01-01T12:30:45Z")
		expected := time.Date(2024, 1, 1, 12, 30, 45, 0, time.UTC)
		if !got.Equal(expected) {
			t.Errorf("parseISOTimestamp() = %v, want %v", got, expected)
		}
	})
}

func TestParseTOTPString(t *testing.T) {
	tests := []struct {
		name           string
		input          string
		wantSecret     string
		wantAlgorithm  model.TOTPAlgorithm
		wantDigits     int
		wantPeriod     int
		wantIssuer     string
		wantAccount    string
	}{
		{
			name:          "Raw secret",
			input:         "JBSWY3DPEHPK3PXP",
			wantSecret:    "JBSWY3DPEHPK3PXP",
			wantAlgorithm: model.TOTPAlgorithmSHA1,
			wantDigits:    6,
			wantPeriod:    30,
		},
		{
			name:          "otpauth URI basic",
			input:         "otpauth://totp/Example:user@example.com?secret=JBSWY3DPEHPK3PXP",
			wantSecret:    "JBSWY3DPEHPK3PXP",
			wantAlgorithm: model.TOTPAlgorithmSHA1,
			wantDigits:    6,
			wantPeriod:    30,
			wantIssuer:    "Example",
			wantAccount:   "user@example.com",
		},
		{
			name:          "otpauth URI with params",
			input:         "otpauth://totp/Test?secret=ABC123&algorithm=SHA256&digits=8&period=60&issuer=TestIssuer",
			wantSecret:    "ABC123",
			wantAlgorithm: model.TOTPAlgorithmSHA256,
			wantDigits:    8,
			wantPeriod:    60,
			wantIssuer:    "TestIssuer",
			wantAccount:   "Test",
		},
		{
			name:          "otpauth URI SHA512",
			input:         "otpauth://totp/Account?secret=XYZ789&algorithm=SHA512",
			wantSecret:    "XYZ789",
			wantAlgorithm: model.TOTPAlgorithmSHA512,
			wantDigits:    6,
			wantPeriod:    30,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := parseTOTPString(tt.input)
			if got.Secret != tt.wantSecret {
				t.Errorf("Secret = %v, want %v", got.Secret, tt.wantSecret)
			}
			if got.Algorithm != tt.wantAlgorithm {
				t.Errorf("Algorithm = %v, want %v", got.Algorithm, tt.wantAlgorithm)
			}
			if got.Digits != tt.wantDigits {
				t.Errorf("Digits = %v, want %v", got.Digits, tt.wantDigits)
			}
			if got.Period != tt.wantPeriod {
				t.Errorf("Period = %v, want %v", got.Period, tt.wantPeriod)
			}
			if tt.wantIssuer != "" && got.Issuer != tt.wantIssuer {
				t.Errorf("Issuer = %v, want %v", got.Issuer, tt.wantIssuer)
			}
			if tt.wantAccount != "" && got.AccountName != tt.wantAccount {
				t.Errorf("AccountName = %v, want %v", got.AccountName, tt.wantAccount)
			}
		})
	}
}

func TestDefaultRegistryHasBitwarden(t *testing.T) {
	reg := DefaultRegistry()
	source, ok := reg.Get("bitwarden")
	if !ok {
		t.Error("Default registry should have bitwarden source")
	}
	if source.Name() != "bitwarden" {
		t.Errorf("Source name = %v, want bitwarden", source.Name())
	}
}
