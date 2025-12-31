package sources

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/nvinuesa/cxporter/internal/model"
)

func TestFirefoxSource_Interface(t *testing.T) {
	s := NewFirefoxSource()

	if s.Name() != "firefox" {
		t.Errorf("Name() = %v, want firefox", s.Name())
	}

	if s.Description() == "" {
		t.Error("Description() should not be empty")
	}

	exts := s.SupportedExtensions()
	if len(exts) != 1 || exts[0] != ".csv" {
		t.Errorf("SupportedExtensions() = %v, want [.csv]", exts)
	}
}

func TestFirefoxSource_Detect(t *testing.T) {
	s := NewFirefoxSource()

	t.Run("Non-existent path", func(t *testing.T) {
		_, err := s.Detect("/nonexistent/logins.csv")
		if err == nil {
			t.Error("Expected error for non-existent path")
		}
	})

	t.Run("Directory instead of file", func(t *testing.T) {
		dir, err := os.MkdirTemp("", "firefoxtest")
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

	t.Run("Valid Firefox CSV", func(t *testing.T) {
		csvPath := filepath.Join(getTestdataPath(), "firefox", "logins.csv")
		if _, err := os.Stat(csvPath); os.IsNotExist(err) {
			t.Skip("testdata/firefox/logins.csv not found")
		}

		confidence, err := s.Detect(csvPath)
		if err != nil {
			t.Fatalf("Detect() error = %v", err)
		}
		if confidence != 100 {
			t.Errorf("Detect() on valid Firefox CSV should return 100, got %d", confidence)
		}
	})

	t.Run("Chrome CSV should have lower confidence", func(t *testing.T) {
		csvPath := filepath.Join(getTestdataPath(), "chrome", "passwords.csv")
		if _, err := os.Stat(csvPath); os.IsNotExist(err) {
			t.Skip("testdata/chrome/passwords.csv not found")
		}

		confidence, err := s.Detect(csvPath)
		if err != nil {
			t.Fatalf("Detect() error = %v", err)
		}
		// Chrome CSV shouldn't match Firefox-specific columns
		if confidence > 0 {
			t.Errorf("Detect() on Chrome CSV should return 0, got %d", confidence)
		}
	})
}

func TestFirefoxSource_Open(t *testing.T) {
	t.Run("Non-existent file", func(t *testing.T) {
		s := NewFirefoxSource()
		err := s.Open("/nonexistent.csv", OpenOptions{})
		if err == nil {
			t.Error("Expected error for non-existent file")
		}
	})

	t.Run("Directory instead of file", func(t *testing.T) {
		dir, err := os.MkdirTemp("", "firefoxtest")
		if err != nil {
			t.Fatal(err)
		}
		defer os.RemoveAll(dir)

		s := NewFirefoxSource()
		err = s.Open(dir, OpenOptions{})
		if err == nil {
			t.Error("Expected error when opening directory")
		}
	})

	t.Run("Valid CSV file", func(t *testing.T) {
		csvPath := filepath.Join(getTestdataPath(), "firefox", "logins.csv")
		if _, err := os.Stat(csvPath); os.IsNotExist(err) {
			t.Skip("testdata/firefox/logins.csv not found")
		}

		s := NewFirefoxSource()
		err := s.Open(csvPath, OpenOptions{})
		if err != nil {
			t.Fatalf("Open() error = %v", err)
		}
		defer s.Close()

		// Double open should fail
		err = s.Open(csvPath, OpenOptions{})
		if err != ErrAlreadyOpen {
			t.Errorf("Double Open() error = %v, want ErrAlreadyOpen", err)
		}
	})
}

func TestFirefoxSource_Read(t *testing.T) {
	t.Run("Read before Open", func(t *testing.T) {
		s := NewFirefoxSource()
		_, err := s.Read()
		if err != ErrNotOpen {
			t.Errorf("Read() before Open() error = %v, want ErrNotOpen", err)
		}
	})

	t.Run("Read standard CSV", func(t *testing.T) {
		csvPath := filepath.Join(getTestdataPath(), "firefox", "logins.csv")
		if _, err := os.Stat(csvPath); os.IsNotExist(err) {
			t.Skip("testdata/firefox/logins.csv not found")
		}

		s := NewFirefoxSource()
		err := s.Open(csvPath, OpenOptions{})
		if err != nil {
			t.Fatalf("Open() error = %v", err)
		}
		defer s.Close()

		creds, err := s.Read()
		if err != nil {
			t.Fatalf("Read() error = %v", err)
		}

		if len(creds) < 3 {
			t.Errorf("Read() returned %d credentials, want at least 3", len(creds))
		}

		// Verify credentials have expected fields
		for _, cred := range creds {
			if cred.ID == "" {
				t.Error("Credential ID should not be empty")
			}
			if cred.Type != model.TypeBasicAuth {
				t.Errorf("Credential type = %v, want TypeBasicAuth", cred.Type)
			}
		}
	})

	t.Run("GUID preservation", func(t *testing.T) {
		csvPath := filepath.Join(getTestdataPath(), "firefox", "logins.csv")
		if _, err := os.Stat(csvPath); os.IsNotExist(err) {
			t.Skip("testdata/firefox/logins.csv not found")
		}

		s := NewFirefoxSource()
		_ = s.Open(csvPath, OpenOptions{})
		defer s.Close()

		creds, _ := s.Read()

		// First entry should have the GUID as ID
		found := false
		for _, cred := range creds {
			if strings.Contains(cred.ID, "abc12345") {
				found = true
				break
			}
		}
		if !found {
			t.Error("GUID should be preserved as credential ID")
		}
	})

	t.Run("Timestamp parsing", func(t *testing.T) {
		csvPath := filepath.Join(getTestdataPath(), "firefox", "logins.csv")
		if _, err := os.Stat(csvPath); os.IsNotExist(err) {
			t.Skip("testdata/firefox/logins.csv not found")
		}

		s := NewFirefoxSource()
		_ = s.Open(csvPath, OpenOptions{})
		defer s.Close()

		creds, _ := s.Read()

		// First entry has timeCreated = 1704067200000 (2024-01-01 00:00:00 UTC)
		expectedTime := time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC)
		for _, cred := range creds {
			if strings.Contains(cred.URL, "example.com") {
				// Check that the Created time is close to expected
				diff := cred.Created.Sub(expectedTime)
				if diff < -time.Hour || diff > time.Hour {
					t.Errorf("Created time = %v, want around %v", cred.Created, expectedTime)
				}
				break
			}
		}
	})

	t.Run("HTTP Realm handling", func(t *testing.T) {
		csvPath := filepath.Join(getTestdataPath(), "firefox", "logins.csv")
		if _, err := os.Stat(csvPath); os.IsNotExist(err) {
			t.Skip("testdata/firefox/logins.csv not found")
		}

		s := NewFirefoxSource()
		_ = s.Open(csvPath, OpenOptions{})
		defer s.Close()

		creds, _ := s.Read()

		// Find the HTTP Basic Auth entry
		var httpAuthEntry *model.Credential
		for i := range creds {
			if strings.Contains(creds[i].URL, "intranet") {
				httpAuthEntry = &creds[i]
				break
			}
		}

		if httpAuthEntry == nil {
			t.Fatal("Should have found intranet entry")
		}

		if !strings.Contains(httpAuthEntry.Notes, "HTTP Basic Auth") {
			t.Error("HTTP Realm entry should have notes about HTTP Basic Auth")
		}
		if !strings.Contains(httpAuthEntry.Title, "HTTP Auth") {
			t.Error("HTTP Realm entry should indicate HTTP Auth in title")
		}
	})

	t.Run("Cached results", func(t *testing.T) {
		csvPath := filepath.Join(getTestdataPath(), "firefox", "logins.csv")
		if _, err := os.Stat(csvPath); os.IsNotExist(err) {
			t.Skip("testdata/firefox/logins.csv not found")
		}

		s := NewFirefoxSource()
		_ = s.Open(csvPath, OpenOptions{})
		defer s.Close()

		creds1, _ := s.Read()
		creds2, _ := s.Read()

		if len(creds1) != len(creds2) {
			t.Error("Cached results should be the same")
		}
	})
}

func TestFirefoxSource_Close(t *testing.T) {
	csvPath := filepath.Join(getTestdataPath(), "firefox", "logins.csv")
	if _, err := os.Stat(csvPath); os.IsNotExist(err) {
		t.Skip("testdata/firefox/logins.csv not found")
	}

	s := NewFirefoxSource()

	// Close without open should not error
	err := s.Close()
	if err != nil {
		t.Errorf("Close() without Open() error = %v", err)
	}

	_ = s.Open(csvPath, OpenOptions{})
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

func TestDetectFirefoxHeader(t *testing.T) {
	tests := []struct {
		name   string
		header []string
		want   int
	}{
		{
			name:   "Full Firefox header",
			header: []string{"url", "username", "password", "httpRealm", "formActionOrigin", "guid", "timeCreated", "timeLastUsed", "timePasswordChanged"},
			want:   100,
		},
		{
			name:   "Minimal with Firefox-specific",
			header: []string{"url", "username", "password", "guid", "httpRealm"},
			want:   100,
		},
		{
			name:   "One Firefox-specific column",
			header: []string{"url", "username", "password", "guid"},
			want:   80,
		},
		{
			name:   "Case insensitive",
			header: []string{"URL", "Username", "Password", "GUID", "HttpRealm"},
			want:   100,
		},
		{
			name:   "With whitespace",
			header: []string{"  url  ", "  username  ", "  password  ", "  guid  ", "  httpRealm  "},
			want:   100,
		},
		{
			name:   "Too few columns",
			header: []string{"url", "password"},
			want:   0,
		},
		{
			name:   "Chrome-style header (no Firefox-specific)",
			header: []string{"name", "url", "username", "password"},
			want:   0,
		},
		{
			name:   "Empty header",
			header: []string{},
			want:   0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := detectFirefoxHeader(tt.header); got != tt.want {
				t.Errorf("detectFirefoxHeader() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestExtractDomainFromURL(t *testing.T) {
	tests := []struct {
		name string
		url  string
		want string
	}{
		{"Full URL", "https://www.example.com/path", "www.example.com"},
		{"URL without path", "https://example.com", "example.com"},
		{"HTTP URL", "http://insecure.example.com", "insecure.example.com"},
		{"URL with port", "https://example.com:8080/path", "example.com:8080"},
		{"Empty URL", "", "Unknown"},
		{"Invalid URL", "not-a-url", "not-a-url"},
		{"URL without scheme", "example.com/path", "example.com"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := extractDomainFromURL(tt.url); got != tt.want {
				t.Errorf("extractDomainFromURL(%q) = %v, want %v", tt.url, got, tt.want)
			}
		})
	}
}

func TestParseMillisTimestamp(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		wantErr bool
	}{
		{"Valid timestamp", "1704067200000", false},
		{"Zero", "0", false},
		{"Invalid", "not-a-number", true},
		{"Empty", "", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := parseMillisTimestamp(tt.input)
			if tt.wantErr && !got.IsZero() {
				t.Errorf("parseMillisTimestamp(%q) should return zero time for invalid input", tt.input)
			}
			if !tt.wantErr && got.IsZero() && tt.input != "0" {
				t.Errorf("parseMillisTimestamp(%q) returned zero time for valid input", tt.input)
			}
		})
	}

	// Test specific timestamp
	t.Run("Specific timestamp", func(t *testing.T) {
		// 1704067200000 = 2024-01-01 00:00:00 UTC
		got := parseMillisTimestamp("1704067200000")
		expected := time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC)
		if !got.Equal(expected) {
			t.Errorf("parseMillisTimestamp() = %v, want %v", got, expected)
		}
	})
}

func TestDefaultRegistryHasFirefox(t *testing.T) {
	reg := DefaultRegistry()
	source, ok := reg.Get("firefox")
	if !ok {
		t.Error("Default registry should have firefox source")
	}
	if source.Name() != "firefox" {
		t.Errorf("Source name = %v, want firefox", source.Name())
	}
}
