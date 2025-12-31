package sources

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/nvinuesa/cxporter/internal/model"
)

func TestChromeSource_Interface(t *testing.T) {
	s := NewChromeSource()

	if s.Name() != "chrome" {
		t.Errorf("Name() = %v, want chrome", s.Name())
	}

	if s.Description() == "" {
		t.Error("Description() should not be empty")
	}

	exts := s.SupportedExtensions()
	if len(exts) != 1 || exts[0] != ".csv" {
		t.Errorf("SupportedExtensions() = %v, want [.csv]", exts)
	}
}

func TestChromeSource_Detect(t *testing.T) {
	s := NewChromeSource()

	t.Run("Non-existent path", func(t *testing.T) {
		_, err := s.Detect("/nonexistent/passwords.csv")
		if err == nil {
			t.Error("Expected error for non-existent path")
		}
	})

	t.Run("Directory instead of file", func(t *testing.T) {
		dir, err := os.MkdirTemp("", "chrometest")
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

	t.Run("Valid Chrome CSV", func(t *testing.T) {
		csvPath := filepath.Join(getTestdataPath(), "chrome", "passwords.csv")
		if _, err := os.Stat(csvPath); os.IsNotExist(err) {
			t.Skip("testdata/chrome/passwords.csv not found")
		}

		confidence, err := s.Detect(csvPath)
		if err != nil {
			t.Fatalf("Detect() error = %v", err)
		}
		if confidence != 100 {
			t.Errorf("Detect() on valid Chrome CSV should return 100, got %d", confidence)
		}
	})

	t.Run("Old format Chrome CSV", func(t *testing.T) {
		csvPath := filepath.Join(getTestdataPath(), "chrome", "passwords_old_format.csv")
		if _, err := os.Stat(csvPath); os.IsNotExist(err) {
			t.Skip("testdata/chrome/passwords_old_format.csv not found")
		}

		confidence, err := s.Detect(csvPath)
		if err != nil {
			t.Fatalf("Detect() error = %v", err)
		}
		if confidence != 100 {
			t.Errorf("Detect() on old format CSV should return 100, got %d", confidence)
		}
	})
}

func TestChromeSource_Open(t *testing.T) {
	t.Run("Non-existent file", func(t *testing.T) {
		s := NewChromeSource()
		err := s.Open("/nonexistent.csv", OpenOptions{})
		if err == nil {
			t.Error("Expected error for non-existent file")
		}
	})

	t.Run("Directory instead of file", func(t *testing.T) {
		dir, err := os.MkdirTemp("", "chrometest")
		if err != nil {
			t.Fatal(err)
		}
		defer os.RemoveAll(dir)

		s := NewChromeSource()
		err = s.Open(dir, OpenOptions{})
		if err == nil {
			t.Error("Expected error when opening directory")
		}
	})

	t.Run("Valid CSV file", func(t *testing.T) {
		csvPath := filepath.Join(getTestdataPath(), "chrome", "passwords.csv")
		if _, err := os.Stat(csvPath); os.IsNotExist(err) {
			t.Skip("testdata/chrome/passwords.csv not found")
		}

		s := NewChromeSource()
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

func TestChromeSource_Read(t *testing.T) {
	t.Run("Read before Open", func(t *testing.T) {
		s := NewChromeSource()
		_, err := s.Read()
		if err != ErrNotOpen {
			t.Errorf("Read() before Open() error = %v, want ErrNotOpen", err)
		}
	})

	t.Run("Read standard CSV", func(t *testing.T) {
		csvPath := filepath.Join(getTestdataPath(), "chrome", "passwords.csv")
		if _, err := os.Stat(csvPath); os.IsNotExist(err) {
			t.Skip("testdata/chrome/passwords.csv not found")
		}

		s := NewChromeSource()
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

	t.Run("Read old format CSV", func(t *testing.T) {
		csvPath := filepath.Join(getTestdataPath(), "chrome", "passwords_old_format.csv")
		if _, err := os.Stat(csvPath); os.IsNotExist(err) {
			t.Skip("testdata/chrome/passwords_old_format.csv not found")
		}

		s := NewChromeSource()
		err := s.Open(csvPath, OpenOptions{})
		if err != nil {
			t.Fatalf("Open() error = %v", err)
		}
		defer s.Close()

		creds, err := s.Read()
		if err != nil {
			t.Fatalf("Read() error = %v", err)
		}

		if len(creds) != 2 {
			t.Errorf("Read() returned %d credentials, want 2", len(creds))
		}

		// Old format shouldn't have notes
		for _, cred := range creds {
			if cred.Notes != "" {
				t.Error("Old format should not have notes")
			}
		}
	})

	t.Run("Read edge cases CSV", func(t *testing.T) {
		csvPath := filepath.Join(getTestdataPath(), "chrome", "edge_cases.csv")
		if _, err := os.Stat(csvPath); os.IsNotExist(err) {
			t.Skip("testdata/chrome/edge_cases.csv not found")
		}

		s := NewChromeSource()
		err := s.Open(csvPath, OpenOptions{})
		if err != nil {
			t.Fatalf("Open() error = %v", err)
		}
		defer s.Close()

		creds, err := s.Read()
		if err != nil {
			t.Fatalf("Read() error = %v", err)
		}

		// Should have parsed entries with commas, quotes, and unicode
		if len(creds) < 3 {
			t.Errorf("Read() returned %d credentials, want at least 3", len(creds))
		}

		// Find the comma entry
		var commaEntry *model.Credential
		for i := range creds {
			if strings.Contains(creds[i].Title, "comma") {
				commaEntry = &creds[i]
				break
			}
		}

		if commaEntry == nil {
			t.Fatal("Should have found entry with comma in name")
		}
		if !strings.Contains(commaEntry.Password, ",") {
			t.Error("Password with commas should be preserved")
		}

		// Find unicode entry
		var unicodeEntry *model.Credential
		for i := range creds {
			if strings.Contains(creds[i].Title, "Unicode") || strings.Contains(creds[i].Username, "用户") {
				unicodeEntry = &creds[i]
				break
			}
		}

		if unicodeEntry == nil {
			t.Fatal("Should have found unicode entry")
		}
	})

	t.Run("Cached results", func(t *testing.T) {
		csvPath := filepath.Join(getTestdataPath(), "chrome", "passwords.csv")
		if _, err := os.Stat(csvPath); os.IsNotExist(err) {
			t.Skip("testdata/chrome/passwords.csv not found")
		}

		s := NewChromeSource()
		_ = s.Open(csvPath, OpenOptions{})
		defer s.Close()

		creds1, _ := s.Read()
		creds2, _ := s.Read()

		if len(creds1) != len(creds2) {
			t.Error("Cached results should be the same")
		}
	})
}

func TestChromeSource_Close(t *testing.T) {
	csvPath := filepath.Join(getTestdataPath(), "chrome", "passwords.csv")
	if _, err := os.Stat(csvPath); os.IsNotExist(err) {
		t.Skip("testdata/chrome/passwords.csv not found")
	}

	s := NewChromeSource()

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

func TestDetectChromeHeader(t *testing.T) {
	tests := []struct {
		name   string
		header []string
		want   int
	}{
		{
			name:   "Full Chrome header",
			header: []string{"name", "url", "username", "password", "note"},
			want:   100,
		},
		{
			name:   "Old Chrome header",
			header: []string{"name", "url", "username", "password"},
			want:   100,
		},
		{
			name:   "With extra columns",
			header: []string{"name", "url", "username", "password", "note", "extra"},
			want:   100,
		},
		{
			name:   "Case insensitive",
			header: []string{"Name", "URL", "UserName", "Password"},
			want:   100,
		},
		{
			name:   "With whitespace",
			header: []string{"  name  ", "  url  ", "  username  ", "  password  "},
			want:   100,
		},
		{
			name:   "Missing one column",
			header: []string{"name", "url", "password", "extra"},
			want:   70,
		},
		{
			name:   "Too few columns",
			header: []string{"name", "url"},
			want:   0,
		},
		{
			name:   "Wrong column names",
			header: []string{"title", "website", "user", "pass"},
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
			if got := detectChromeHeader(tt.header); got != tt.want {
				t.Errorf("detectChromeHeader() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestIsEmptyRecord(t *testing.T) {
	tests := []struct {
		name   string
		record []string
		want   bool
	}{
		{"Empty strings", []string{"", "", "", ""}, true},
		{"Whitespace only", []string{"  ", "\t", " \n "}, true},
		{"With content", []string{"", "value", ""}, false},
		{"Empty slice", []string{}, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := isEmptyRecord(tt.record); got != tt.want {
				t.Errorf("isEmptyRecord() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestBOMSkippingReader(t *testing.T) {
	t.Run("With BOM", func(t *testing.T) {
		// UTF-8 BOM + "hello"
		input := append([]byte{0xEF, 0xBB, 0xBF}, []byte("hello")...)
		reader := newBOMSkippingReader(strings.NewReader(string(input)))

		buf := make([]byte, 10)
		n, err := reader.Read(buf)
		if err != nil {
			t.Fatalf("Read() error = %v", err)
		}

		result := string(buf[:n])
		if result != "hello" {
			t.Errorf("Read() = %q, want %q", result, "hello")
		}
	})

	t.Run("Without BOM", func(t *testing.T) {
		input := "hello"
		reader := newBOMSkippingReader(strings.NewReader(input))

		buf := make([]byte, 10)
		n, err := reader.Read(buf)
		if err != nil {
			t.Fatalf("Read() error = %v", err)
		}

		result := string(buf[:n])
		if result != "hello" {
			t.Errorf("Read() = %q, want %q", result, "hello")
		}
	})
}

func TestDefaultRegistryHasChrome(t *testing.T) {
	reg := DefaultRegistry()
	source, ok := reg.Get("chrome")
	if !ok {
		t.Error("Default registry should have chrome source")
	}
	if source.Name() != "chrome" {
		t.Errorf("Source name = %v, want chrome", source.Name())
	}
}
