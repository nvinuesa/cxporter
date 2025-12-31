package sources

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/nvinuesa/cxporter/internal/model"
)

func TestSSHSource_Interface(t *testing.T) {
	s := NewSSHSource()

	if s.Name() != "ssh" {
		t.Errorf("Name() = %v, want ssh", s.Name())
	}

	if s.Description() == "" {
		t.Error("Description() should not be empty")
	}

	// SSH source uses directories, not file extensions
	if len(s.SupportedExtensions()) != 0 {
		t.Error("SupportedExtensions() should be empty for directory-based source")
	}
}

func TestSSHSource_Detect(t *testing.T) {
	s := NewSSHSource()

	t.Run("Non-existent path", func(t *testing.T) {
		_, err := s.Detect("/nonexistent/path")
		if err == nil {
			t.Error("Expected error for non-existent path")
		}
	})

	t.Run("File instead of directory", func(t *testing.T) {
		// Create a temp file
		f, err := os.CreateTemp("", "sshtest")
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
			t.Errorf("Detect() on file should return 0, got %d", confidence)
		}
	})

	t.Run("Empty directory", func(t *testing.T) {
		dir, err := os.MkdirTemp("", "sshtest")
		if err != nil {
			t.Fatal(err)
		}
		defer os.RemoveAll(dir)

		confidence, err := s.Detect(dir)
		if err != nil {
			t.Fatalf("Detect() error = %v", err)
		}
		if confidence != 0 {
			t.Errorf("Detect() on empty dir should return 0, got %d", confidence)
		}
	})

	t.Run("Directory with SSH keys", func(t *testing.T) {
		// Use the testdata directory
		testDir := filepath.Join(getTestdataPath(), "ssh")
		if _, err := os.Stat(testDir); os.IsNotExist(err) {
			t.Skip("testdata/ssh not found")
		}

		confidence, err := s.Detect(testDir)
		if err != nil {
			t.Fatalf("Detect() error = %v", err)
		}
		if confidence == 0 {
			t.Error("Detect() should return non-zero confidence for directory with SSH keys")
		}
	})

	t.Run("Directory named .ssh", func(t *testing.T) {
		dir, err := os.MkdirTemp("", "parent")
		if err != nil {
			t.Fatal(err)
		}
		defer os.RemoveAll(dir)

		sshDir := filepath.Join(dir, ".ssh")
		if err := os.Mkdir(sshDir, 0700); err != nil {
			t.Fatal(err)
		}

		// Create a dummy key file
		keyFile := filepath.Join(sshDir, "id_test")
		if err := os.WriteFile(keyFile, []byte("key"), 0600); err != nil {
			t.Fatal(err)
		}

		confidence, err := s.Detect(sshDir)
		if err != nil {
			t.Fatalf("Detect() error = %v", err)
		}
		if confidence != 100 {
			t.Errorf("Detect() on .ssh dir should return 100, got %d", confidence)
		}
	})
}

func TestSSHSource_Open(t *testing.T) {
	s := NewSSHSource()

	t.Run("Non-existent path", func(t *testing.T) {
		err := s.Open("/nonexistent/path", OpenOptions{})
		if err == nil {
			t.Error("Expected error for non-existent path")
		}
	})

	t.Run("File instead of directory", func(t *testing.T) {
		f, err := os.CreateTemp("", "sshtest")
		if err != nil {
			t.Fatal(err)
		}
		defer os.Remove(f.Name())
		f.Close()

		err = s.Open(f.Name(), OpenOptions{})
		if err == nil {
			t.Error("Expected error when opening a file")
		}
	})

	t.Run("Valid directory", func(t *testing.T) {
		testDir := filepath.Join(getTestdataPath(), "ssh")
		if _, err := os.Stat(testDir); os.IsNotExist(err) {
			t.Skip("testdata/ssh not found")
		}

		s := NewSSHSource()
		err := s.Open(testDir, OpenOptions{})
		if err != nil {
			t.Fatalf("Open() error = %v", err)
		}
		defer s.Close()

		// Double open should fail
		err = s.Open(testDir, OpenOptions{})
		if err != ErrAlreadyOpen {
			t.Errorf("Double Open() error = %v, want ErrAlreadyOpen", err)
		}
	})
}

func TestSSHSource_Read(t *testing.T) {
	testDir := filepath.Join(getTestdataPath(), "ssh")
	if _, err := os.Stat(testDir); os.IsNotExist(err) {
		t.Skip("testdata/ssh not found")
	}

	t.Run("Read before Open", func(t *testing.T) {
		s := NewSSHSource()
		_, err := s.Read()
		if err != ErrNotOpen {
			t.Errorf("Read() before Open() error = %v, want ErrNotOpen", err)
		}
	})

	t.Run("Read unencrypted keys", func(t *testing.T) {
		s := NewSSHSource()
		err := s.Open(testDir, OpenOptions{})
		if err != nil {
			t.Fatalf("Open() error = %v", err)
		}
		defer s.Close()

		creds, err := s.Read()
		// We expect partial read because of the encrypted key
		if err != nil && !IsPartialRead(err) {
			t.Fatalf("Read() error = %v", err)
		}

		// Should have at least 3 unencrypted keys
		if len(creds) < 3 {
			t.Errorf("Read() returned %d credentials, want at least 3", len(creds))
		}

		// Verify credentials have expected fields
		for _, cred := range creds {
			if cred.Type != model.TypeSSHKey {
				t.Errorf("Credential type = %v, want TypeSSHKey", cred.Type)
			}
			if cred.SSHKey == nil {
				t.Error("SSHKey data should not be nil")
				continue
			}
			if cred.SSHKey.PrivateKey == "" {
				t.Error("PrivateKey should not be empty")
			}
			if cred.SSHKey.PublicKey == "" {
				t.Error("PublicKey should not be empty")
			}
			if cred.SSHKey.Fingerprint == "" {
				t.Error("Fingerprint should not be empty")
			}
			if !strings.HasPrefix(cred.SSHKey.Fingerprint, "SHA256:") {
				t.Errorf("Fingerprint should start with SHA256:, got %s", cred.SSHKey.Fingerprint)
			}
		}
	})

	t.Run("Read with password for encrypted key", func(t *testing.T) {
		s := NewSSHSource()
		err := s.Open(testDir, OpenOptions{
			Password: "testpassword",
		})
		if err != nil {
			t.Fatalf("Open() error = %v", err)
		}
		defer s.Close()

		creds, err := s.Read()
		if err != nil {
			t.Fatalf("Read() error = %v", err)
		}

		// Should have all 4 keys now
		if len(creds) < 4 {
			t.Errorf("Read() returned %d credentials, want at least 4", len(creds))
		}

		// Find the encrypted key
		var encryptedKey *model.Credential
		for i := range creds {
			if strings.Contains(creds[i].Title, "encrypted") {
				encryptedKey = &creds[i]
				break
			}
		}

		if encryptedKey == nil {
			t.Error("Should have found the encrypted key")
		} else if !encryptedKey.SSHKey.Encrypted {
			t.Error("Encrypted key should have Encrypted=true")
		}
	})

	t.Run("Cached results", func(t *testing.T) {
		s := NewSSHSource()
		err := s.Open(testDir, OpenOptions{Password: "testpassword"})
		if err != nil {
			t.Fatalf("Open() error = %v", err)
		}
		defer s.Close()

		creds1, _ := s.Read()
		creds2, _ := s.Read()

		if len(creds1) != len(creds2) {
			t.Error("Cached results should be the same")
		}
	})
}

func TestSSHSource_Close(t *testing.T) {
	s := NewSSHSource()

	// Close without open should not error
	err := s.Close()
	if err != nil {
		t.Errorf("Close() without Open() error = %v", err)
	}

	testDir := filepath.Join(getTestdataPath(), "ssh")
	if _, err := os.Stat(testDir); os.IsNotExist(err) {
		t.Skip("testdata/ssh not found")
	}

	s = NewSSHSource()
	_ = s.Open(testDir, OpenOptions{Password: "testpassword"})
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

func TestSSHSource_KeyTypes(t *testing.T) {
	testDir := filepath.Join(getTestdataPath(), "ssh")
	if _, err := os.Stat(testDir); os.IsNotExist(err) {
		t.Skip("testdata/ssh not found")
	}

	s := NewSSHSource()
	err := s.Open(testDir, OpenOptions{Password: "testpassword"})
	if err != nil {
		t.Fatalf("Open() error = %v", err)
	}
	defer s.Close()

	creds, _ := s.Read()

	keyTypes := make(map[model.SSHKeyType]bool)
	for _, cred := range creds {
		if cred.SSHKey != nil {
			keyTypes[cred.SSHKey.KeyType] = true
		}
	}

	expectedTypes := []model.SSHKeyType{
		model.SSHKeyTypeEd25519,
		model.SSHKeyTypeRSA,
		model.SSHKeyTypeECDSA,
	}

	for _, expected := range expectedTypes {
		if !keyTypes[expected] {
			t.Errorf("Missing key type: %s", expected)
		}
	}
}

func TestSSHSource_Comments(t *testing.T) {
	testDir := filepath.Join(getTestdataPath(), "ssh")
	if _, err := os.Stat(testDir); os.IsNotExist(err) {
		t.Skip("testdata/ssh not found")
	}

	s := NewSSHSource()
	err := s.Open(testDir, OpenOptions{Password: "testpassword"})
	if err != nil {
		t.Fatalf("Open() error = %v", err)
	}
	defer s.Close()

	creds, _ := s.Read()

	// At least one key should have a comment from .pub file
	hasComment := false
	for _, cred := range creds {
		if cred.SSHKey != nil && strings.Contains(cred.SSHKey.Comment, "@example.com") {
			hasComment = true
			break
		}
	}

	if !hasComment {
		t.Error("At least one key should have a comment from .pub file")
	}
}

func TestIsSSHPrivateKeyFilename(t *testing.T) {
	tests := []struct {
		name     string
		filename string
		want     bool
	}{
		{"id_rsa", "id_rsa", true},
		{"id_ed25519", "id_ed25519", true},
		{"id_ecdsa", "id_ecdsa", true},
		{"custom_key", "my_key", true},
		{"pem file", "server.pem", true},
		{"identity", "identity", true},
		{"public key", "id_rsa.pub", false},
		{"known_hosts", "known_hosts", false},
		{"config", "config", false},
		{"authorized_keys", "authorized_keys", false},
		{"random file", "random_file.txt", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := isSSHPrivateKeyFilename(tt.filename); got != tt.want {
				t.Errorf("isSSHPrivateKeyFilename(%q) = %v, want %v", tt.filename, got, tt.want)
			}
		})
	}
}

func TestIsPassphraseError(t *testing.T) {
	tests := []struct {
		name    string
		errMsg  string
		want    bool
	}{
		{"passphrase error", "passphrase required", true},
		{"password error", "bad password", true},
		{"encrypted error", "key is encrypted", true},
		{"decryption error", "decryption failed", true},
		{"other error", "file not found", false},
		{"nil error", "", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var err error
			if tt.errMsg != "" {
				err = &testError{msg: tt.errMsg}
			}
			if got := isPassphraseError(err); got != tt.want {
				t.Errorf("isPassphraseError(%q) = %v, want %v", tt.errMsg, got, tt.want)
			}
		})
	}
}

type testError struct {
	msg string
}

func (e *testError) Error() string {
	return e.msg
}

func TestDefaultRegistryHasSSH(t *testing.T) {
	reg := DefaultRegistry()
	source, ok := reg.Get("ssh")
	if !ok {
		t.Error("Default registry should have ssh source")
	}
	if source.Name() != "ssh" {
		t.Errorf("Source name = %v, want ssh", source.Name())
	}
}

// getTestdataPath returns the path to the testdata directory.
func getTestdataPath() string {
	// Try to find testdata relative to the package
	wd, err := os.Getwd()
	if err != nil {
		return "testdata"
	}

	// Walk up to find the testdata directory
	for dir := wd; dir != "/" && dir != "."; dir = filepath.Dir(dir) {
		testdata := filepath.Join(dir, "testdata")
		if info, err := os.Stat(testdata); err == nil && info.IsDir() {
			return testdata
		}
	}

	return filepath.Join(wd, "..", "..", "testdata")
}
