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

	// SSH source now works with files, supports .pem extension
	exts := s.SupportedExtensions()
	if len(exts) != 1 || exts[0] != ".pem" {
		t.Errorf("SupportedExtensions() = %v, want [.pem]", exts)
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

	t.Run("Directory instead of file", func(t *testing.T) {
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
			t.Errorf("Detect() on directory should return 0, got %d", confidence)
		}
	})

	t.Run("Non-SSH file", func(t *testing.T) {
		f, err := os.CreateTemp("", "sshtest")
		if err != nil {
			t.Fatal(err)
		}
		defer os.Remove(f.Name())
		f.WriteString("not a key file")
		f.Close()

		confidence, err := s.Detect(f.Name())
		if err != nil {
			t.Fatalf("Detect() error = %v", err)
		}
		if confidence != 0 {
			t.Errorf("Detect() on non-SSH file should return 0, got %d", confidence)
		}
	})

	t.Run("Valid SSH key file", func(t *testing.T) {
		testKey := filepath.Join(getTestdataPath(), "ssh", "id_ed25519")
		if _, err := os.Stat(testKey); os.IsNotExist(err) {
			t.Skip("testdata/ssh/id_ed25519 not found")
		}

		confidence, err := s.Detect(testKey)
		if err != nil {
			t.Fatalf("Detect() error = %v", err)
		}
		if confidence != 100 {
			t.Errorf("Detect() should return 100 for valid SSH key, got %d", confidence)
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

	t.Run("Directory instead of file", func(t *testing.T) {
		dir, err := os.MkdirTemp("", "sshtest")
		if err != nil {
			t.Fatal(err)
		}
		defer os.RemoveAll(dir)

		s := NewSSHSource()
		err = s.Open(dir, OpenOptions{})
		if err == nil {
			t.Error("Expected error when opening a directory")
		}
	})

	t.Run("Valid SSH key file", func(t *testing.T) {
		testKey := filepath.Join(getTestdataPath(), "ssh", "id_ed25519")
		if _, err := os.Stat(testKey); os.IsNotExist(err) {
			t.Skip("testdata/ssh/id_ed25519 not found")
		}

		s := NewSSHSource()
		err := s.Open(testKey, OpenOptions{})
		if err != nil {
			t.Fatalf("Open() error = %v", err)
		}
		defer s.Close()

		// Double open should fail
		err = s.Open(testKey, OpenOptions{})
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

	t.Run("Read unencrypted Ed25519 key", func(t *testing.T) {
		s := NewSSHSource()
		testKey := filepath.Join(testDir, "id_ed25519")
		err := s.Open(testKey, OpenOptions{})
		if err != nil {
			t.Fatalf("Open() error = %v", err)
		}
		defer s.Close()

		creds, err := s.Read()
		if err != nil {
			t.Fatalf("Read() error = %v", err)
		}

		if len(creds) != 1 {
			t.Fatalf("Read() returned %d credentials, want 1", len(creds))
		}

		cred := creds[0]
		if cred.Type != model.TypeSSHKey {
			t.Errorf("Credential type = %v, want TypeSSHKey", cred.Type)
		}
		if cred.SSHKey == nil {
			t.Fatal("SSHKey data should not be nil")
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
		if cred.SSHKey.KeyType != model.SSHKeyTypeEd25519 {
			t.Errorf("KeyType = %v, want ed25519", cred.SSHKey.KeyType)
		}
	})

	t.Run("Read unencrypted RSA key", func(t *testing.T) {
		s := NewSSHSource()
		testKey := filepath.Join(testDir, "id_rsa")
		err := s.Open(testKey, OpenOptions{})
		if err != nil {
			t.Fatalf("Open() error = %v", err)
		}
		defer s.Close()

		creds, err := s.Read()
		if err != nil {
			t.Fatalf("Read() error = %v", err)
		}

		if len(creds) != 1 {
			t.Fatalf("Read() returned %d credentials, want 1", len(creds))
		}

		if creds[0].SSHKey.KeyType != model.SSHKeyTypeRSA {
			t.Errorf("KeyType = %v, want rsa", creds[0].SSHKey.KeyType)
		}
	})

	t.Run("Read unencrypted ECDSA key", func(t *testing.T) {
		s := NewSSHSource()
		testKey := filepath.Join(testDir, "id_ecdsa")
		err := s.Open(testKey, OpenOptions{})
		if err != nil {
			t.Fatalf("Open() error = %v", err)
		}
		defer s.Close()

		creds, err := s.Read()
		if err != nil {
			t.Fatalf("Read() error = %v", err)
		}

		if len(creds) != 1 {
			t.Fatalf("Read() returned %d credentials, want 1", len(creds))
		}

		if creds[0].SSHKey.KeyType != model.SSHKeyTypeECDSA {
			t.Errorf("KeyType = %v, want ecdsa", creds[0].SSHKey.KeyType)
		}
	})

	t.Run("Read encrypted key without password", func(t *testing.T) {
		s := NewSSHSource()
		testKey := filepath.Join(testDir, "id_encrypted")
		err := s.Open(testKey, OpenOptions{})
		if err != nil {
			t.Fatalf("Open() error = %v", err)
		}
		defer s.Close()

		_, err = s.Read()
		if err == nil {
			t.Fatal("Read() should fail for encrypted key without password")
		}
		if !IsAuthError(err) {
			t.Errorf("Expected auth error, got %v", err)
		}
	})

	t.Run("Read encrypted key with password", func(t *testing.T) {
		s := NewSSHSource()
		testKey := filepath.Join(testDir, "id_encrypted")
		err := s.Open(testKey, OpenOptions{
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

		if len(creds) != 1 {
			t.Fatalf("Read() returned %d credentials, want 1", len(creds))
		}

		if !creds[0].SSHKey.Encrypted {
			t.Error("Encrypted key should have Encrypted=true")
		}
	})

	t.Run("Cached results", func(t *testing.T) {
		s := NewSSHSource()
		testKey := filepath.Join(testDir, "id_ed25519")
		err := s.Open(testKey, OpenOptions{})
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

	testKey := filepath.Join(getTestdataPath(), "ssh", "id_ed25519")
	if _, err := os.Stat(testKey); os.IsNotExist(err) {
		t.Skip("testdata/ssh/id_ed25519 not found")
	}

	s = NewSSHSource()
	_ = s.Open(testKey, OpenOptions{})
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

func TestSSHSource_Comments(t *testing.T) {
	testKey := filepath.Join(getTestdataPath(), "ssh", "id_ed25519")
	if _, err := os.Stat(testKey); os.IsNotExist(err) {
		t.Skip("testdata/ssh/id_ed25519 not found")
	}

	s := NewSSHSource()
	err := s.Open(testKey, OpenOptions{})
	if err != nil {
		t.Fatalf("Open() error = %v", err)
	}
	defer s.Close()

	creds, _ := s.Read()

	// The key should have a comment from .pub file
	if len(creds) > 0 && creds[0].SSHKey != nil {
		if !strings.Contains(creds[0].SSHKey.Comment, "@example.com") {
			t.Logf("Comment: %s (may not have @example.com)", creds[0].SSHKey.Comment)
		}
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
		name   string
		errMsg string
		want   bool
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
