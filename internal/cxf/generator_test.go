package cxf

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/nvinuesa/go-cxf"

	"github.com/nvinuesa/cxporter/internal/model"
)

func TestGenerate(t *testing.T) {
	t.Run("Empty credentials", func(t *testing.T) {
		_, err := Generate(nil, DefaultOptions())
		if err != ErrNoCredentials {
			t.Errorf("Generate() with nil error = %v, want ErrNoCredentials", err)
		}

		_, err = Generate([]model.Credential{}, DefaultOptions())
		if err != ErrNoCredentials {
			t.Errorf("Generate() with empty slice error = %v, want ErrNoCredentials", err)
		}
	})

	t.Run("Missing RP ID", func(t *testing.T) {
		creds := []model.Credential{{Title: "Test", Type: model.TypeBasicAuth}}
		opts := GeneratorOptions{ExporterName: "test"}
		_, err := Generate(creds, opts)
		if err != ErrMissingRpID {
			t.Errorf("Generate() without RP ID error = %v, want ErrMissingRpID", err)
		}
	})

	t.Run("Missing exporter name", func(t *testing.T) {
		creds := []model.Credential{{Title: "Test", Type: model.TypeBasicAuth}}
		opts := GeneratorOptions{ExporterRpID: "test.local"}
		_, err := Generate(creds, opts)
		if err != ErrMissingExporter {
			t.Errorf("Generate() without exporter name error = %v, want ErrMissingExporter", err)
		}
	})

	t.Run("Basic generation", func(t *testing.T) {
		now := time.Now()
		creds := []model.Credential{
			{
				ID:       "test-id-1",
				Type:     model.TypeBasicAuth,
				Title:    "Test Site",
				Username: "user",
				Password: "pass",
				URL:      "https://example.com",
				Created:  now,
				Modified: now,
			},
		}

		opts := DefaultOptions()
		opts.AccountUsername = "testuser"
		opts.AccountEmail = "test@example.com"

		header, err := Generate(creds, opts)
		if err != nil {
			t.Fatalf("Generate() error = %v", err)
		}

		// Check header fields
		if header.Version.Major != cxf.VersionMajor {
			t.Errorf("Version.Major = %v, want %v", header.Version.Major, cxf.VersionMajor)
		}
		if header.Version.Minor != cxf.VersionMinor {
			t.Errorf("Version.Minor = %v, want %v", header.Version.Minor, cxf.VersionMinor)
		}
		if header.ExporterRpId != opts.ExporterRpID {
			t.Errorf("ExporterRpId = %v, want %v", header.ExporterRpId, opts.ExporterRpID)
		}
		if header.ExporterDisplayName != opts.ExporterName {
			t.Errorf("ExporterDisplayName = %v, want %v", header.ExporterDisplayName, opts.ExporterName)
		}
		if header.Timestamp == 0 {
			t.Error("Timestamp should not be zero")
		}

		// Check accounts
		if len(header.Accounts) != 1 {
			t.Fatalf("Expected 1 account, got %d", len(header.Accounts))
		}

		account := header.Accounts[0]
		if account.Username != opts.AccountUsername {
			t.Errorf("Account.Username = %v, want %v", account.Username, opts.AccountUsername)
		}
		if account.Email != opts.AccountEmail {
			t.Errorf("Account.Email = %v, want %v", account.Email, opts.AccountEmail)
		}

		// Check items
		if len(account.Items) != 1 {
			t.Fatalf("Expected 1 item, got %d", len(account.Items))
		}

		item := account.Items[0]
		if item.Title != "Test Site" {
			t.Errorf("Item.Title = %v, want Test Site", item.Title)
		}
		if item.Scope == nil || len(item.Scope.Urls) == 0 {
			t.Error("Item.Scope.Urls should have the URL")
		} else if item.Scope.Urls[0] != "https://example.com" {
			t.Errorf("Item.Scope.Urls[0] = %v, want https://example.com", item.Scope.Urls[0])
		}
	})

	t.Run("With collections", func(t *testing.T) {
		creds := []model.Credential{
			{
				ID:         "cred1",
				Type:       model.TypeBasicAuth,
				Title:      "Work Site",
				FolderPath: "Work/Servers",
			},
			{
				ID:         "cred2",
				Type:       model.TypeBasicAuth,
				Title:      "Personal Site",
				FolderPath: "Personal",
			},
		}

		opts := DefaultOptions()
		opts.PreserveHierarchy = true

		header, err := Generate(creds, opts)
		if err != nil {
			t.Fatalf("Generate() error = %v", err)
		}

		// Should have collections
		if len(header.Accounts[0].Collections) == 0 {
			t.Error("Expected collections to be created from folder paths")
		}
	})

	t.Run("Without hierarchy preservation", func(t *testing.T) {
		creds := []model.Credential{
			{
				ID:         "cred1",
				Type:       model.TypeBasicAuth,
				Title:      "Test",
				FolderPath: "Some/Path",
			},
		}

		opts := DefaultOptions()
		opts.PreserveHierarchy = false

		header, err := Generate(creds, opts)
		if err != nil {
			t.Fatalf("Generate() error = %v", err)
		}

		if len(header.Accounts[0].Collections) != 0 {
			t.Error("Collections should be empty when PreserveHierarchy is false")
		}
	})
}

func TestMapCredentialToItem(t *testing.T) {
	t.Run("BasicAuth credential", func(t *testing.T) {
		cred := &model.Credential{
			ID:       "basic-auth-id",
			Type:     model.TypeBasicAuth,
			Title:    "My Account",
			Username: "user@example.com",
			Password: "secret123",
			URL:      "https://example.com",
			Tags:     []string{"work", "important"},
			Notes:    "Some notes here",
		}

		item, err := mapCredentialToItem(cred)
		if err != nil {
			t.Fatalf("mapCredentialToItem() error = %v", err)
		}

		if item.Title != cred.Title {
			t.Errorf("Title = %v, want %v", item.Title, cred.Title)
		}
		if len(item.Tags) != 2 {
			t.Errorf("Tags count = %d, want 2", len(item.Tags))
		}

		// Should have 2 credentials: basic-auth + notes
		if len(item.Credentials) != 2 {
			t.Errorf("Credentials count = %d, want 2 (basic-auth + notes)", len(item.Credentials))
		}
	})

	t.Run("TOTP credential", func(t *testing.T) {
		cred := &model.Credential{
			ID:    "totp-id",
			Type:  model.TypeTOTP,
			Title: "TOTP Account",
			TOTP: &model.TOTPData{
				Secret:    "JBSWY3DPEHPK3PXP",
				Algorithm: model.TOTPAlgorithmSHA1,
				Digits:    6,
				Period:    30,
				Issuer:    "Example",
			},
		}

		item, err := mapCredentialToItem(cred)
		if err != nil {
			t.Fatalf("mapCredentialToItem() error = %v", err)
		}

		if len(item.Credentials) != 1 {
			t.Fatalf("Credentials count = %d, want 1", len(item.Credentials))
		}

		var totpCred cxf.TOTPCredential
		if err := json.Unmarshal(item.Credentials[0], &totpCred); err != nil {
			t.Fatalf("Failed to unmarshal TOTP credential: %v", err)
		}

		if totpCred.Type != cxf.CredentialTypeTOTP {
			t.Errorf("Type = %v, want %v", totpCred.Type, cxf.CredentialTypeTOTP)
		}
		if totpCred.Secret != cred.TOTP.Secret {
			t.Errorf("Secret = %v, want %v", totpCred.Secret, cred.TOTP.Secret)
		}
		if totpCred.Algorithm != cxf.OTPHashAlgorithmSha1 {
			t.Errorf("Algorithm = %v, want sha1", totpCred.Algorithm)
		}
	})

	t.Run("SSH key credential", func(t *testing.T) {
		cred := &model.Credential{
			ID:    "ssh-id",
			Type:  model.TypeSSHKey,
			Title: "SSH Key",
			SSHKey: &model.SSHKeyData{
				KeyType:    model.SSHKeyTypeEd25519,
				PrivateKey: "private-key-content",
				Comment:    "user@host",
			},
		}

		item, err := mapCredentialToItem(cred)
		if err != nil {
			t.Fatalf("mapCredentialToItem() error = %v", err)
		}

		var sshCred cxf.SSHKeyCredential
		if err := json.Unmarshal(item.Credentials[0], &sshCred); err != nil {
			t.Fatalf("Failed to unmarshal SSH credential: %v", err)
		}

		if sshCred.Type != cxf.CredentialTypeSSHKey {
			t.Errorf("Type = %v, want %v", sshCred.Type, cxf.CredentialTypeSSHKey)
		}
		if sshCred.KeyType != "ssh-ed25519" {
			t.Errorf("KeyType = %v, want ssh-ed25519", sshCred.KeyType)
		}
	})

	t.Run("Note credential", func(t *testing.T) {
		cred := &model.Credential{
			ID:    "note-id",
			Type:  model.TypeNote,
			Title: "My Note",
			Notes: "This is a secure note",
		}

		item, err := mapCredentialToItem(cred)
		if err != nil {
			t.Fatalf("mapCredentialToItem() error = %v", err)
		}

		var noteCred cxf.NoteCredential
		if err := json.Unmarshal(item.Credentials[0], &noteCred); err != nil {
			t.Fatalf("Failed to unmarshal Note credential: %v", err)
		}

		if noteCred.Type != cxf.CredentialTypeNote {
			t.Errorf("Type = %v, want %v", noteCred.Type, cxf.CredentialTypeNote)
		}
	})

	t.Run("Credit card credential", func(t *testing.T) {
		cred := &model.Credential{
			ID:    "cc-id",
			Type:  model.TypeCreditCard,
			Title: "My Credit Card",
			CreditCard: &model.CreditCardData{
				Number:      "4111111111111111",
				Holder:      "John Doe",
				ExpiryMonth: 12,
				ExpiryYear:  2025,
				CVV:         "123",
				Brand:       "Visa",
			},
		}

		item, err := mapCredentialToItem(cred)
		if err != nil {
			t.Fatalf("mapCredentialToItem() error = %v", err)
		}

		var ccCred cxf.CreditCardCredential
		if err := json.Unmarshal(item.Credentials[0], &ccCred); err != nil {
			t.Fatalf("Failed to unmarshal Credit Card credential: %v", err)
		}

		if ccCred.Type != cxf.CredentialTypeCreditCard {
			t.Errorf("Type = %v, want %v", ccCred.Type, cxf.CredentialTypeCreditCard)
		}
	})

	t.Run("API key credential", func(t *testing.T) {
		cred := &model.Credential{
			ID:       "api-id",
			Type:     model.TypeAPIKey,
			Title:    "API Key",
			Username: "service-account",
			Password: "api-key-value",
			URL:      "https://api.example.com",
		}

		item, err := mapCredentialToItem(cred)
		if err != nil {
			t.Fatalf("mapCredentialToItem() error = %v", err)
		}

		var apiCred cxf.APIKeyCredential
		if err := json.Unmarshal(item.Credentials[0], &apiCred); err != nil {
			t.Fatalf("Failed to unmarshal API Key credential: %v", err)
		}

		if apiCred.Type != cxf.CredentialTypeAPIKey {
			t.Errorf("Type = %v, want %v", apiCred.Type, cxf.CredentialTypeAPIKey)
		}
	})

	t.Run("WiFi credential", func(t *testing.T) {
		cred := &model.Credential{
			ID:       "wifi-id",
			Type:     model.TypeWiFi,
			Title:    "Home WiFi",
			Password: "wifi-password",
		}

		item, err := mapCredentialToItem(cred)
		if err != nil {
			t.Fatalf("mapCredentialToItem() error = %v", err)
		}

		var wifiCred cxf.WiFiCredential
		if err := json.Unmarshal(item.Credentials[0], &wifiCred); err != nil {
			t.Fatalf("Failed to unmarshal WiFi credential: %v", err)
		}

		if wifiCred.Type != cxf.CredentialTypeWiFi {
			t.Errorf("Type = %v, want %v", wifiCred.Type, cxf.CredentialTypeWiFi)
		}
	})

	t.Run("With custom fields", func(t *testing.T) {
		cred := &model.Credential{
			ID:    "custom-id",
			Type:  model.TypeBasicAuth,
			Title: "Custom",
			CustomFields: map[string]string{
				"custom_field":  "value",
				"secret_token":  "secret",
				"another_field": "data",
			},
		}

		item, err := mapCredentialToItem(cred)
		if err != nil {
			t.Fatalf("mapCredentialToItem() error = %v", err)
		}

		// Should have basic-auth + custom-fields
		if len(item.Credentials) != 2 {
			t.Errorf("Credentials count = %d, want 2", len(item.Credentials))
		}
	})
}

func TestBuildCollections(t *testing.T) {
	t.Run("No folder paths", func(t *testing.T) {
		creds := []model.Credential{
			{ID: "1", Title: "Test1"},
			{ID: "2", Title: "Test2"},
		}

		collections := BuildCollections(creds)
		if len(collections) != 0 {
			t.Errorf("Expected 0 collections, got %d", len(collections))
		}
	})

	t.Run("Single level folders", func(t *testing.T) {
		creds := []model.Credential{
			{ID: "1", Title: "Test1", FolderPath: "Work"},
			{ID: "2", Title: "Test2", FolderPath: "Personal"},
			{ID: "3", Title: "Test3", FolderPath: "Work"},
		}

		collections := BuildCollections(creds)
		if len(collections) != 2 {
			t.Fatalf("Expected 2 collections, got %d", len(collections))
		}

		// Find Work collection
		var workCollection *cxf.Collection
		for i := range collections {
			if collections[i].Title == "Work" {
				workCollection = &collections[i]
				break
			}
		}

		if workCollection == nil {
			t.Fatal("Expected to find Work collection")
		}

		if len(workCollection.Items) != 2 {
			t.Errorf("Work collection should have 2 items, got %d", len(workCollection.Items))
		}
	})

	t.Run("Nested folders", func(t *testing.T) {
		creds := []model.Credential{
			{ID: "1", Title: "Test1", FolderPath: "Work/Servers/Production"},
			{ID: "2", Title: "Test2", FolderPath: "Work/Servers/Staging"},
			{ID: "3", Title: "Test3", FolderPath: "Work"},
		}

		collections := BuildCollections(creds)
		if len(collections) != 1 {
			t.Fatalf("Expected 1 top-level collection, got %d", len(collections))
		}

		workCollection := collections[0]
		if workCollection.Title != "Work" {
			t.Errorf("Top collection title = %v, want Work", workCollection.Title)
		}

		// Work should have 1 item and sub-collections
		if len(workCollection.Items) != 1 {
			t.Errorf("Work should have 1 direct item, got %d", len(workCollection.Items))
		}

		if len(workCollection.SubCollections) != 1 {
			t.Fatalf("Work should have 1 sub-collection, got %d", len(workCollection.SubCollections))
		}

		serversCollection := workCollection.SubCollections[0]
		if serversCollection.Title != "Servers" {
			t.Errorf("Sub-collection title = %v, want Servers", serversCollection.Title)
		}

		if len(serversCollection.SubCollections) != 2 {
			t.Errorf("Servers should have 2 sub-collections, got %d", len(serversCollection.SubCollections))
		}
	})

	t.Run("Path normalization", func(t *testing.T) {
		creds := []model.Credential{
			{ID: "1", Title: "Test1", FolderPath: "/Work/"},
			{ID: "2", Title: "Test2", FolderPath: "Work"},
			{ID: "3", Title: "Test3", FolderPath: "Work\\Servers"},
		}

		collections := BuildCollections(creds)

		// All should be under "Work"
		if len(collections) != 1 {
			t.Errorf("Expected 1 collection after normalization, got %d", len(collections))
		}

		if collections[0].Title != "Work" {
			t.Errorf("Collection title = %v, want Work", collections[0].Title)
		}
	})
}

func TestSplitPath(t *testing.T) {
	tests := []struct {
		name string
		path string
		want []string
	}{
		{"Empty path", "", nil},
		{"Root", "/", nil},
		{"Single level", "Work", []string{"Work"}},
		{"Multiple levels", "Work/Servers/Production", []string{"Work", "Servers", "Production"}},
		{"With leading slash", "/Work/Servers", []string{"Work", "Servers"}},
		{"With trailing slash", "Work/Servers/", []string{"Work", "Servers"}},
		{"Windows path", "Work\\Servers", []string{"Work", "Servers"}},
		{"Mixed separators", "Work/Servers\\Production", []string{"Work", "Servers", "Production"}},
		{"With whitespace", "  Work  /  Servers  ", []string{"Work", "Servers"}},
		{"Double slashes", "Work//Servers", []string{"Work", "Servers"}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := splitPath(tt.path)
			if len(got) != len(tt.want) {
				t.Errorf("splitPath(%q) = %v, want %v", tt.path, got, tt.want)
				return
			}
			for i := range got {
				if got[i] != tt.want[i] {
					t.Errorf("splitPath(%q)[%d] = %v, want %v", tt.path, i, got[i], tt.want[i])
				}
			}
		})
	}
}

func TestMapTOTPAlgorithms(t *testing.T) {
	tests := []struct {
		name      string
		algorithm model.TOTPAlgorithm
		want      string
	}{
		{"SHA1", model.TOTPAlgorithmSHA1, cxf.OTPHashAlgorithmSha1},
		{"SHA256", model.TOTPAlgorithmSHA256, cxf.OTPHashAlgorithmSha256},
		{"SHA512", model.TOTPAlgorithmSHA512, cxf.OTPHashAlgorithmSha512},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cred := &model.Credential{
				Type: model.TypeTOTP,
				TOTP: &model.TOTPData{
					Secret:    "TEST",
					Algorithm: tt.algorithm,
					Digits:    6,
					Period:    30,
				},
			}

			item, err := mapCredentialToItem(cred)
			if err != nil {
				t.Fatalf("mapCredentialToItem() error = %v", err)
			}

			var totpCred cxf.TOTPCredential
			if err := json.Unmarshal(item.Credentials[0], &totpCred); err != nil {
				t.Fatalf("Unmarshal error: %v", err)
			}

			if totpCred.Algorithm != tt.want {
				t.Errorf("Algorithm = %v, want %v", totpCred.Algorithm, tt.want)
			}
		})
	}
}

func TestMapSSHKeyTypes(t *testing.T) {
	tests := []struct {
		name    string
		keyType model.SSHKeyType
		want    string
	}{
		{"ED25519", model.SSHKeyTypeEd25519, "ssh-ed25519"},
		{"RSA", model.SSHKeyTypeRSA, "ssh-rsa"},
		{"ECDSA", model.SSHKeyTypeECDSA, "ecdsa-sha2-nistp256"},
		{"DSA", model.SSHKeyTypeDSA, "ssh-dss"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cred := &model.Credential{
				Type: model.TypeSSHKey,
				SSHKey: &model.SSHKeyData{
					KeyType:    tt.keyType,
					PrivateKey: "test-key",
				},
			}

			item, err := mapCredentialToItem(cred)
			if err != nil {
				t.Fatalf("mapCredentialToItem() error = %v", err)
			}

			var sshCred cxf.SSHKeyCredential
			if err := json.Unmarshal(item.Credentials[0], &sshCred); err != nil {
				t.Fatalf("Unmarshal error: %v", err)
			}

			if sshCred.KeyType != tt.want {
				t.Errorf("KeyType = %v, want %v", sshCred.KeyType, tt.want)
			}
		})
	}
}

func TestFormatExpiryDate(t *testing.T) {
	tests := []struct {
		name  string
		year  string
		month string
		want  string
	}{
		{"Full year and month", "2025", "12", "2025-12"},
		{"Short year", "25", "12", "2025-12"},
		{"Single digit month", "2025", "3", "2025-03"},
		{"Empty year", "", "12", ""},
		{"Empty month", "2025", "", ""},
		{"Both empty", "", "", ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := formatExpiryDate(tt.year, tt.month)
			if got != tt.want {
				t.Errorf("formatExpiryDate(%q, %q) = %q, want %q", tt.year, tt.month, got, tt.want)
			}
		})
	}
}

func TestIsBase64URL(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  bool
	}{
		{"Valid base64url", "SGVsbG8", true},
		{"Valid base64url with underscores", "SGVs_G8", true},
		{"Empty string", "", false},
		{"Plain text with spaces", "hello world", false},
		{"Contains invalid chars", "abc@def", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := isBase64URL(tt.input)
			if got != tt.want {
				t.Errorf("isBase64URL(%q) = %v, want %v", tt.input, got, tt.want)
			}
		})
	}
}

func TestDefaultOptions(t *testing.T) {
	opts := DefaultOptions()

	if opts.ExporterRpID != "cxporter.local" {
		t.Errorf("ExporterRpID = %v, want cxporter.local", opts.ExporterRpID)
	}
	if opts.ExporterName != "cxporter" {
		t.Errorf("ExporterName = %v, want cxporter", opts.ExporterName)
	}
	if !opts.PreserveHierarchy {
		t.Error("PreserveHierarchy should default to true")
	}
}

func TestGenerateBase64URLID(t *testing.T) {
	id1 := generateBase64URLID()
	id2 := generateBase64URLID()

	if id1 == "" {
		t.Error("Generated ID should not be empty")
	}

	if id1 == id2 {
		t.Error("Generated IDs should be unique")
	}

	// Should be valid base64url
	if !isBase64URL(id1) {
		t.Errorf("Generated ID %q should be valid base64url", id1)
	}
}

func TestMixedCredentialTypes(t *testing.T) {
	// Test generating a header with multiple credential types
	now := time.Now()
	creds := []model.Credential{
		{
			ID:         "1",
			Type:       model.TypeBasicAuth,
			Title:      "Basic Auth",
			Username:   "user",
			Password:   "pass",
			FolderPath: "Web",
			Created:    now,
		},
		{
			ID:         "2",
			Type:       model.TypeTOTP,
			Title:      "TOTP",
			FolderPath: "2FA",
			TOTP: &model.TOTPData{
				Secret:    "SECRET",
				Algorithm: model.TOTPAlgorithmSHA1,
				Digits:    6,
				Period:    30,
			},
			Created: now,
		},
		{
			ID:         "3",
			Type:       model.TypeSSHKey,
			Title:      "SSH",
			FolderPath: "Keys",
			SSHKey: &model.SSHKeyData{
				KeyType:    model.SSHKeyTypeEd25519,
				PrivateKey: "key",
			},
			Created: now,
		},
		{
			ID:         "4",
			Type:       model.TypeNote,
			Title:      "Note",
			Notes:      "Secret note",
			FolderPath: "Notes",
			Created:    now,
		},
		{
			ID:         "5",
			Type:       model.TypeCreditCard,
			Title:      "Credit Card",
			FolderPath: "Payment",
			CreditCard: &model.CreditCardData{
				Number: "4111111111111111",
			},
			Created: now,
		},
	}

	header, err := Generate(creds, DefaultOptions())
	if err != nil {
		t.Fatalf("Generate() error = %v", err)
	}

	// Should have 5 items
	if len(header.Accounts[0].Items) != 5 {
		t.Errorf("Expected 5 items, got %d", len(header.Accounts[0].Items))
	}

	// Should have 5 collections (one per unique folder)
	if len(header.Accounts[0].Collections) != 5 {
		t.Errorf("Expected 5 collections, got %d", len(header.Accounts[0].Collections))
	}

	// Verify JSON output is valid
	jsonBytes, err := json.MarshalIndent(header, "", "  ")
	if err != nil {
		t.Fatalf("Failed to marshal to JSON: %v", err)
	}

	// Unmarshal back to verify structure
	var parsed cxf.Header
	if err := json.Unmarshal(jsonBytes, &parsed); err != nil {
		t.Fatalf("Failed to unmarshal JSON: %v", err)
	}

	if len(parsed.Accounts) != 1 {
		t.Errorf("Parsed accounts = %d, want 1", len(parsed.Accounts))
	}
}
