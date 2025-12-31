package model

import (
	"testing"
	"time"
)

func TestCredentialType_String(t *testing.T) {
	tests := []struct {
		name     string
		credType CredentialType
		want     string
	}{
		{"BasicAuth", TypeBasicAuth, "basic-auth"},
		{"TOTP", TypeTOTP, "totp"},
		{"SSHKey", TypeSSHKey, "ssh-key"},
		{"Note", TypeNote, "note"},
		{"CreditCard", TypeCreditCard, "credit-card"},
		{"Identity", TypeIdentity, "identity"},
		{"APIKey", TypeAPIKey, "api-key"},
		{"WiFi", TypeWiFi, "wifi"},
		{"Unknown", CredentialType(99), "unknown(99)"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.credType.String(); got != tt.want {
				t.Errorf("CredentialType.String() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestParseCredentialType(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		want    CredentialType
		wantErr bool
	}{
		{"BasicAuth", "basic-auth", TypeBasicAuth, false},
		{"TOTP", "totp", TypeTOTP, false},
		{"SSHKey", "ssh-key", TypeSSHKey, false},
		{"Note", "note", TypeNote, false},
		{"CreditCard", "credit-card", TypeCreditCard, false},
		{"Identity", "identity", TypeIdentity, false},
		{"APIKey", "api-key", TypeAPIKey, false},
		{"WiFi", "wifi", TypeWiFi, false},
		{"Unknown", "unknown", TypeBasicAuth, true},
		{"Empty", "", TypeBasicAuth, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ParseCredentialType(tt.input)
			if (err != nil) != tt.wantErr {
				t.Errorf("ParseCredentialType() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !tt.wantErr && got != tt.want {
				t.Errorf("ParseCredentialType() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestTOTPAlgorithm_String(t *testing.T) {
	tests := []struct {
		name string
		algo TOTPAlgorithm
		want string
	}{
		{"SHA1", TOTPAlgorithmSHA1, "sha1"},
		{"SHA256", TOTPAlgorithmSHA256, "sha256"},
		{"SHA512", TOTPAlgorithmSHA512, "sha512"},
		{"Empty", "", "sha1"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.algo.String(); got != tt.want {
				t.Errorf("TOTPAlgorithm.String() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestCredential_IsEmpty(t *testing.T) {
	tests := []struct {
		name string
		cred *Credential
		want bool
	}{
		{"Nil", nil, true},
		{"Empty struct", &Credential{}, true},
		{"With title", &Credential{Title: "test"}, false},
		{"With username", &Credential{Username: "user"}, false},
		{"With password", &Credential{Password: "pass"}, false},
		{"With URL", &Credential{URL: "https://example.com"}, false},
		{"With notes", &Credential{Notes: "notes"}, false},
		{"With TOTP", &Credential{TOTP: &TOTPData{Secret: "JBSWY3DPEHPK3PXP"}}, false},
		{"With SSHKey", &Credential{SSHKey: &SSHKeyData{PrivateKey: "key"}}, false},
		{"With CreditCard", &Credential{CreditCard: &CreditCardData{Number: "1234"}}, false},
		{"With CustomFields", &Credential{CustomFields: map[string]string{"key": "value"}}, false},
		{"With Attachments", &Credential{Attachments: []Attachment{{Name: "file.txt"}}}, false},
		{"With empty TOTP", &Credential{TOTP: &TOTPData{}}, true},
		{"With empty SSHKey", &Credential{SSHKey: &SSHKeyData{}}, true},
		{"With empty CreditCard", &Credential{CreditCard: &CreditCardData{}}, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.cred.IsEmpty(); got != tt.want {
				t.Errorf("Credential.IsEmpty() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestCredential_Clone(t *testing.T) {
	original := &Credential{
		ID:         "test-id",
		Type:       TypeBasicAuth,
		Title:      "Test Credential",
		Username:   "user",
		Password:   "pass",
		URL:        "https://example.com",
		Notes:      "Some notes",
		FolderPath: "Work/Test",
		Created:    time.Now(),
		Modified:   time.Now(),
		Tags:       []string{"tag1", "tag2"},
		CustomFields: map[string]string{
			"field1": "value1",
		},
		TOTP: &TOTPData{
			Secret:    "JBSWY3DPEHPK3PXP",
			Algorithm: TOTPAlgorithmSHA1,
			Digits:    6,
			Period:    30,
		},
		SSHKey: &SSHKeyData{
			PrivateKey:  "-----BEGIN OPENSSH PRIVATE KEY-----\nkey\n-----END OPENSSH PRIVATE KEY-----",
			PublicKey:   "ssh-ed25519 AAAA...",
			Fingerprint: "SHA256:xxx",
			KeyType:     SSHKeyTypeEd25519,
			Comment:     "test@host",
		},
		CreditCard: &CreditCardData{
			Number:      "4111111111111111",
			Holder:      "John Doe",
			ExpiryMonth: 12,
			ExpiryYear:  2025,
			CVV:         "123",
		},
		Attachments: []Attachment{
			{Name: "file.txt", Data: []byte("content"), MimeType: "text/plain"},
		},
	}

	clone := original.Clone()

	// Verify clone is not the same pointer
	if clone == original {
		t.Error("Clone should return a new pointer")
	}

	// Verify basic fields
	if clone.ID != original.ID {
		t.Errorf("Clone ID = %v, want %v", clone.ID, original.ID)
	}
	if clone.Title != original.Title {
		t.Errorf("Clone Title = %v, want %v", clone.Title, original.Title)
	}

	// Verify TOTP is deep copied
	if clone.TOTP == original.TOTP {
		t.Error("Clone TOTP should be a new pointer")
	}
	if clone.TOTP.Secret != original.TOTP.Secret {
		t.Errorf("Clone TOTP.Secret = %v, want %v", clone.TOTP.Secret, original.TOTP.Secret)
	}

	// Verify SSHKey is deep copied
	if clone.SSHKey == original.SSHKey {
		t.Error("Clone SSHKey should be a new pointer")
	}

	// Verify CreditCard is deep copied
	if clone.CreditCard == original.CreditCard {
		t.Error("Clone CreditCard should be a new pointer")
	}

	// Verify Tags are deep copied
	if &clone.Tags[0] == &original.Tags[0] {
		t.Error("Clone Tags should be a new slice")
	}

	// Verify CustomFields are deep copied
	clone.CustomFields["new"] = "value"
	if _, exists := original.CustomFields["new"]; exists {
		t.Error("Modifying clone CustomFields should not affect original")
	}

	// Verify Attachments are deep copied
	if &clone.Attachments[0].Data[0] == &original.Attachments[0].Data[0] {
		t.Error("Clone Attachments data should be a new slice")
	}

	// Verify nil clone
	var nilCred *Credential
	if nilCred.Clone() != nil {
		t.Error("Clone of nil should return nil")
	}
}

func TestCredential_Sanitize(t *testing.T) {
	cred := &Credential{
		ID:         "  test-id  ",
		Title:      "  Test Title  ",
		Username:   "  user  ",
		Password:   "  pass  ",
		URL:        "  https://example.com  ",
		Notes:      "  Some notes  ",
		FolderPath: "  Work/Test  ",
		Tags:       []string{"  tag1  ", "  tag2  "},
		CustomFields: map[string]string{
			"  field1  ": "  value1  ",
		},
		TOTP: &TOTPData{
			Secret:      "  JBSWY3DPEHPK3PXP  ",
			Issuer:      "  Test  ",
			AccountName: "  user  ",
		},
		SSHKey: &SSHKeyData{
			PrivateKey:  "  -----BEGIN KEY-----  ",
			PublicKey:   "  ssh-ed25519 AAAA  ",
			Fingerprint: "  SHA256:xxx  ",
			Comment:     "  test@host  ",
		},
		CreditCard: &CreditCardData{
			Number: "  4111111111111111  ",
			Holder: "  John Doe  ",
			CVV:    "  123  ",
			PIN:    "  1234  ",
			Brand:  "  Visa  ",
		},
		Attachments: []Attachment{
			{Name: "  file.txt  ", MimeType: "  text/plain  "},
		},
	}

	cred.Sanitize()

	// Verify basic fields are trimmed
	if cred.ID != "test-id" {
		t.Errorf("Sanitize ID = %q, want %q", cred.ID, "test-id")
	}
	if cred.Title != "Test Title" {
		t.Errorf("Sanitize Title = %q, want %q", cred.Title, "Test Title")
	}
	if cred.Tags[0] != "tag1" {
		t.Errorf("Sanitize Tags[0] = %q, want %q", cred.Tags[0], "tag1")
	}

	// Verify CustomFields keys and values are trimmed
	if _, exists := cred.CustomFields["field1"]; !exists {
		t.Error("CustomFields key should be trimmed")
	}
	if cred.CustomFields["field1"] != "value1" {
		t.Errorf("CustomFields value = %q, want %q", cred.CustomFields["field1"], "value1")
	}

	// Verify TOTP is trimmed
	if cred.TOTP.Secret != "JBSWY3DPEHPK3PXP" {
		t.Errorf("TOTP.Secret = %q, want %q", cred.TOTP.Secret, "JBSWY3DPEHPK3PXP")
	}

	// Verify SSHKey is trimmed
	if cred.SSHKey.Comment != "test@host" {
		t.Errorf("SSHKey.Comment = %q, want %q", cred.SSHKey.Comment, "test@host")
	}

	// Verify CreditCard is trimmed
	if cred.CreditCard.Holder != "John Doe" {
		t.Errorf("CreditCard.Holder = %q, want %q", cred.CreditCard.Holder, "John Doe")
	}

	// Verify Attachments are trimmed
	if cred.Attachments[0].Name != "file.txt" {
		t.Errorf("Attachments[0].Name = %q, want %q", cred.Attachments[0].Name, "file.txt")
	}

	// Verify nil sanitize doesn't panic
	var nilCred *Credential
	nilCred.Sanitize() // Should not panic
}

func TestCredential_Validate(t *testing.T) {
	tests := []struct {
		name    string
		cred    *Credential
		wantErr error
	}{
		{
			name:    "Nil credential",
			cred:    nil,
			wantErr: ErrEmptyCredential,
		},
		{
			name:    "Empty credential",
			cred:    &Credential{},
			wantErr: ErrEmptyCredential,
		},
		{
			name: "Missing ID",
			cred: &Credential{
				Title:    "Test",
				Password: "pass",
			},
			wantErr: ErrMissingID,
		},
		{
			name: "Valid BasicAuth",
			cred: &Credential{
				ID:       "1",
				Type:     TypeBasicAuth,
				Username: "user",
				Password: "pass",
			},
			wantErr: nil,
		},
		{
			name: "BasicAuth with only username",
			cred: &Credential{
				ID:       "1",
				Type:     TypeBasicAuth,
				Username: "user",
			},
			wantErr: nil,
		},
		{
			name: "BasicAuth missing credentials",
			cred: &Credential{
				ID:    "1",
				Type:  TypeBasicAuth,
				Title: "Test",
			},
			wantErr: ErrMissingPassword,
		},
		{
			name: "Valid TOTP",
			cred: &Credential{
				ID:   "1",
				Type: TypeTOTP,
				TOTP: &TOTPData{
					Secret:    "JBSWY3DPEHPK3PXP",
					Algorithm: TOTPAlgorithmSHA1,
					Digits:    6,
					Period:    30,
				},
			},
			wantErr: nil,
		},
		{
			name: "TOTP missing secret",
			cred: &Credential{
				ID:    "1",
				Type:  TypeTOTP,
				Title: "Missing TOTP",
			},
			wantErr: ErrMissingTOTPSecret,
		},
		{
			name: "Valid SSHKey",
			cred: &Credential{
				ID:   "1",
				Type: TypeSSHKey,
				SSHKey: &SSHKeyData{
					PrivateKey: "-----BEGIN OPENSSH PRIVATE KEY-----\nkey\n-----END OPENSSH PRIVATE KEY-----",
				},
			},
			wantErr: nil,
		},
		{
			name: "SSHKey missing key",
			cred: &Credential{
				ID:    "1",
				Type:  TypeSSHKey,
				Title: "Missing SSH Key",
			},
			wantErr: ErrMissingSSHKey,
		},
		{
			name: "Valid Note",
			cred: &Credential{
				ID:    "1",
				Type:  TypeNote,
				Title: "My Note",
			},
			wantErr: nil,
		},
		{
			name: "Note with content only",
			cred: &Credential{
				ID:    "1",
				Type:  TypeNote,
				Notes: "Some content",
			},
			wantErr: nil,
		},
		{
			name: "Valid CreditCard",
			cred: &Credential{
				ID:   "1",
				Type: TypeCreditCard,
				CreditCard: &CreditCardData{
					Number:      "4111111111111111",
					ExpiryMonth: 12,
					ExpiryYear:  2025,
				},
			},
			wantErr: nil,
		},
		{
			name: "CreditCard missing number",
			cred: &Credential{
				ID:    "1",
				Type:  TypeCreditCard,
				Title: "Missing Card",
			},
			wantErr: ErrMissingCardNumber,
		},
		{
			name: "Valid Identity",
			cred: &Credential{
				ID:    "1",
				Type:  TypeIdentity,
				Title: "John Doe",
			},
			wantErr: nil,
		},
		{
			name: "Valid APIKey",
			cred: &Credential{
				ID:       "1",
				Type:     TypeAPIKey,
				Password: "sk-1234567890",
			},
			wantErr: nil,
		},
		{
			name: "Valid WiFi",
			cred: &Credential{
				ID:       "1",
				Type:     TypeWiFi,
				Title:    "MyNetwork",
				Password: "wifi-pass",
			},
			wantErr: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.cred.Validate()
			if tt.wantErr != nil {
				if err == nil {
					t.Errorf("Validate() error = nil, wantErr %v", tt.wantErr)
				} else if err != tt.wantErr && err.Error() != tt.wantErr.Error() {
					t.Errorf("Validate() error = %v, wantErr %v", err, tt.wantErr)
				}
			} else if err != nil {
				t.Errorf("Validate() unexpected error = %v", err)
			}
		})
	}
}

func TestValidateTOTP(t *testing.T) {
	tests := []struct {
		name    string
		totp    *TOTPData
		wantErr error
	}{
		{
			name:    "Nil",
			totp:    nil,
			wantErr: ErrMissingTOTPSecret,
		},
		{
			name:    "Empty secret",
			totp:    &TOTPData{},
			wantErr: ErrMissingTOTPSecret,
		},
		{
			name: "Valid secret",
			totp: &TOTPData{
				Secret: "JBSWY3DPEHPK3PXP",
			},
			wantErr: nil,
		},
		{
			name: "Valid secret lowercase",
			totp: &TOTPData{
				Secret: "jbswy3dpehpk3pxp",
			},
			wantErr: nil,
		},
		{
			name: "Valid secret with padding",
			totp: &TOTPData{
				Secret: "JBSWY3DPEHPK3PXP====",
			},
			wantErr: nil,
		},
		{
			name: "Valid secret with spaces",
			totp: &TOTPData{
				Secret: "JBSW Y3DP EHPK 3PXP",
			},
			wantErr: nil,
		},
		{
			name: "Invalid secret",
			totp: &TOTPData{
				Secret: "invalid!!!",
			},
			wantErr: ErrInvalidTOTPSecret,
		},
		{
			name: "Invalid digits",
			totp: &TOTPData{
				Secret: "JBSWY3DPEHPK3PXP",
				Digits: 7,
			},
			wantErr: ErrInvalidTOTPDigits,
		},
		{
			name: "Valid 8 digits",
			totp: &TOTPData{
				Secret: "JBSWY3DPEHPK3PXP",
				Digits: 8,
			},
			wantErr: nil,
		},
		{
			name: "Negative period",
			totp: &TOTPData{
				Secret: "JBSWY3DPEHPK3PXP",
				Period: -1,
			},
			wantErr: ErrInvalidTOTPPeriod,
		},
		{
			name: "Invalid algorithm",
			totp: &TOTPData{
				Secret:    "JBSWY3DPEHPK3PXP",
				Algorithm: "MD5",
			},
			wantErr: ErrInvalidTOTPAlgo,
		},
		{
			name: "Valid SHA256",
			totp: &TOTPData{
				Secret:    "JBSWY3DPEHPK3PXP",
				Algorithm: TOTPAlgorithmSHA256,
			},
			wantErr: nil,
		},
		{
			name: "Valid SHA512",
			totp: &TOTPData{
				Secret:    "JBSWY3DPEHPK3PXP",
				Algorithm: TOTPAlgorithmSHA512,
			},
			wantErr: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateTOTP(tt.totp)
			if tt.wantErr != nil {
				if err == nil {
					t.Errorf("ValidateTOTP() error = nil, wantErr %v", tt.wantErr)
				}
			} else if err != nil {
				t.Errorf("ValidateTOTP() unexpected error = %v", err)
			}
		})
	}
}

func TestValidateSSHKey(t *testing.T) {
	tests := []struct {
		name    string
		sshKey  *SSHKeyData
		wantErr error
	}{
		{
			name:    "Nil",
			sshKey:  nil,
			wantErr: ErrMissingSSHKey,
		},
		{
			name:    "Empty private key",
			sshKey:  &SSHKeyData{},
			wantErr: ErrMissingSSHKey,
		},
		{
			name: "Valid PEM key",
			sshKey: &SSHKeyData{
				PrivateKey: "-----BEGIN OPENSSH PRIVATE KEY-----\nkey content\n-----END OPENSSH PRIVATE KEY-----",
			},
			wantErr: nil,
		},
		{
			name: "Valid RSA key",
			sshKey: &SSHKeyData{
				PrivateKey: "-----BEGIN RSA PRIVATE KEY-----\nkey content\n-----END RSA PRIVATE KEY-----",
			},
			wantErr: nil,
		},
		{
			name: "Invalid format - no BEGIN",
			sshKey: &SSHKeyData{
				PrivateKey: "key content\n-----END OPENSSH PRIVATE KEY-----",
			},
			wantErr: ErrInvalidSSHKeyFormat,
		},
		{
			name: "Invalid format - no END",
			sshKey: &SSHKeyData{
				PrivateKey: "-----BEGIN OPENSSH PRIVATE KEY-----\nkey content",
			},
			wantErr: ErrInvalidSSHKeyFormat,
		},
		{
			name: "Invalid format - plain text",
			sshKey: &SSHKeyData{
				PrivateKey: "not a pem key",
			},
			wantErr: ErrInvalidSSHKeyFormat,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateSSHKey(tt.sshKey)
			if tt.wantErr != nil {
				if err == nil {
					t.Errorf("ValidateSSHKey() error = nil, wantErr %v", tt.wantErr)
				} else if err != tt.wantErr {
					t.Errorf("ValidateSSHKey() error = %v, wantErr %v", err, tt.wantErr)
				}
			} else if err != nil {
				t.Errorf("ValidateSSHKey() unexpected error = %v", err)
			}
		})
	}
}

func TestValidateCreditCard(t *testing.T) {
	tests := []struct {
		name    string
		card    *CreditCardData
		wantErr error
	}{
		{
			name:    "Nil",
			card:    nil,
			wantErr: ErrMissingCardNumber,
		},
		{
			name:    "Empty number",
			card:    &CreditCardData{},
			wantErr: ErrMissingCardNumber,
		},
		{
			name: "Valid card",
			card: &CreditCardData{
				Number:      "4111111111111111",
				ExpiryMonth: 12,
				ExpiryYear:  2025,
			},
			wantErr: nil,
		},
		{
			name: "Card with number only",
			card: &CreditCardData{
				Number: "4111111111111111",
			},
			wantErr: nil,
		},
		{
			name: "Invalid month - 0",
			card: &CreditCardData{
				Number:      "4111111111111111",
				ExpiryMonth: 0,
			},
			wantErr: nil, // 0 means not set
		},
		{
			name: "Invalid month - 13",
			card: &CreditCardData{
				Number:      "4111111111111111",
				ExpiryMonth: 13,
			},
			wantErr: ErrInvalidCardMonth,
		},
		{
			name: "Invalid year - 2 digits",
			card: &CreditCardData{
				Number:     "4111111111111111",
				ExpiryYear: 25,
			},
			wantErr: ErrInvalidCardYear,
		},
		{
			name: "Invalid year - too long",
			card: &CreditCardData{
				Number:     "4111111111111111",
				ExpiryYear: 10000,
			},
			wantErr: ErrInvalidCardYear,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateCreditCard(tt.card)
			if tt.wantErr != nil {
				if err == nil {
					t.Errorf("ValidateCreditCard() error = nil, wantErr %v", tt.wantErr)
				} else if err != tt.wantErr {
					t.Errorf("ValidateCreditCard() error = %v, wantErr %v", err, tt.wantErr)
				}
			} else if err != nil {
				t.Errorf("ValidateCreditCard() unexpected error = %v", err)
			}
		})
	}
}

func TestValidateAll(t *testing.T) {
	creds := []Credential{
		{ID: "1", Type: TypeBasicAuth, Username: "user", Password: "pass"},
		{ID: "", Type: TypeBasicAuth, Title: "Missing ID"}, // Invalid
		{ID: "3", Type: TypeTOTP}, // Invalid - missing TOTP
	}

	errs := ValidateAll(creds)
	if len(errs) != 2 {
		t.Errorf("ValidateAll() returned %d errors, want 2", len(errs))
	}
}

func TestNewTOTPData(t *testing.T) {
	totp := NewTOTPData("JBSWY3DPEHPK3PXP")

	if totp.Secret != "JBSWY3DPEHPK3PXP" {
		t.Errorf("NewTOTPData().Secret = %v, want JBSWY3DPEHPK3PXP", totp.Secret)
	}
	if totp.Algorithm != TOTPAlgorithmSHA1 {
		t.Errorf("NewTOTPData().Algorithm = %v, want SHA1", totp.Algorithm)
	}
	if totp.Digits != 6 {
		t.Errorf("NewTOTPData().Digits = %v, want 6", totp.Digits)
	}
	if totp.Period != 30 {
		t.Errorf("NewTOTPData().Period = %v, want 30", totp.Period)
	}
}

func TestNewSSHKeyData(t *testing.T) {
	ssh := NewSSHKeyData("-----BEGIN KEY-----\ntest\n-----END KEY-----", SSHKeyTypeEd25519)

	if ssh.PrivateKey != "-----BEGIN KEY-----\ntest\n-----END KEY-----" {
		t.Errorf("NewSSHKeyData().PrivateKey mismatch")
	}
	if ssh.KeyType != SSHKeyTypeEd25519 {
		t.Errorf("NewSSHKeyData().KeyType = %v, want ed25519", ssh.KeyType)
	}
}
