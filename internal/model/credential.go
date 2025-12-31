package model

import (
	"strings"
	"time"
)

// Credential represents a normalized credential that can be converted to CXF format.
// It serves as the intermediate representation between source formats and CXF output.
type Credential struct {
	// ID is a unique identifier for the credential.
	ID string

	// Type indicates what kind of credential this is.
	Type CredentialType

	// Title is the display name for the credential.
	Title string

	// Username for authentication credentials.
	Username string

	// Password for basic auth credentials.
	Password string

	// URL is the associated website or service URL.
	URL string

	// Notes contains additional text notes.
	Notes string

	// TOTP contains TOTP configuration if Type == TypeTOTP.
	TOTP *TOTPData

	// SSHKey contains SSH key data if Type == TypeSSHKey.
	SSHKey *SSHKeyData

	// CreditCard contains credit card data if Type == TypeCreditCard.
	CreditCard *CreditCardData

	// CustomFields stores additional key-value pairs.
	CustomFields map[string]string

	// Tags for categorization.
	Tags []string

	// FolderPath represents the hierarchical location, "/" separated.
	// Example: "Work/Servers"
	FolderPath string

	// Created is when the credential was first created.
	Created time.Time

	// Modified is when the credential was last modified.
	Modified time.Time

	// Attachments contains binary attachments.
	Attachments []Attachment
}

// TOTPData contains Time-based One-Time Password configuration.
type TOTPData struct {
	// Secret is the base32-encoded TOTP secret.
	Secret string

	// Algorithm is the hash algorithm (SHA1, SHA256, SHA512).
	Algorithm TOTPAlgorithm

	// Digits is the number of digits in the code (typically 6 or 8).
	Digits int

	// Period is the time step in seconds (typically 30).
	Period int

	// Issuer is the service that issued the TOTP.
	Issuer string

	// AccountName is the account identifier for the TOTP.
	AccountName string
}

// SSHKeyData contains SSH key information.
type SSHKeyData struct {
	// PrivateKey is the PEM-encoded private key.
	PrivateKey string

	// PublicKey is the OpenSSH-format public key.
	PublicKey string

	// Fingerprint is the SHA256 fingerprint of the public key.
	Fingerprint string

	// KeyType is the algorithm (ed25519, rsa, ecdsa).
	KeyType SSHKeyType

	// Comment is the key comment (often user@host).
	Comment string

	// Encrypted indicates if the private key is password-protected.
	Encrypted bool
}

// CreditCardData contains credit card information.
type CreditCardData struct {
	// Number is the card number.
	Number string

	// Holder is the cardholder name.
	Holder string

	// ExpiryMonth is the expiration month (1-12).
	ExpiryMonth int

	// ExpiryYear is the expiration year (4-digit).
	ExpiryYear int

	// CVV is the card verification value.
	CVV string

	// PIN is the card PIN.
	PIN string

	// Brand is the card brand (Visa, Mastercard, etc.).
	Brand string
}

// Attachment represents a binary attachment to a credential.
type Attachment struct {
	// Name is the filename of the attachment.
	Name string

	// Data is the binary content.
	Data []byte

	// MimeType is the MIME type of the attachment.
	MimeType string
}

// IsEmpty returns true if the credential has no meaningful data.
func (c *Credential) IsEmpty() bool {
	if c == nil {
		return true
	}

	// Check basic fields
	if c.Title != "" || c.Username != "" || c.Password != "" || c.URL != "" || c.Notes != "" {
		return false
	}

	// Check type-specific data
	if c.TOTP != nil && c.TOTP.Secret != "" {
		return false
	}
	if c.SSHKey != nil && c.SSHKey.PrivateKey != "" {
		return false
	}
	if c.CreditCard != nil && c.CreditCard.Number != "" {
		return false
	}

	// Check custom fields
	if len(c.CustomFields) > 0 {
		return false
	}

	// Check attachments
	if len(c.Attachments) > 0 {
		return false
	}

	return true
}

// Clone creates a deep copy of the credential.
func (c *Credential) Clone() *Credential {
	if c == nil {
		return nil
	}

	clone := &Credential{
		ID:         c.ID,
		Type:       c.Type,
		Title:      c.Title,
		Username:   c.Username,
		Password:   c.Password,
		URL:        c.URL,
		Notes:      c.Notes,
		FolderPath: c.FolderPath,
		Created:    c.Created,
		Modified:   c.Modified,
	}

	// Clone TOTP
	if c.TOTP != nil {
		clone.TOTP = &TOTPData{
			Secret:      c.TOTP.Secret,
			Algorithm:   c.TOTP.Algorithm,
			Digits:      c.TOTP.Digits,
			Period:      c.TOTP.Period,
			Issuer:      c.TOTP.Issuer,
			AccountName: c.TOTP.AccountName,
		}
	}

	// Clone SSHKey
	if c.SSHKey != nil {
		clone.SSHKey = &SSHKeyData{
			PrivateKey:  c.SSHKey.PrivateKey,
			PublicKey:   c.SSHKey.PublicKey,
			Fingerprint: c.SSHKey.Fingerprint,
			KeyType:     c.SSHKey.KeyType,
			Comment:     c.SSHKey.Comment,
			Encrypted:   c.SSHKey.Encrypted,
		}
	}

	// Clone CreditCard
	if c.CreditCard != nil {
		clone.CreditCard = &CreditCardData{
			Number:      c.CreditCard.Number,
			Holder:      c.CreditCard.Holder,
			ExpiryMonth: c.CreditCard.ExpiryMonth,
			ExpiryYear:  c.CreditCard.ExpiryYear,
			CVV:         c.CreditCard.CVV,
			PIN:         c.CreditCard.PIN,
			Brand:       c.CreditCard.Brand,
		}
	}

	// Clone CustomFields
	if len(c.CustomFields) > 0 {
		clone.CustomFields = make(map[string]string, len(c.CustomFields))
		for k, v := range c.CustomFields {
			clone.CustomFields[k] = v
		}
	}

	// Clone Tags
	if len(c.Tags) > 0 {
		clone.Tags = make([]string, len(c.Tags))
		copy(clone.Tags, c.Tags)
	}

	// Clone Attachments
	if len(c.Attachments) > 0 {
		clone.Attachments = make([]Attachment, len(c.Attachments))
		for i, att := range c.Attachments {
			clone.Attachments[i] = Attachment{
				Name:     att.Name,
				MimeType: att.MimeType,
			}
			if len(att.Data) > 0 {
				clone.Attachments[i].Data = make([]byte, len(att.Data))
				copy(clone.Attachments[i].Data, att.Data)
			}
		}
	}

	return clone
}

// Sanitize removes leading/trailing whitespace from string fields.
func (c *Credential) Sanitize() {
	if c == nil {
		return
	}

	c.ID = strings.TrimSpace(c.ID)
	c.Title = strings.TrimSpace(c.Title)
	c.Username = strings.TrimSpace(c.Username)
	c.Password = strings.TrimSpace(c.Password)
	c.URL = strings.TrimSpace(c.URL)
	c.Notes = strings.TrimSpace(c.Notes)
	c.FolderPath = strings.TrimSpace(c.FolderPath)

	// Sanitize tags
	for i, tag := range c.Tags {
		c.Tags[i] = strings.TrimSpace(tag)
	}

	// Sanitize custom fields
	if c.CustomFields != nil {
		sanitized := make(map[string]string, len(c.CustomFields))
		for k, v := range c.CustomFields {
			sanitized[strings.TrimSpace(k)] = strings.TrimSpace(v)
		}
		c.CustomFields = sanitized
	}

	// Sanitize TOTP
	if c.TOTP != nil {
		c.TOTP.Secret = strings.TrimSpace(c.TOTP.Secret)
		c.TOTP.Issuer = strings.TrimSpace(c.TOTP.Issuer)
		c.TOTP.AccountName = strings.TrimSpace(c.TOTP.AccountName)
	}

	// Sanitize SSHKey
	if c.SSHKey != nil {
		c.SSHKey.PrivateKey = strings.TrimSpace(c.SSHKey.PrivateKey)
		c.SSHKey.PublicKey = strings.TrimSpace(c.SSHKey.PublicKey)
		c.SSHKey.Fingerprint = strings.TrimSpace(c.SSHKey.Fingerprint)
		c.SSHKey.Comment = strings.TrimSpace(c.SSHKey.Comment)
	}

	// Sanitize CreditCard
	if c.CreditCard != nil {
		c.CreditCard.Number = strings.TrimSpace(c.CreditCard.Number)
		c.CreditCard.Holder = strings.TrimSpace(c.CreditCard.Holder)
		c.CreditCard.CVV = strings.TrimSpace(c.CreditCard.CVV)
		c.CreditCard.PIN = strings.TrimSpace(c.CreditCard.PIN)
		c.CreditCard.Brand = strings.TrimSpace(c.CreditCard.Brand)
	}

	// Sanitize Attachments
	for i := range c.Attachments {
		c.Attachments[i].Name = strings.TrimSpace(c.Attachments[i].Name)
		c.Attachments[i].MimeType = strings.TrimSpace(c.Attachments[i].MimeType)
	}
}

// NewTOTPData creates a TOTPData with default values.
func NewTOTPData(secret string) *TOTPData {
	return &TOTPData{
		Secret:    secret,
		Algorithm: TOTPAlgorithmSHA1,
		Digits:    6,
		Period:    30,
	}
}

// NewSSHKeyData creates an SSHKeyData with the given private key.
func NewSSHKeyData(privateKey string, keyType SSHKeyType) *SSHKeyData {
	return &SSHKeyData{
		PrivateKey: privateKey,
		KeyType:    keyType,
	}
}
