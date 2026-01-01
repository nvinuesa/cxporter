package model

import (
	"encoding/base32"
	"errors"
	"fmt"
	"strings"
	
	"github.com/nvinuesa/cxporter/internal/security"
)

// Validation errors.
var (
	ErrEmptyCredential     = errors.New("credential is empty")
	ErrMissingID           = errors.New("credential ID is required")
	ErrMissingTitle        = errors.New("credential title is required")
	ErrMissingPassword     = errors.New("password is required for basic-auth credential")
	ErrMissingTOTPSecret   = errors.New("TOTP secret is required")
	ErrInvalidTOTPSecret   = errors.New("TOTP secret must be valid base32")
	ErrInvalidTOTPDigits   = errors.New("TOTP digits must be 6 or 8")
	ErrInvalidTOTPPeriod   = errors.New("TOTP period must be positive")
	ErrInvalidTOTPAlgo     = errors.New("TOTP algorithm must be SHA1, SHA256, or SHA512")
	ErrMissingSSHKey       = errors.New("SSH private key is required")
	ErrInvalidSSHKeyFormat = errors.New("SSH private key must be PEM-encoded")
	ErrMissingCardNumber   = errors.New("credit card number is required")
	ErrInvalidCardMonth    = errors.New("credit card expiry month must be 1-12")
	ErrInvalidCardYear     = errors.New("credit card expiry year must be 4 digits")
)

// Validate validates the credential based on its type.
func (c *Credential) Validate() error {
	if c == nil || c.IsEmpty() {
		return ErrEmptyCredential
	}

	// ID is always required and must be valid
	if err := security.ValidateCredentialID(c.ID); err != nil {
		return err
	}
	
	// Validate string lengths to prevent DoS
	if err := security.ValidateStringLength(c.Title, security.MaxTitleLength, "title"); err != nil {
		return err
	}
	if err := security.ValidateStringLength(c.Username, security.MaxUsernameLength, "username"); err != nil {
		return err
	}
	if err := security.ValidateStringLength(c.Password, security.MaxPasswordLength, "password"); err != nil {
		return err
	}
	if err := security.ValidateStringLength(c.URL, security.MaxURLLength, "URL"); err != nil {
		return err
	}
	if err := security.ValidateStringLength(c.Notes, security.MaxNotesLength, "notes"); err != nil {
		return err
	}
	if err := security.ValidateStringLength(c.FolderPath, security.MaxFolderPathLength, "folder path"); err != nil {
		return err
	}
	
	// Validate tags
	if len(c.Tags) > security.MaxTagCount {
		return fmt.Errorf("too many tags: %d (max %d)", len(c.Tags), security.MaxTagCount)
	}
	for _, tag := range c.Tags {
		if err := security.ValidateStringLength(tag, security.MaxTagLength, "tag"); err != nil {
			return err
		}
	}
	
	// Validate custom fields
	for key, value := range c.CustomFields {
		if err := security.ValidateStringLength(key, security.MaxCustomFieldKey, "custom field key"); err != nil {
			return err
		}
		if err := security.ValidateStringLength(value, security.MaxCustomFieldValue, "custom field value"); err != nil {
			return err
		}
	}
	
	// Validate attachments
	if len(c.Attachments) > security.MaxAttachmentCount {
		return fmt.Errorf("too many attachments: %d (max %d)", len(c.Attachments), security.MaxAttachmentCount)
	}
	for i, att := range c.Attachments {
		if err := security.ValidateAttachmentSize(len(att.Data)); err != nil {
			return fmt.Errorf("attachment %d: %w", i, err)
		}
		if security.HasDangerousFileExtension(att.Name) {
			return fmt.Errorf("attachment %d has dangerous file extension: %s", i, att.Name)
		}
	}

	// Title is recommended but not strictly required for all types
	// Some sources may not have titles

	switch c.Type {
	case TypeBasicAuth:
		return c.validateBasicAuth()
	case TypeTOTP:
		return c.validateTOTP()
	case TypeSSHKey:
		return c.validateSSHKey()
	case TypeNote:
		return c.validateNote()
	case TypeCreditCard:
		return c.validateCreditCard()
	case TypeIdentity:
		return c.validateIdentity()
	case TypeAPIKey:
		return c.validateAPIKey()
	case TypeWiFi:
		return c.validateWiFi()
	default:
		return fmt.Errorf("unknown credential type: %d", c.Type)
	}
}

func (c *Credential) validateBasicAuth() error {
	// Basic auth should have at least username or password
	if c.Username == "" && c.Password == "" {
		return ErrMissingPassword
	}
	return nil
}

func (c *Credential) validateTOTP() error {
	if c.TOTP == nil {
		return ErrMissingTOTPSecret
	}
	return ValidateTOTP(c.TOTP)
}

func (c *Credential) validateSSHKey() error {
	if c.SSHKey == nil {
		return ErrMissingSSHKey
	}
	return ValidateSSHKey(c.SSHKey)
}

func (c *Credential) validateNote() error {
	// Notes should have some content
	if c.Notes == "" && c.Title == "" {
		return errors.New("note must have title or content")
	}
	return nil
}

func (c *Credential) validateCreditCard() error {
	if c.CreditCard == nil {
		return ErrMissingCardNumber
	}
	return ValidateCreditCard(c.CreditCard)
}

func (c *Credential) validateIdentity() error {
	// Identity credentials are flexible - just need some data
	if c.Title == "" && c.Notes == "" && len(c.CustomFields) == 0 {
		return errors.New("identity must have title, notes, or custom fields")
	}
	return nil
}

func (c *Credential) validateAPIKey() error {
	// API keys need at least a password (the key) or custom fields
	if c.Password == "" && len(c.CustomFields) == 0 {
		return errors.New("API key credential must have password or custom fields")
	}
	return nil
}

func (c *Credential) validateWiFi() error {
	// WiFi needs at least a title (SSID) or password
	if c.Title == "" && c.Password == "" {
		return errors.New("WiFi credential must have title (SSID) or password")
	}
	return nil
}

// ValidateTOTP validates TOTP data.
func ValidateTOTP(t *TOTPData) error {
	if t == nil {
		return ErrMissingTOTPSecret
	}

	if t.Secret == "" {
		return ErrMissingTOTPSecret
	}

	// Validate base32 encoding (allow lowercase and padding variations)
	secret := strings.ToUpper(strings.TrimRight(t.Secret, "="))
	// Remove any spaces that might be in the secret
	secret = strings.ReplaceAll(secret, " ", "")
	if _, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(secret); err != nil {
		return fmt.Errorf("%w: %v", ErrInvalidTOTPSecret, err)
	}

	// Validate digits
	if t.Digits != 0 && t.Digits != 6 && t.Digits != 8 {
		return ErrInvalidTOTPDigits
	}

	// Validate period
	if t.Period < 0 {
		return ErrInvalidTOTPPeriod
	}

	// Validate algorithm
	switch t.Algorithm {
	case "", TOTPAlgorithmSHA1, TOTPAlgorithmSHA256, TOTPAlgorithmSHA512:
		// Valid
	default:
		return ErrInvalidTOTPAlgo
	}

	return nil
}

// ValidateSSHKey validates SSH key data.
func ValidateSSHKey(k *SSHKeyData) error {
	if k == nil {
		return ErrMissingSSHKey
	}

	if k.PrivateKey == "" {
		return ErrMissingSSHKey
	}

	// Check for PEM format
	if !strings.Contains(k.PrivateKey, "-----BEGIN") {
		return ErrInvalidSSHKeyFormat
	}

	if !strings.Contains(k.PrivateKey, "-----END") {
		return ErrInvalidSSHKeyFormat
	}

	return nil
}

// ValidateCreditCard validates credit card data.
func ValidateCreditCard(cc *CreditCardData) error {
	if cc == nil {
		return ErrMissingCardNumber
	}

	if cc.Number == "" {
		return ErrMissingCardNumber
	}

	// Validate month if provided
	if cc.ExpiryMonth != 0 && (cc.ExpiryMonth < 1 || cc.ExpiryMonth > 12) {
		return ErrInvalidCardMonth
	}

	// Validate year if provided (should be 4 digits)
	if cc.ExpiryYear != 0 && (cc.ExpiryYear < 1000 || cc.ExpiryYear > 9999) {
		return ErrInvalidCardYear
	}

	return nil
}

// ValidateAll validates a slice of credentials and returns all errors.
func ValidateAll(creds []Credential) []error {
	var errs []error
	for i, cred := range creds {
		if err := cred.Validate(); err != nil {
			errs = append(errs, fmt.Errorf("credential %d (%s): %w", i, cred.Title, err))
		}
	}
	return errs
}
