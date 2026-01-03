package cxf

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/nvinuesa/go-cxf"

	"github.com/nvinuesa/cxporter/internal/model"
)

// mapCredentialToItem converts a model.Credential to a cxf.Item.
func mapCredentialToItem(c *model.Credential) (cxf.Item, error) {
	// Generate ID if empty
	id := c.ID
	if id == "" {
		id = generateBase64URLID()
	} else {
		// Ensure ID is base64url encoded
		if !isBase64URL(id) {
			id = base64.RawURLEncoding.EncodeToString([]byte(id))
		}
	}

	// Build timestamps
	var creationAt, modifiedAt *uint64
	if !c.Created.IsZero() {
		creationAt = uintPtr(uint64(c.Created.Unix()))
	}
	if !c.Modified.IsZero() {
		modifiedAt = uintPtr(uint64(c.Modified.Unix()))
	}

	// Build scope from URL
	var scope *cxf.CredentialScope
	if c.URL != "" {
		scope = &cxf.CredentialScope{
			Urls:        []string{c.URL},
			AndroidApps: []cxf.AndroidAppIdCredential{},
		}
	}

	// Map credential type to CXF credentials
	credentials, err := mapCredentials(c)
	if err != nil {
		return cxf.Item{}, err
	}

	return cxf.Item{
		ID:          id,
		CreationAt:  creationAt,
		ModifiedAt:  modifiedAt,
		Title:       c.Title,
		Subtitle:    "", // Not used in internal model
		Scope:       scope,
		Credentials: credentials,
		Tags:        c.Tags,
	}, nil
}

// mapCredentials creates the credentials array for an item.
func mapCredentials(c *model.Credential) ([]json.RawMessage, error) {
	var credentials []json.RawMessage

	switch c.Type {
	case model.TypeBasicAuth:
		cred, err := mapBasicAuth(c)
		if err != nil {
			return nil, err
		}
		credentials = append(credentials, cred)

	case model.TypeTOTP:
		cred, err := mapTOTP(c)
		if err != nil {
			return nil, err
		}
		credentials = append(credentials, cred)

	case model.TypeSSHKey:
		cred, err := mapSSHKey(c)
		if err != nil {
			return nil, err
		}
		credentials = append(credentials, cred)

	case model.TypeNote:
		cred, err := mapNote(c)
		if err != nil {
			return nil, err
		}
		credentials = append(credentials, cred)

	case model.TypeCreditCard:
		cred, err := mapCreditCard(c)
		if err != nil {
			return nil, err
		}
		credentials = append(credentials, cred)

	case model.TypeAPIKey:
		cred, err := mapAPIKey(c)
		if err != nil {
			return nil, err
		}
		credentials = append(credentials, cred)

	case model.TypeWiFi:
		cred, err := mapWiFi(c)
		if err != nil {
			return nil, err
		}
		credentials = append(credentials, cred)

	default:
		// Default to basic auth for unknown types
		cred, err := mapBasicAuth(c)
		if err != nil {
			return nil, err
		}
		credentials = append(credentials, cred)
	}

	// Add notes as a separate credential if present and not already a note type
	if c.Notes != "" && c.Type != model.TypeNote {
		noteCred, err := marshalCredential(cxf.NoteCredential{
			Type:    cxf.CredentialTypeNote,
			Content: makeEditableField(cxf.FieldTypeString, c.Notes),
		})
		if err != nil {
			return nil, err
		}
		credentials = append(credentials, noteCred)
	}

	// Add custom fields if present
	if len(c.CustomFields) > 0 {
		customCred, err := mapCustomFields(c.CustomFields)
		if err != nil {
			return nil, err
		}
		credentials = append(credentials, customCred)
	}

	return credentials, nil
}

// mapBasicAuth creates a BasicAuthCredential from a model.Credential.
func mapBasicAuth(c *model.Credential) (json.RawMessage, error) {
	cred := cxf.BasicAuthCredential{
		Type: cxf.CredentialTypeBasicAuth,
	}

	if c.Username != "" {
		cred.Username = makeEditableField(cxf.FieldTypeString, c.Username)
	}
	if c.Password != "" {
		cred.Password = makeEditableField(cxf.FieldTypeConcealedString, c.Password)
	}

	return marshalCredential(cred)
}

// mapTOTP creates a TOTPCredential from a model.Credential.
func mapTOTP(c *model.Credential) (json.RawMessage, error) {
	if c.TOTP == nil {
		// Return empty TOTP credential
		return marshalCredential(cxf.TOTPCredential{
			Type:      cxf.CredentialTypeTOTP,
			Secret:    "",
			Period:    30,
			Digits:    6,
			Algorithm: cxf.OTPHashAlgorithmSha1,
		})
	}

	// Map algorithm
	var algorithm string
	switch c.TOTP.Algorithm {
	case model.TOTPAlgorithmSHA256:
		algorithm = cxf.OTPHashAlgorithmSha256
	case model.TOTPAlgorithmSHA512:
		algorithm = cxf.OTPHashAlgorithmSha512
	default:
		algorithm = cxf.OTPHashAlgorithmSha1
	}

	// Use defaults for missing values
	period := c.TOTP.Period
	if period == 0 {
		period = 30
	}
	digits := c.TOTP.Digits
	if digits == 0 {
		digits = 6
	}

	cred := cxf.TOTPCredential{
		Type:      cxf.CredentialTypeTOTP,
		Secret:    c.TOTP.Secret,
		Period:    uint8(period),
		Digits:    uint8(digits),
		Username:  c.Username,
		Algorithm: algorithm,
		Issuer:    c.TOTP.Issuer,
	}

	return marshalCredential(cred)
}

// mapSSHKey creates an SSHKeyCredential from a model.Credential.
func mapSSHKey(c *model.Credential) (json.RawMessage, error) {
	if c.SSHKey == nil {
		return marshalCredential(cxf.SSHKeyCredential{
			Type:       cxf.CredentialTypeSSHKey,
			KeyType:    "ssh-ed25519",
			PrivateKey: "",
		})
	}

	// Map key type
	var keyType string
	switch c.SSHKey.KeyType {
	case model.SSHKeyTypeRSA:
		keyType = "ssh-rsa"
	case model.SSHKeyTypeECDSA:
		keyType = "ecdsa-sha2-nistp256"
	case model.SSHKeyTypeDSA:
		keyType = "ssh-dss"
	case model.SSHKeyTypeEd25519:
		keyType = "ssh-ed25519"
	default:
		keyType = "ssh-ed25519"
	}

	// Encode private key as base64url if not already
	privateKey := c.SSHKey.PrivateKey
	if privateKey != "" && !isBase64URL(privateKey) {
		privateKey = base64.RawURLEncoding.EncodeToString([]byte(privateKey))
	}

	cred := cxf.SSHKeyCredential{
		Type:       cxf.CredentialTypeSSHKey,
		KeyType:    keyType,
		PrivateKey: privateKey,
		KeyComment: c.SSHKey.Comment,
	}

	return marshalCredential(cred)
}

// mapNote creates a NoteCredential from a model.Credential.
func mapNote(c *model.Credential) (json.RawMessage, error) {
	content := c.Notes
	if content == "" && c.Password != "" {
		// Use password as content for note type if no notes
		content = c.Password
	}

	cred := cxf.NoteCredential{
		Type:    cxf.CredentialTypeNote,
		Content: makeEditableField(cxf.FieldTypeString, content),
	}

	return marshalCredential(cred)
}

// mapCreditCard creates a CreditCardCredential from a model.Credential.
func mapCreditCard(c *model.Credential) (json.RawMessage, error) {
	cred := cxf.CreditCardCredential{
		Type: cxf.CredentialTypeCreditCard,
	}

	if c.CreditCard != nil {
		if c.CreditCard.Number != "" {
			cred.Number = makeEditableField(cxf.FieldTypeConcealedString, c.CreditCard.Number)
		}
		if c.CreditCard.Holder != "" {
			cred.FullName = makeEditableField(cxf.FieldTypeString, c.CreditCard.Holder)
		}
		if c.CreditCard.Brand != "" {
			cred.CardType = makeEditableField(cxf.FieldTypeString, c.CreditCard.Brand)
		}
		if c.CreditCard.CVV != "" {
			cred.VerificationNumber = makeEditableField(cxf.FieldTypeConcealedString, c.CreditCard.CVV)
		}
		if c.CreditCard.PIN != "" {
			cred.PIN = makeEditableField(cxf.FieldTypeConcealedString, c.CreditCard.PIN)
		}
		if c.CreditCard.ExpiryMonth != 0 || c.CreditCard.ExpiryYear != 0 {
			expiryDate := formatExpiryDateInts(c.CreditCard.ExpiryYear, c.CreditCard.ExpiryMonth)
			if expiryDate != "" {
				cred.ExpiryDate = makeEditableField(cxf.FieldTypeYearMonth, expiryDate)
			}
		}
	}

	return marshalCredential(cred)
}

// mapAPIKey creates an APIKeyCredential from a model.Credential.
func mapAPIKey(c *model.Credential) (json.RawMessage, error) {
	cred := cxf.APIKeyCredential{
		Type: cxf.CredentialTypeAPIKey,
	}

	if c.Password != "" {
		cred.Key = makeEditableField(cxf.FieldTypeConcealedString, c.Password)
	}
	if c.Username != "" {
		cred.Username = makeEditableField(cxf.FieldTypeString, c.Username)
	}
	if c.URL != "" {
		cred.URL = makeEditableField(cxf.FieldTypeString, c.URL)
	}

	return marshalCredential(cred)
}

// mapWiFi creates a WiFiCredential from a model.Credential.
func mapWiFi(c *model.Credential) (json.RawMessage, error) {
	cred := cxf.WiFiCredential{
		Type: cxf.CredentialTypeWiFi,
	}

	// Use Title as SSID
	if c.Title != "" {
		cred.SSID = makeEditableField(cxf.FieldTypeString, c.Title)
	}

	// Use Password as passphrase
	if c.Password != "" {
		cred.Passphrase = makeEditableField(cxf.FieldTypeConcealedString, c.Password)
	}

	// Default to WPA2 if we have a password
	if c.Password != "" {
		cred.NetworkSecurityType = makeEditableField(cxf.FieldTypeWifiNetworkSecurity, cxf.WifiSecurityWPA2Personal)
	} else {
		cred.NetworkSecurityType = makeEditableField(cxf.FieldTypeWifiNetworkSecurity, cxf.WifiSecurityUnsecured)
	}

	return marshalCredential(cred)
}

// mapCustomFields creates a CustomFieldsCredential from custom fields map.
func mapCustomFields(fields map[string]string) (json.RawMessage, error) {
	editableFields := make([]cxf.EditableField, 0, len(fields))

	for key, value := range fields {
		// Determine field type based on content
		fieldType := cxf.FieldTypeString
		lowerKey := strings.ToLower(key)
		if strings.Contains(lowerKey, "password") ||
			strings.Contains(lowerKey, "secret") ||
			strings.Contains(lowerKey, "key") ||
			strings.Contains(lowerKey, "token") {
			fieldType = cxf.FieldTypeConcealedString
		}

		fieldValue, _ := json.Marshal(value)
		editableFields = append(editableFields, cxf.EditableField{
			ID:        generateBase64URLID(),
			FieldType: fieldType,
			Value:     fieldValue,
			Label:     key,
		})
	}

	cred := cxf.CustomFieldsCredential{
		Type:   cxf.CredentialTypeCustomFields,
		ID:     generateBase64URLID(),
		Label:  "Custom Fields",
		Fields: editableFields,
	}

	return marshalCredential(cred)
}

// makeEditableField creates an EditableField with the given type and value.
func makeEditableField(fieldType, value string) *cxf.EditableField {
	if value == "" {
		return nil
	}

	marshalledValue, _ := json.Marshal(value)
	return &cxf.EditableField{
		FieldType: fieldType,
		Value:     marshalledValue,
	}
}

// marshalCredential marshals a credential to json.RawMessage.
func marshalCredential(cred any) (json.RawMessage, error) {
	return json.Marshal(cred)
}

// isBase64URL checks if a string is valid base64url encoding.
func isBase64URL(s string) bool {
	if s == "" {
		return false
	}
	_, err := base64.RawURLEncoding.DecodeString(s)
	return err == nil
}

// formatExpiryDate formats year and month strings as YYYY-MM.
func formatExpiryDate(year, month string) string {
	if year == "" || month == "" {
		return ""
	}

	// Ensure year is 4 digits
	if len(year) == 2 {
		year = "20" + year
	}

	// Ensure month is 2 digits
	if len(month) == 1 {
		month = "0" + month
	}

	return year + "-" + month
}

// formatExpiryDateInts formats year and month ints as YYYY-MM.
func formatExpiryDateInts(year, month int) string {
	if year == 0 || month == 0 {
		return ""
	}

	// Ensure year is 4 digits
	yearStr := fmt.Sprintf("%d", year)
	if len(yearStr) == 2 {
		yearStr = "20" + yearStr
	}

	// Format month with leading zero
	monthStr := fmt.Sprintf("%02d", month)

	return yearStr + "-" + monthStr
}
