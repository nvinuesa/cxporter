package sources

import (
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/nvinuesa/cxporter/internal/model"
)

// Bitwarden item types.
const (
	bitwardenTypeLogin      = 1
	bitwardenTypeSecureNote = 2
	bitwardenTypeCard       = 3
	bitwardenTypeIdentity   = 4
)

// BitwardenExport represents the top-level Bitwarden JSON export structure.
type BitwardenExport struct {
	Encrypted bool              `json:"encrypted"`
	Folders   []BitwardenFolder `json:"folders"`
	Items     []BitwardenItem   `json:"items"`
}

// BitwardenFolder represents a folder in the Bitwarden export.
type BitwardenFolder struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

// BitwardenItem represents a single item in the Bitwarden export.
type BitwardenItem struct {
	ID             string             `json:"id"`
	OrganizationID string             `json:"organizationId"`
	FolderID       string             `json:"folderId"`
	Type           int                `json:"type"`
	Name           string             `json:"name"`
	Notes          string             `json:"notes"`
	Favorite       bool               `json:"favorite"`
	Login          *BitwardenLogin    `json:"login,omitempty"`
	SecureNote     *BitwardenNote     `json:"secureNote,omitempty"`
	Card           *BitwardenCard     `json:"card,omitempty"`
	Identity       *BitwardenIdentity `json:"identity,omitempty"`
	CollectionIDs  []string           `json:"collectionIds"`
	CreationDate   string             `json:"creationDate"`
	RevisionDate   string             `json:"revisionDate"`
	Reprompt       int                `json:"reprompt"`
	Fields         []BitwardenField   `json:"fields,omitempty"`
}

// BitwardenLogin represents login data in a Bitwarden item.
type BitwardenLogin struct {
	URIs     []BitwardenURI `json:"uris"`
	Username string         `json:"username"`
	Password string         `json:"password"`
	TOTP     string         `json:"totp"`
}

// BitwardenURI represents a URI entry in a Bitwarden login.
type BitwardenURI struct {
	URI   string `json:"uri"`
	Match *int   `json:"match,omitempty"`
}

// BitwardenNote represents secure note data in a Bitwarden item.
type BitwardenNote struct {
	Type int `json:"type"`
}

// BitwardenCard represents credit card data in a Bitwarden item.
type BitwardenCard struct {
	CardholderName string `json:"cardholderName"`
	Brand          string `json:"brand"`
	Number         string `json:"number"`
	ExpMonth       string `json:"expMonth"`
	ExpYear        string `json:"expYear"`
	Code           string `json:"code"`
}

// BitwardenIdentity represents identity data in a Bitwarden item.
type BitwardenIdentity struct {
	Title          string `json:"title"`
	FirstName      string `json:"firstName"`
	MiddleName     string `json:"middleName"`
	LastName       string `json:"lastName"`
	Address1       string `json:"address1"`
	Address2       string `json:"address2"`
	Address3       string `json:"address3"`
	City           string `json:"city"`
	State          string `json:"state"`
	PostalCode     string `json:"postalCode"`
	Country        string `json:"country"`
	Company        string `json:"company"`
	Email          string `json:"email"`
	Phone          string `json:"phone"`
	SSN            string `json:"ssn"`
	Username       string `json:"username"`
	PassportNumber string `json:"passportNumber"`
	LicenseNumber  string `json:"licenseNumber"`
}

// BitwardenField represents a custom field in a Bitwarden item.
type BitwardenField struct {
	Name  string `json:"name"`
	Value string `json:"value"`
	Type  int    `json:"type"` // 0=text, 1=hidden, 2=boolean, 3=linked
}

// BitwardenSource implements the Source interface for Bitwarden JSON exports.
type BitwardenSource struct {
	filePath    string
	opts        OpenOptions
	fileInfo    os.FileInfo
	isOpen      bool
	credentials []model.Credential
	export      *BitwardenExport
}

// NewBitwardenSource creates a new Bitwarden JSON source adapter.
func NewBitwardenSource() *BitwardenSource {
	return &BitwardenSource{}
}

// Name returns the unique identifier for this source.
func (s *BitwardenSource) Name() string {
	return "bitwarden"
}

// Description returns a human-readable description.
func (s *BitwardenSource) Description() string {
	return "Bitwarden unencrypted JSON export"
}

// SupportedExtensions returns file extensions this source handles.
func (s *BitwardenSource) SupportedExtensions() []string {
	return []string{".json"}
}

// Detect checks if the given path is a Bitwarden JSON export.
func (s *BitwardenSource) Detect(path string) (int, error) {
	info, err := os.Stat(path)
	if err != nil {
		if os.IsNotExist(err) {
			return 0, &ErrFileNotFound{Path: path}
		}
		return 0, err
	}

	if info.IsDir() {
		return 0, nil
	}

	// Check extension
	if !strings.HasSuffix(strings.ToLower(path), ".json") {
		return 0, nil
	}

	// Try to parse the JSON to detect Bitwarden structure
	data, err := os.ReadFile(path)
	if err != nil {
		return 0, nil
	}

	var export BitwardenExport
	if err := json.Unmarshal(data, &export); err != nil {
		return 0, nil
	}

	// Check for Bitwarden-specific structure
	confidence := detectBitwardenStructure(&export)
	return confidence, nil
}

// detectBitwardenStructure checks if the JSON matches Bitwarden export format.
func detectBitwardenStructure(export *BitwardenExport) int {
	// If explicitly encrypted, we can detect it but with lower confidence
	// since we can't actually parse it
	if export.Encrypted {
		return 50 // We detect it's Bitwarden but can't use it
	}

	// Check for items array
	if len(export.Items) == 0 && len(export.Folders) == 0 {
		return 0
	}

	// Check items have Bitwarden-specific structure
	bitwardenIndicators := 0
	for _, item := range export.Items {
		// Check for Bitwarden item types
		if item.Type >= 1 && item.Type <= 4 {
			bitwardenIndicators++
		}
		// Check for Bitwarden-specific fields
		if item.Login != nil && len(item.Login.URIs) > 0 {
			bitwardenIndicators++
		}
		if item.RevisionDate != "" || item.CreationDate != "" {
			bitwardenIndicators++
		}
		if item.CollectionIDs != nil {
			bitwardenIndicators++
		}
		// Only need a few indicators
		if bitwardenIndicators >= 3 {
			break
		}
	}

	if bitwardenIndicators >= 3 {
		return 100
	} else if bitwardenIndicators >= 1 {
		return 80
	}

	return 0
}

// Open initializes the source with the given file path.
func (s *BitwardenSource) Open(path string, opts OpenOptions) error {
	if s.isOpen {
		return ErrAlreadyOpen
	}

	info, err := os.Stat(path)
	if err != nil {
		if os.IsNotExist(err) {
			return &ErrFileNotFound{Path: path}
		}
		return &ErrPermissionDenied{Path: path, Op: "stat", Err: err}
	}

	if info.IsDir() {
		return &ErrInvalidFormat{
			Source:  s.Name(),
			Path:    path,
			Details: "path must be a file, not a directory",
		}
	}

	// Read and parse JSON
	data, err := os.ReadFile(path)
	if err != nil {
		return &ErrPermissionDenied{Path: path, Op: "read", Err: err}
	}

	var export BitwardenExport
	if err := json.Unmarshal(data, &export); err != nil {
		return &ErrInvalidFormat{
			Source:  s.Name(),
			Path:    path,
			Details: "invalid JSON",
			Err:     err,
		}
	}

	// Reject encrypted exports
	if export.Encrypted {
		return &ErrInvalidFormat{
			Source:  s.Name(),
			Path:    path,
			Details: "encrypted Bitwarden exports are not supported; please export without encryption",
		}
	}

	s.filePath = path
	s.opts = opts
	s.fileInfo = info
	s.isOpen = true
	s.credentials = nil
	s.export = &export

	return nil
}

// Read parses the Bitwarden JSON and returns credentials.
func (s *BitwardenSource) Read() ([]model.Credential, error) {
	if !s.isOpen {
		return nil, ErrNotOpen
	}

	// Return cached results if available
	if s.credentials != nil {
		return s.credentials, nil
	}

	// Build folder lookup map
	folderMap := make(map[string]string)
	for _, folder := range s.export.Folders {
		folderMap[folder.ID] = folder.Name
	}

	var credentials []model.Credential
	partialErr := &ErrPartialRead{Source: s.Name()}

	for i, item := range s.export.Items {
		partialErr.TotalItems++

		creds, err := s.parseItem(&item, folderMap)
		if err != nil {
			partialErr.AddFailure(fmt.Sprintf("item %d (%s): %v", i, item.Name, err), err)
			continue
		}

		for _, cred := range creds {
			credentials = append(credentials, cred)
			partialErr.ReadItems++
		}
	}

	s.credentials = credentials

	if partialErr.HasFailures() {
		return credentials, partialErr
	}

	return credentials, nil
}

// parseItem converts a Bitwarden item to one or more credentials.
func (s *BitwardenSource) parseItem(item *BitwardenItem, folderMap map[string]string) ([]model.Credential, error) {
	var credentials []model.Credential

	// Determine folder path
	folderPath := ""
	if item.FolderID != "" {
		if name, ok := folderMap[item.FolderID]; ok {
			folderPath = name
		}
	}

	// Parse timestamps
	created := parseISOTimestamp(item.CreationDate)
	if created.IsZero() {
		created = s.fileInfo.ModTime()
	}
	modified := parseISOTimestamp(item.RevisionDate)
	if modified.IsZero() {
		modified = s.fileInfo.ModTime()
	}

	// Build base credential
	baseCred := model.Credential{
		ID:         item.ID,
		Title:      item.Name,
		Notes:      item.Notes,
		FolderPath: folderPath,
		Created:    created,
		Modified:   modified,
	}

	// Add favorite tag
	if item.Favorite {
		baseCred.Tags = append(baseCred.Tags, "favorite")
	}

	// Add custom fields
	if len(item.Fields) > 0 {
		baseCred.CustomFields = make(map[string]string)
		for _, field := range item.Fields {
			if field.Name != "" {
				baseCred.CustomFields[field.Name] = field.Value
			}
		}
	}

	switch item.Type {
	case bitwardenTypeLogin:
		cred := s.parseLogin(item, baseCred)
		credentials = append(credentials, cred)

		// If TOTP is present, create a separate TOTP credential
		if item.Login != nil && item.Login.TOTP != "" {
			totpCred := s.parseTOTP(item, baseCred)
			if totpCred != nil {
				credentials = append(credentials, *totpCred)
			}
		}

	case bitwardenTypeSecureNote:
		cred := s.parseSecureNote(baseCred)
		credentials = append(credentials, cred)

	case bitwardenTypeCard:
		cred := s.parseCard(item, baseCred)
		credentials = append(credentials, cred)

	case bitwardenTypeIdentity:
		cred := s.parseIdentity(item, baseCred)
		credentials = append(credentials, cred)

	default:
		return nil, fmt.Errorf("unknown item type: %d", item.Type)
	}

	return credentials, nil
}

// parseLogin converts a Bitwarden login to a credential.
func (s *BitwardenSource) parseLogin(item *BitwardenItem, base model.Credential) model.Credential {
	cred := base
	cred.Type = model.TypeBasicAuth

	if item.Login != nil {
		cred.Username = item.Login.Username
		cred.Password = item.Login.Password

		// Get primary URL
		if len(item.Login.URIs) > 0 {
			cred.URL = item.Login.URIs[0].URI

			// Add additional URIs to custom fields
			for i := 1; i < len(item.Login.URIs); i++ {
				if cred.CustomFields == nil {
					cred.CustomFields = make(map[string]string)
				}
				cred.CustomFields[fmt.Sprintf("uri_%d", i+1)] = item.Login.URIs[i].URI
			}
		}
	}

	return cred
}

// parseTOTP extracts TOTP data from a login item.
func (s *BitwardenSource) parseTOTP(item *BitwardenItem, base model.Credential) *model.Credential {
	if item.Login == nil || item.Login.TOTP == "" {
		return nil
	}

	cred := base
	cred.ID = item.ID + "-totp"
	cred.Type = model.TypeTOTP
	cred.Title = base.Title + " (TOTP)"

	totpData := parseTOTPString(item.Login.TOTP)
	cred.TOTP = totpData

	return &cred
}

// parseTOTPString parses a TOTP string (otpauth:// URI or raw secret).
func parseTOTPString(totp string) *model.TOTPData {
	// Check if it's an otpauth:// URI
	if strings.HasPrefix(totp, "otpauth://totp/") {
		return parseBitwardenOTPAuthURI(totp)
	}

	// Assume it's a raw secret with default settings
	return model.NewTOTPData(totp)
}

// parseBitwardenOTPAuthURI parses an otpauth:// URI into TOTPData.
func parseBitwardenOTPAuthURI(uri string) *model.TOTPData {
	parsed, err := url.Parse(uri)
	if err != nil {
		// Fall back to treating it as a raw secret
		return model.NewTOTPData(uri)
	}

	// Extract label (account name)
	label := strings.TrimPrefix(parsed.Path, "/")
	label, _ = url.QueryUnescape(label)

	// Extract issuer from label if present (format: "Issuer:Account")
	var issuer, accountName string
	if idx := strings.Index(label, ":"); idx > 0 {
		issuer = label[:idx]
		accountName = label[idx+1:]
	} else {
		accountName = label
	}

	params := parsed.Query()

	// Get secret
	secret := params.Get("secret")
	if secret == "" {
		return model.NewTOTPData(uri) // Fall back
	}

	// Get optional parameters
	algorithm := model.TOTPAlgorithmSHA1
	switch strings.ToUpper(params.Get("algorithm")) {
	case "SHA256":
		algorithm = model.TOTPAlgorithmSHA256
	case "SHA512":
		algorithm = model.TOTPAlgorithmSHA512
	}

	digits := 6
	if d := params.Get("digits"); d != "" {
		if parsed, err := strconv.Atoi(d); err == nil && parsed > 0 {
			digits = parsed
		}
	}

	period := 30
	if p := params.Get("period"); p != "" {
		if parsed, err := strconv.Atoi(p); err == nil && parsed > 0 {
			period = parsed
		}
	}

	// Override issuer from query param if present
	if i := params.Get("issuer"); i != "" {
		issuer = i
	}

	return &model.TOTPData{
		Secret:      secret,
		Algorithm:   algorithm,
		Digits:      digits,
		Period:      period,
		Issuer:      issuer,
		AccountName: accountName,
	}
}

// parseSecureNote converts a Bitwarden secure note to a credential.
func (s *BitwardenSource) parseSecureNote(base model.Credential) model.Credential {
	cred := base
	cred.Type = model.TypeNote
	return cred
}

// parseCard converts a Bitwarden card to a credential.
func (s *BitwardenSource) parseCard(item *BitwardenItem, base model.Credential) model.Credential {
	cred := base
	cred.Type = model.TypeCreditCard

	if item.Card != nil {
		expMonth := 0
		if item.Card.ExpMonth != "" {
			if m, err := strconv.Atoi(item.Card.ExpMonth); err == nil {
				expMonth = m
			}
		}

		expYear := 0
		if item.Card.ExpYear != "" {
			if y, err := strconv.Atoi(item.Card.ExpYear); err == nil {
				expYear = y
			}
		}

		cred.CreditCard = &model.CreditCardData{
			Number:      item.Card.Number,
			Holder:      item.Card.CardholderName,
			ExpiryMonth: expMonth,
			ExpiryYear:  expYear,
			CVV:         item.Card.Code,
			Brand:       item.Card.Brand,
		}
	}

	return cred
}

// parseIdentity converts a Bitwarden identity to a credential.
func (s *BitwardenSource) parseIdentity(item *BitwardenItem, base model.Credential) model.Credential {
	cred := base
	cred.Type = model.TypeIdentity

	if item.Identity != nil {
		// Build structured notes from identity fields
		var parts []string

		if item.Identity.Title != "" {
			parts = append(parts, fmt.Sprintf("Title: %s", item.Identity.Title))
		}

		// Build full name
		nameParts := []string{}
		if item.Identity.FirstName != "" {
			nameParts = append(nameParts, item.Identity.FirstName)
		}
		if item.Identity.MiddleName != "" {
			nameParts = append(nameParts, item.Identity.MiddleName)
		}
		if item.Identity.LastName != "" {
			nameParts = append(nameParts, item.Identity.LastName)
		}
		if len(nameParts) > 0 {
			parts = append(parts, fmt.Sprintf("Name: %s", strings.Join(nameParts, " ")))
		}

		if item.Identity.Company != "" {
			parts = append(parts, fmt.Sprintf("Company: %s", item.Identity.Company))
		}
		if item.Identity.Email != "" {
			parts = append(parts, fmt.Sprintf("Email: %s", item.Identity.Email))
		}
		if item.Identity.Phone != "" {
			parts = append(parts, fmt.Sprintf("Phone: %s", item.Identity.Phone))
		}

		// Build address
		addressParts := []string{}
		if item.Identity.Address1 != "" {
			addressParts = append(addressParts, item.Identity.Address1)
		}
		if item.Identity.Address2 != "" {
			addressParts = append(addressParts, item.Identity.Address2)
		}
		if item.Identity.Address3 != "" {
			addressParts = append(addressParts, item.Identity.Address3)
		}
		cityStateZip := []string{}
		if item.Identity.City != "" {
			cityStateZip = append(cityStateZip, item.Identity.City)
		}
		if item.Identity.State != "" {
			cityStateZip = append(cityStateZip, item.Identity.State)
		}
		if item.Identity.PostalCode != "" {
			cityStateZip = append(cityStateZip, item.Identity.PostalCode)
		}
		if len(cityStateZip) > 0 {
			addressParts = append(addressParts, strings.Join(cityStateZip, ", "))
		}
		if item.Identity.Country != "" {
			addressParts = append(addressParts, item.Identity.Country)
		}
		if len(addressParts) > 0 {
			parts = append(parts, fmt.Sprintf("Address: %s", strings.Join(addressParts, ", ")))
		}

		// Sensitive fields
		if item.Identity.SSN != "" {
			parts = append(parts, fmt.Sprintf("SSN: %s", item.Identity.SSN))
		}
		if item.Identity.PassportNumber != "" {
			parts = append(parts, fmt.Sprintf("Passport: %s", item.Identity.PassportNumber))
		}
		if item.Identity.LicenseNumber != "" {
			parts = append(parts, fmt.Sprintf("License: %s", item.Identity.LicenseNumber))
		}
		if item.Identity.Username != "" {
			cred.Username = item.Identity.Username
		}

		// Combine with existing notes
		if len(parts) > 0 {
			identityInfo := strings.Join(parts, "\n")
			if cred.Notes != "" {
				cred.Notes = cred.Notes + "\n\n" + identityInfo
			} else {
				cred.Notes = identityInfo
			}
		}
	}

	return cred
}

// Close releases resources.
func (s *BitwardenSource) Close() error {
	s.isOpen = false
	s.filePath = ""
	s.fileInfo = nil
	s.credentials = nil
	s.export = nil
	return nil
}

// parseISOTimestamp parses an ISO 8601 timestamp string.
func parseISOTimestamp(s string) time.Time {
	if s == "" {
		return time.Time{}
	}

	// Try various ISO 8601 formats
	formats := []string{
		time.RFC3339,
		time.RFC3339Nano,
		"2006-01-02T15:04:05Z",
		"2006-01-02T15:04:05.000Z",
		"2006-01-02T15:04:05",
		"2006-01-02",
	}

	for _, format := range formats {
		if t, err := time.Parse(format, s); err == nil {
			return t
		}
	}

	return time.Time{}
}

// init registers the Bitwarden source with the default registry.
func init() {
	RegisterDefault(NewBitwardenSource())
}

// Ensure BitwardenSource implements Source interface
var _ Source = (*BitwardenSource)(nil)
