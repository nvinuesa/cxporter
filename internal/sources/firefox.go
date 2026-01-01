package sources

import (
	"encoding/csv"
	"fmt"
	"io"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/nvinuesa/cxporter/internal/model"
)

// Firefox CSV header columns.
const (
	firefoxColURL                 = "url"
	firefoxColUsername            = "username"
	firefoxColPassword            = "password"
	firefoxColHTTPRealm           = "httprealm"
	firefoxColFormActionOrigin    = "formactionorigin"
	firefoxColGUID                = "guid"
	firefoxColTimeCreated         = "timecreated"
	firefoxColTimeLastUsed        = "timelastused"
	firefoxColTimePasswordChanged = "timepasswordchanged"
)

// FirefoxSource implements the Source interface for Firefox CSV exports.
type FirefoxSource struct {
	filePath    string
	opts        OpenOptions
	fileInfo    os.FileInfo
	isOpen      bool
	credentials []model.Credential
}

// NewFirefoxSource creates a new Firefox CSV source adapter.
func NewFirefoxSource() *FirefoxSource {
	return &FirefoxSource{}
}

// Name returns the unique identifier for this source.
func (s *FirefoxSource) Name() string {
	return "firefox"
}

// Description returns a human-readable description.
func (s *FirefoxSource) Description() string {
	return "Mozilla Firefox password export (CSV)"
}

// SupportedExtensions returns file extensions this source handles.
func (s *FirefoxSource) SupportedExtensions() []string {
	return []string{".csv"}
}

// Detect checks if the given path is a Firefox CSV export.
func (s *FirefoxSource) Detect(path string) (int, error) {
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
	ext := strings.ToLower(filepath.Ext(path))
	if ext != ".csv" {
		return 0, nil
	}

	// Check for Firefox CSV header
	f, err := os.Open(path)
	if err != nil {
		return 0, err
	}
	defer f.Close()

	// Read first line
	reader := csv.NewReader(f)
	reader.LazyQuotes = true
	reader.TrimLeadingSpace = true

	header, err := reader.Read()
	if err != nil {
		return 0, nil // Not a valid CSV
	}

	// Firefox CSV has specific columns
	confidence := detectFirefoxHeader(header)
	return confidence, nil
}

// detectFirefoxHeader checks if the header matches Firefox CSV format.
func detectFirefoxHeader(header []string) int {
	if len(header) < 3 {
		return 0
	}

	// Normalize header names
	normalized := make([]string, len(header))
	for i, h := range header {
		normalized[i] = strings.ToLower(strings.TrimSpace(h))
	}

	// Firefox CSV required columns
	required := []string{firefoxColURL, firefoxColUsername, firefoxColPassword}
	found := 0
	for _, req := range required {
		for _, h := range normalized {
			if h == req {
				found++
				break
			}
		}
	}

	if found < 3 {
		return 0
	}

	// Check for Firefox-specific columns (guid, httpRealm, etc.)
	firefoxSpecific := []string{firefoxColGUID, firefoxColHTTPRealm, firefoxColTimeCreated}
	firefoxMatches := 0
	for _, spec := range firefoxSpecific {
		for _, h := range normalized {
			if h == spec {
				firefoxMatches++
				break
			}
		}
	}

	if firefoxMatches >= 2 {
		return 100 // High confidence - Firefox specific columns
	} else if firefoxMatches == 1 {
		return 80 // Medium confidence
	}

	return 0 // Could be Chrome or other CSV
}

// Open initializes the source with the given file path.
func (s *FirefoxSource) Open(path string, opts OpenOptions) error {
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

	s.filePath = path
	s.opts = opts
	s.fileInfo = info
	s.isOpen = true
	s.credentials = nil

	return nil
}

// Read parses the Firefox CSV and returns credentials.
func (s *FirefoxSource) Read() ([]model.Credential, error) {
	if !s.isOpen {
		return nil, ErrNotOpen
	}

	// Return cached results if available
	if s.credentials != nil {
		return s.credentials, nil
	}

	f, err := os.Open(s.filePath)
	if err != nil {
		return nil, &ErrPermissionDenied{Path: s.filePath, Op: "open", Err: err}
	}
	defer f.Close()

	// Handle UTF-8 BOM
	reader := newBOMSkippingReader(f)
	csvReader := csv.NewReader(reader)
	csvReader.LazyQuotes = true
	csvReader.TrimLeadingSpace = true
	csvReader.FieldsPerRecord = -1 // Variable field count

	// Read header
	header, err := csvReader.Read()
	if err != nil {
		return nil, &ErrInvalidFormat{
			Source:  s.Name(),
			Path:    s.filePath,
			Details: "failed to read CSV header",
			Err:     err,
		}
	}

	// Build column index
	colIndex := make(map[string]int)
	for i, h := range header {
		colIndex[strings.ToLower(strings.TrimSpace(h))] = i
	}

	// Validate required columns
	requiredCols := []string{firefoxColURL, firefoxColUsername, firefoxColPassword}
	for _, col := range requiredCols {
		if _, ok := colIndex[col]; !ok {
			return nil, &ErrInvalidFormat{
				Source:  s.Name(),
				Path:    s.filePath,
				Details: fmt.Sprintf("missing required column: %s", col),
			}
		}
	}

	var credentials []model.Credential
	partialErr := &ErrPartialRead{Source: s.Name()}

	lineNum := 1 // Start at 1 because we already read header
	for {
		lineNum++
		record, err := csvReader.Read()
		if err == io.EOF {
			break
		}
		if err != nil {
			partialErr.TotalItems++
			partialErr.AddFailure(fmt.Sprintf("line %d: parse error", lineNum), err)
			continue
		}

		partialErr.TotalItems++

		// Skip empty rows
		if isEmptyRecord(record) {
			continue
		}

		cred, err := s.parseRecord(record, colIndex, lineNum)
		if err != nil {
			partialErr.AddFailure(fmt.Sprintf("line %d: %v", lineNum, err), err)
			continue
		}

		if cred != nil {
			credentials = append(credentials, *cred)
			partialErr.ReadItems++
		}
	}

	s.credentials = credentials

	if partialErr.HasFailures() {
		return credentials, partialErr
	}

	return credentials, nil
}

// parseRecord converts a CSV record to a credential.
func (s *FirefoxSource) parseRecord(record []string, colIndex map[string]int, lineNum int) (*model.Credential, error) {
	getField := func(name string) string {
		if idx, ok := colIndex[name]; ok && idx < len(record) {
			// Sanitize for CSV/formula injection
			return sanitizeCSVField(strings.TrimSpace(record[idx]))
		}
		return ""
	}

	urlStr := getField(firefoxColURL)
	username := getField(firefoxColUsername)
	password := getField(firefoxColPassword)
	httpRealm := getField(firefoxColHTTPRealm)
	guid := getField(firefoxColGUID)
	timeCreated := getField(firefoxColTimeCreated)
	timePasswordChanged := getField(firefoxColTimePasswordChanged)

	// Skip entries with no useful data
	if urlStr == "" && username == "" && password == "" {
		return nil, nil
	}

	// Generate title from URL
	title := extractDomainFromURL(urlStr)
	if httpRealm != "" {
		title = title + " (HTTP Auth)"
	}

	// Use GUID as ID if available
	id := guid
	if id == "" {
		id = generateUUID()
	}

	// Parse timestamps (Firefox uses milliseconds since epoch)
	var created, modified time.Time
	if timeCreated != "" {
		created = parseMillisTimestamp(timeCreated)
	}
	if timePasswordChanged != "" {
		modified = parseMillisTimestamp(timePasswordChanged)
	}

	// Fall back to file modification time
	if created.IsZero() {
		created = s.fileInfo.ModTime()
	}
	if modified.IsZero() {
		modified = s.fileInfo.ModTime()
	}

	// Build notes from httpRealm if present
	var notes string
	if httpRealm != "" {
		notes = fmt.Sprintf("HTTP Basic Auth Realm: %s", httpRealm)
	}

	cred := &model.Credential{
		ID:       id,
		Type:     model.TypeBasicAuth,
		Title:    title,
		URL:      urlStr,
		Username: username,
		Password: password,
		Notes:    notes,
		Created:  created,
		Modified: modified,
	}

	return cred, nil
}

// Close releases resources.
func (s *FirefoxSource) Close() error {
	s.isOpen = false
	s.filePath = ""
	s.fileInfo = nil
	s.credentials = nil
	return nil
}

// extractDomainFromURL extracts the domain from a URL for use as title.
func extractDomainFromURL(rawURL string) string {
	if rawURL == "" {
		return "Unknown"
	}

	parsed, err := url.Parse(rawURL)
	if err != nil || parsed.Host == "" {
		// Try to extract something useful
		rawURL = strings.TrimPrefix(rawURL, "http://")
		rawURL = strings.TrimPrefix(rawURL, "https://")
		if idx := strings.Index(rawURL, "/"); idx > 0 {
			return rawURL[:idx]
		}
		return rawURL
	}

	return parsed.Host
}

// parseMillisTimestamp parses a milliseconds-since-epoch timestamp.
func parseMillisTimestamp(s string) time.Time {
	millis, err := strconv.ParseInt(s, 10, 64)
	if err != nil {
		return time.Time{}
	}
	return time.UnixMilli(millis)
}

// generateUUID generates a new UUID string.
func generateUUID() string {
	return fmt.Sprintf("%d", time.Now().UnixNano())
}

// init registers the Firefox source with the default registry.
func init() {
	RegisterDefault(NewFirefoxSource())
}

// Ensure FirefoxSource implements Source interface
var _ Source = (*FirefoxSource)(nil)
