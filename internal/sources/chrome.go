package sources

import (
	"encoding/csv"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/google/uuid"

	"github.com/nvinuesa/cxporter/internal/model"
)

// Chrome CSV header columns.
const (
	chromeColName     = "name"
	chromeColURL      = "url"
	chromeColUsername = "username"
	chromeColPassword = "password"
	chromeColNote     = "note"
)

// ChromeSource implements the Source interface for Chrome CSV exports.
type ChromeSource struct {
	filePath    string
	opts        OpenOptions
	fileInfo    os.FileInfo
	isOpen      bool
	credentials []model.Credential
}

// NewChromeSource creates a new Chrome CSV source adapter.
func NewChromeSource() *ChromeSource {
	return &ChromeSource{}
}

// Name returns the unique identifier for this source.
func (s *ChromeSource) Name() string {
	return "chrome"
}

// Description returns a human-readable description.
func (s *ChromeSource) Description() string {
	return "Google Chrome password export (CSV)"
}

// SupportedExtensions returns file extensions this source handles.
func (s *ChromeSource) SupportedExtensions() []string {
	return []string{".csv"}
}

// Detect checks if the given path is a Chrome CSV export.
func (s *ChromeSource) Detect(path string) (int, error) {
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

	// Check for Chrome CSV header
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

	// Chrome CSV has specific columns
	confidence := detectChromeHeader(header)
	return confidence, nil
}

// detectChromeHeader checks if the header matches Chrome CSV format.
func detectChromeHeader(header []string) int {
	if len(header) < 4 {
		return 0
	}

	// Normalize header names
	normalized := make([]string, len(header))
	for i, h := range header {
		normalized[i] = strings.ToLower(strings.TrimSpace(h))
	}

	// Chrome CSV columns (required)
	required := []string{chromeColName, chromeColURL, chromeColUsername, chromeColPassword}
	found := 0
	for _, req := range required {
		for _, h := range normalized {
			if h == req {
				found++
				break
			}
		}
	}

	if found == len(required) {
		return 100 // Perfect match
	}

	if found >= 3 {
		return 70 // Close match
	}

	return 0
}

// Open initializes the source with the given file path.
func (s *ChromeSource) Open(path string, opts OpenOptions) error {
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

// Read parses the Chrome CSV and returns credentials.
func (s *ChromeSource) Read() ([]model.Credential, error) {
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
	requiredCols := []string{chromeColName, chromeColURL, chromeColUsername, chromeColPassword}
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
func (s *ChromeSource) parseRecord(record []string, colIndex map[string]int, lineNum int) (*model.Credential, error) {
	getField := func(name string) string {
		if idx, ok := colIndex[name]; ok && idx < len(record) {
			// Sanitize for CSV/formula injection
			return sanitizeCSVField(strings.TrimSpace(record[idx]))
		}
		return ""
	}

	name := getField(chromeColName)
	urlStr := getField(chromeColURL)
	username := getField(chromeColUsername)
	password := getField(chromeColPassword)
	note := getField(chromeColNote)

	// Skip entries with no useful data
	if name == "" && urlStr == "" && username == "" && password == "" {
		return nil, nil
	}

	// Generate UUID for the credential
	id := uuid.New().String()

	// Use file modification time for timestamps
	modTime := s.fileInfo.ModTime()

	cred := &model.Credential{
		ID:       id,
		Type:     model.TypeBasicAuth,
		Title:    name,
		URL:      urlStr,
		Username: username,
		Password: password,
		Notes:    note,
		Created:  modTime,
		Modified: modTime,
	}

	return cred, nil
}

// Close releases resources.
func (s *ChromeSource) Close() error {
	s.isOpen = false
	s.filePath = ""
	s.fileInfo = nil
	s.credentials = nil
	return nil
}

// isEmptyRecord checks if a CSV record has only empty fields.
func isEmptyRecord(record []string) bool {
	for _, field := range record {
		if strings.TrimSpace(field) != "" {
			return false
		}
	}
	return true
}

// bomSkippingReader wraps a reader and skips UTF-8 BOM if present.
type bomSkippingReader struct {
	r       io.Reader
	checked bool
}

func newBOMSkippingReader(r io.Reader) *bomSkippingReader {
	return &bomSkippingReader{r: r}
}

func (r *bomSkippingReader) Read(p []byte) (int, error) {
	if !r.checked {
		r.checked = true

		// Read first 3 bytes to check for BOM
		bom := make([]byte, 3)
		n, err := r.r.Read(bom)
		if err != nil {
			return 0, err
		}

		// Check for UTF-8 BOM (0xEF, 0xBB, 0xBF)
		if n >= 3 && bom[0] == 0xEF && bom[1] == 0xBB && bom[2] == 0xBF {
			// BOM found, skip it
			return r.r.Read(p)
		}

		// No BOM, copy what we read to output
		copy(p, bom[:n])
		if n < len(p) {
			n2, err := r.r.Read(p[n:])
			return n + n2, err
		}
		return n, nil
	}
	return r.r.Read(p)
}

// sanitizeCSVField removes or escapes formula injection characters.
// CSV fields starting with =, +, -, @, tab, or carriage return
// can trigger formula execution in spreadsheet applications.
func sanitizeCSVField(s string) string {
	if s == "" {
		return s
	}

	// Check for formula injection prefixes
	// These characters can trigger formula execution in Excel, LibreOffice, etc.
	firstChar := s[0]
	if firstChar == '=' || firstChar == '+' || firstChar == '-' || firstChar == '@' ||
		firstChar == '\t' || firstChar == '\r' {
		// Prefix with a single quote to escape the formula
		// This is a common mitigation that prevents formula execution
		return "'" + s
	}

	return s
}

// init registers the Chrome source with the default registry.
func init() {
	RegisterDefault(NewChromeSource())
}

// Ensure ChromeSource implements Source interface
var _ Source = (*ChromeSource)(nil)
