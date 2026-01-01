package test

import (
	"bytes"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/nvinuesa/cxporter/internal/cxf"
	"github.com/nvinuesa/cxporter/internal/cxp"
	"github.com/nvinuesa/cxporter/internal/model"
	"github.com/nvinuesa/cxporter/internal/sources"
	gocxf "github.com/nvinuesa/go-cxf"
)

// getItemCount returns total items across all accounts
func getItemCount(header *gocxf.Header) int {
	count := 0
	for _, account := range header.Accounts {
		count += len(account.Items)
	}
	return count
}

// getCollectionCount returns total collections across all accounts
func getCollectionCount(header *gocxf.Header) int {
	count := 0
	for _, account := range header.Accounts {
		count += len(account.Collections)
	}
	return count
}

// getItems returns all items across all accounts
func getItems(header *gocxf.Header) []gocxf.Item {
	var items []gocxf.Item
	for _, account := range header.Accounts {
		items = append(items, account.Items...)
	}
	return items
}

func getTestdataPath() string {
	// Find testdata relative to this test file
	wd, _ := os.Getwd()
	// Navigate up from test/ to project root
	return filepath.Join(wd, "..", "testdata")
}

func getBinaryPath() string {
	wd, _ := os.Getwd()
	return filepath.Join(wd, "..", "bin", "cxporter")
}

func TestChromeToCXF(t *testing.T) {
	csvPath := filepath.Join(getTestdataPath(), "chrome", "passwords.csv")
	if _, err := os.Stat(csvPath); os.IsNotExist(err) {
		t.Skip("testdata/chrome/passwords.csv not found")
	}

	// Open Chrome source
	source := sources.NewChromeSource()
	err := source.Open(csvPath, sources.OpenOptions{})
	if err != nil {
		t.Fatalf("Failed to open Chrome source: %v", err)
	}
	defer source.Close()

	// Read credentials
	creds, err := source.Read()
	if err != nil && !sources.IsPartialRead(err) {
		t.Fatalf("Failed to read credentials: %v", err)
	}

	if len(creds) == 0 {
		t.Fatal("Expected at least one credential from Chrome CSV")
	}

	// Generate CXF
	opts := cxf.DefaultOptions()
	header, err := cxf.Generate(creds, opts)
	if err != nil {
		t.Fatalf("Failed to generate CXF: %v", err)
	}

	// Verify structure
	if header.Version.Major != 1 || header.Version.Minor != 0 {
		t.Errorf("Expected version 1.0, got %d.%d", header.Version.Major, header.Version.Minor)
	}

	itemCount := getItemCount(header)
	if itemCount != len(creds) {
		t.Errorf("Expected %d items, got %d", len(creds), itemCount)
	}

	// Verify all items have credentials
	for _, item := range getItems(header) {
		if len(item.Credentials) == 0 {
			t.Errorf("Item %s has no credentials", item.ID)
		}
	}

	// Verify export works
	exportOpts := cxp.ExportOptions{}
	output, err := cxp.ExportToBytes(header, exportOpts)
	if err != nil {
		t.Fatalf("Failed to export CXF: %v", err)
	}

	if len(output) == 0 {
		t.Error("Export produced empty output")
	}

	// Verify output is valid JSON
	var parsed gocxf.Header
	if err := json.Unmarshal(output, &parsed); err != nil {
		t.Fatalf("Export produced invalid JSON: %v", err)
	}
}

func TestFirefoxToCXF(t *testing.T) {
	csvPath := filepath.Join(getTestdataPath(), "firefox", "logins.csv")
	if _, err := os.Stat(csvPath); os.IsNotExist(err) {
		t.Skip("testdata/firefox/logins.csv not found")
	}

	// Open Firefox source
	source := sources.NewFirefoxSource()
	err := source.Open(csvPath, sources.OpenOptions{})
	if err != nil {
		t.Fatalf("Failed to open Firefox source: %v", err)
	}
	defer source.Close()

	// Read credentials
	creds, err := source.Read()
	if err != nil && !sources.IsPartialRead(err) {
		t.Fatalf("Failed to read credentials: %v", err)
	}

	if len(creds) == 0 {
		t.Fatal("Expected at least one credential from Firefox CSV")
	}

	// Generate CXF
	opts := cxf.DefaultOptions()
	header, err := cxf.Generate(creds, opts)
	if err != nil {
		t.Fatalf("Failed to generate CXF: %v", err)
	}

	// Verify export
	exportOpts := cxp.ExportOptions{}
	output, err := cxp.ExportToBytes(header, exportOpts)
	if err != nil {
		t.Fatalf("Failed to export CXF: %v", err)
	}

	if len(output) == 0 {
		t.Error("Export produced empty output")
	}
}

func TestBitwardenToCXF(t *testing.T) {
	jsonPath := filepath.Join(getTestdataPath(), "bitwarden", "export.json")
	if _, err := os.Stat(jsonPath); os.IsNotExist(err) {
		t.Skip("testdata/bitwarden/export.json not found")
	}

	// Open Bitwarden source
	source := sources.NewBitwardenSource()
	err := source.Open(jsonPath, sources.OpenOptions{})
	if err != nil {
		t.Fatalf("Failed to open Bitwarden source: %v", err)
	}
	defer source.Close()

	// Read credentials
	creds, err := source.Read()
	if err != nil && !sources.IsPartialRead(err) {
		t.Fatalf("Failed to read credentials: %v", err)
	}

	if len(creds) == 0 {
		t.Fatal("Expected at least one credential from Bitwarden JSON")
	}

	// Count credential types
	typeCounts := make(map[model.CredentialType]int)
	for _, cred := range creds {
		typeCounts[cred.Type]++
	}

	// Should have multiple types from comprehensive Bitwarden export
	if typeCounts[model.TypeBasicAuth] == 0 {
		t.Error("Expected at least one BasicAuth credential")
	}
	if typeCounts[model.TypeNote] == 0 {
		t.Error("Expected at least one Note credential")
	}
	if typeCounts[model.TypeCreditCard] == 0 {
		t.Error("Expected at least one CreditCard credential")
	}

	// Generate CXF
	opts := cxf.DefaultOptions()
	opts.PreserveHierarchy = true
	header, err := cxf.Generate(creds, opts)
	if err != nil {
		t.Fatalf("Failed to generate CXF: %v", err)
	}

	// Verify collections are created
	if getCollectionCount(header) == 0 {
		t.Error("Expected collections from Bitwarden folders")
	}

	// Verify export
	exportOpts := cxp.ExportOptions{}
	output, err := cxp.ExportToBytes(header, exportOpts)
	if err != nil {
		t.Fatalf("Failed to export CXF: %v", err)
	}

	if len(output) == 0 {
		t.Error("Export produced empty output")
	}
}

func TestMixedSources(t *testing.T) {
	var allCreds []model.Credential

	// Load Chrome credentials
	chromePath := filepath.Join(getTestdataPath(), "chrome", "passwords.csv")
	if _, err := os.Stat(chromePath); err == nil {
		source := sources.NewChromeSource()
		if err := source.Open(chromePath, sources.OpenOptions{}); err == nil {
			creds, _ := source.Read()
			allCreds = append(allCreds, creds...)
			source.Close()
		}
	}

	// Load Firefox credentials
	firefoxPath := filepath.Join(getTestdataPath(), "firefox", "logins.csv")
	if _, err := os.Stat(firefoxPath); err == nil {
		source := sources.NewFirefoxSource()
		if err := source.Open(firefoxPath, sources.OpenOptions{}); err == nil {
			creds, _ := source.Read()
			allCreds = append(allCreds, creds...)
			source.Close()
		}
	}

	// Load Bitwarden credentials
	bitwardenPath := filepath.Join(getTestdataPath(), "bitwarden", "export.json")
	if _, err := os.Stat(bitwardenPath); err == nil {
		source := sources.NewBitwardenSource()
		if err := source.Open(bitwardenPath, sources.OpenOptions{}); err == nil {
			creds, _ := source.Read()
			allCreds = append(allCreds, creds...)
			source.Close()
		}
	}

	if len(allCreds) == 0 {
		t.Skip("No test data available")
	}

	// Generate combined CXF
	opts := cxf.DefaultOptions()
	header, err := cxf.Generate(allCreds, opts)
	if err != nil {
		t.Fatalf("Failed to generate combined CXF: %v", err)
	}

	if getItemCount(header) != len(allCreds) {
		t.Errorf("Expected %d items, got %d", len(allCreds), getItemCount(header))
	}

	// Verify export
	exportOpts := cxp.ExportOptions{}
	output, err := cxp.ExportToBytes(header, exportOpts)
	if err != nil {
		t.Fatalf("Failed to export combined CXF: %v", err)
	}

	// Verify valid JSON with all items
	var parsed gocxf.Header
	if err := json.Unmarshal(output, &parsed); err != nil {
		t.Fatalf("Export produced invalid JSON: %v", err)
	}

	parsedItemCount := 0
	for _, account := range parsed.Accounts {
		parsedItemCount += len(account.Items)
	}
	if parsedItemCount != len(allCreds) {
		t.Errorf("Parsed output has %d items, expected %d", parsedItemCount, len(allCreds))
	}
}

func TestEncryptedExport(t *testing.T) {
	csvPath := filepath.Join(getTestdataPath(), "chrome", "passwords.csv")
	if _, err := os.Stat(csvPath); os.IsNotExist(err) {
		t.Skip("testdata/chrome/passwords.csv not found")
	}

	// Generate keypair
	privateKey, publicKey, err := cxp.GenerateKeyPair()
	if err != nil {
		t.Fatalf("Failed to generate keypair: %v", err)
	}

	// Load credentials
	source := sources.NewChromeSource()
	if err := source.Open(csvPath, sources.OpenOptions{}); err != nil {
		t.Fatalf("Failed to open source: %v", err)
	}
	defer source.Close()

	creds, _ := source.Read()
	if len(creds) == 0 {
		t.Skip("No credentials to test")
	}

	// Generate CXF
	opts := cxf.DefaultOptions()
	header, err := cxf.Generate(creds, opts)
	if err != nil {
		t.Fatalf("Failed to generate CXF: %v", err)
	}

	// Export encrypted
	exportOpts := cxp.ExportOptions{
		Encrypt:         true,
		RecipientPubKey: publicKey,
	}

	encrypted, err := cxp.ExportToBytes(header, exportOpts)
	if err != nil {
		t.Fatalf("Failed to export encrypted: %v", err)
	}

	// Verify encrypted output is different from plaintext
	plainOpts := cxp.ExportOptions{}
	plaintext, _ := cxp.ExportToBytes(header, plainOpts)

	if bytes.Equal(encrypted, plaintext) {
		t.Error("Encrypted output should differ from plaintext")
	}

	// Verify it looks like a ZIP (CXP archive)
	if len(encrypted) < 4 || encrypted[0] != 'P' || encrypted[1] != 'K' {
		t.Error("Encrypted output should be a ZIP archive")
	}

	// Keep private key reference to avoid unused variable error
	_ = privateKey
}

func TestLargeExport(t *testing.T) {
	// Generate 1000+ synthetic credentials
	var creds []model.Credential
	for i := 0; i < 1100; i++ {
		cred := model.Credential{
			ID:       generateTestID(i),
			Type:     model.TypeBasicAuth,
			Title:    generateTestTitle(i),
			Username: generateTestUsername(i),
			Password: generateTestPassword(i),
			URL:      generateTestURL(i),
			Notes:    generateTestNotes(i),
		}
		creds = append(creds, cred)
	}

	// Generate CXF
	opts := cxf.DefaultOptions()
	header, err := cxf.Generate(creds, opts)
	if err != nil {
		t.Fatalf("Failed to generate large CXF: %v", err)
	}

	if getItemCount(header) != 1100 {
		t.Errorf("Expected 1100 items, got %d", getItemCount(header))
	}

	// Export and verify
	exportOpts := cxp.ExportOptions{}
	output, err := cxp.ExportToBytes(header, exportOpts)
	if err != nil {
		t.Fatalf("Failed to export large CXF: %v", err)
	}

	// Verify valid JSON
	var parsed gocxf.Header
	if err := json.Unmarshal(output, &parsed); err != nil {
		t.Fatalf("Large export produced invalid JSON: %v", err)
	}

	parsedItemCount := 0
	for _, account := range parsed.Accounts {
		parsedItemCount += len(account.Items)
	}
	if parsedItemCount != 1100 {
		t.Errorf("Parsed output has %d items, expected 1100", parsedItemCount)
	}
}

func TestCLIConvert(t *testing.T) {
	binaryPath := getBinaryPath()
	if _, err := os.Stat(binaryPath); os.IsNotExist(err) {
		t.Skip("Binary not built; run 'make build' first")
	}

	csvPath := filepath.Join(getTestdataPath(), "chrome", "passwords.csv")
	if _, err := os.Stat(csvPath); os.IsNotExist(err) {
		t.Skip("testdata/chrome/passwords.csv not found")
	}

	// Create temp output file
	tmpFile, err := os.CreateTemp("", "cxporter-test-*.cxf.json")
	if err != nil {
		t.Fatalf("Failed to create temp file: %v", err)
	}
	tmpFile.Close()
	defer os.Remove(tmpFile.Name())

	// Run CLI convert command
	cmd := exec.Command(binaryPath, "convert", csvPath, "-o", tmpFile.Name())
	var stderr bytes.Buffer
	cmd.Stderr = &stderr

	if err := cmd.Run(); err != nil {
		t.Fatalf("CLI convert failed: %v\nStderr: %s", err, stderr.String())
	}

	// Verify output file exists and contains valid JSON
	output, err := os.ReadFile(tmpFile.Name())
	if err != nil {
		t.Fatalf("Failed to read output file: %v", err)
	}

	if len(output) == 0 {
		t.Error("CLI produced empty output")
	}

	var parsed gocxf.Header
	if err := json.Unmarshal(output, &parsed); err != nil {
		t.Fatalf("CLI output is not valid JSON: %v", err)
	}

	itemCount := 0
	for _, account := range parsed.Accounts {
		itemCount += len(account.Items)
	}
	if itemCount == 0 {
		t.Error("CLI output has no items")
	}
}

func TestCLIPreview(t *testing.T) {
	binaryPath := getBinaryPath()
	if _, err := os.Stat(binaryPath); os.IsNotExist(err) {
		t.Skip("Binary not built; run 'make build' first")
	}

	csvPath := filepath.Join(getTestdataPath(), "chrome", "passwords.csv")
	if _, err := os.Stat(csvPath); os.IsNotExist(err) {
		t.Skip("testdata/chrome/passwords.csv not found")
	}

	// Run CLI preview command
	cmd := exec.Command(binaryPath, "preview", "-s", "chrome", csvPath)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	if err := cmd.Run(); err != nil {
		t.Fatalf("CLI preview failed: %v\nStderr: %s", err, stderr.String())
	}

	// Verify output contains expected information
	output := stdout.String()
	if !strings.Contains(output, "chrome") {
		t.Error("Preview output should mention 'chrome' source")
	}
	if !strings.Contains(output, "Credentials:") {
		t.Error("Preview output should show credential count")
	}
}

func TestCLIVersion(t *testing.T) {
	binaryPath := getBinaryPath()
	if _, err := os.Stat(binaryPath); os.IsNotExist(err) {
		t.Skip("Binary not built; run 'make build' first")
	}

	cmd := exec.Command(binaryPath, "version")
	var stdout bytes.Buffer
	cmd.Stdout = &stdout

	if err := cmd.Run(); err != nil {
		t.Fatalf("CLI version failed: %v", err)
	}

	output := stdout.String()
	if !strings.Contains(output, "cxporter") {
		t.Error("Version output should contain 'cxporter'")
	}
}

func TestCLISources(t *testing.T) {
	t.Skip("sources command has been removed - sources are listed in help text")
}

func TestAutoDetection(t *testing.T) {
	registry := sources.DefaultRegistry()

	tests := []struct {
		name       string
		path       string
		wantSource string
	}{
		{"Chrome CSV", filepath.Join(getTestdataPath(), "chrome", "passwords.csv"), "chrome"},
		{"Firefox CSV", filepath.Join(getTestdataPath(), "firefox", "logins.csv"), "firefox"},
		{"Bitwarden JSON", filepath.Join(getTestdataPath(), "bitwarden", "export.json"), "bitwarden"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := os.Stat(tt.path); os.IsNotExist(err) {
				t.Skipf("%s not found", tt.path)
			}

			detected, err := registry.DetectSource(tt.path)
			if err != nil {
				t.Fatalf("Detection failed: %v", err)
			}

			if detected.Name() != tt.wantSource {
				t.Errorf("Detected %s, want %s", detected.Name(), tt.wantSource)
			}
		})
	}
}

// Helper functions for generating test data

func generateTestID(i int) string {
	return strings.ReplaceAll(strings.ReplaceAll(
		"xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx",
		"x", string(rune('a'+i%26))),
		"y", string(rune('8'+i%4)))
}

func generateTestTitle(i int) string {
	sites := []string{"Gmail", "GitHub", "AWS", "Slack", "Jira", "Confluence", "Office365", "Dropbox"}
	return sites[i%len(sites)] + "-" + string(rune('A'+i/len(sites)%26))
}

func generateTestUsername(i int) string {
	return "user" + string(rune('a'+i%26)) + "@example.com"
}

func generateTestPassword(i int) string {
	return "P@ssw0rd" + string(rune('0'+i%10)) + string(rune('A'+i%26))
}

func generateTestURL(i int) string {
	domains := []string{"gmail.com", "github.com", "aws.amazon.com", "slack.com", "atlassian.net"}
	return "https://" + domains[i%len(domains)]
}

func generateTestNotes(i int) string {
	if i%5 == 0 {
		return "This is a test note for credential #" + string(rune('0'+i%10))
	}
	return ""
}
