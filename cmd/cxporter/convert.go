package main

import (
	"encoding/base64"
	"fmt"
	"os"
	"strings"

	"github.com/spf13/cobra"
	"golang.org/x/term"

	gocxf "github.com/nvinuesa/go-cxf"

	"github.com/nvinuesa/cxporter/internal/cxf"
	"github.com/nvinuesa/cxporter/internal/cxp"
	"github.com/nvinuesa/cxporter/internal/model"
	"github.com/nvinuesa/cxporter/internal/sources"
)

var convertFlags struct {
	source       string
	output       string
	password     string
	keyFile      string
	encrypt      bool
	recipientKey string
	filter       string
}

var convertCmd = &cobra.Command{
	Use:   "convert [input-file]",
	Short: "Convert credentials to CXF format",
	Long: `Convert credentials from a source format to CXF.

The convert command reads credentials from a source (KeePass, Chrome, Firefox,
SSH keys, etc.) and outputs them in the FIDO Alliance Credential Exchange
Format (CXF).

By default, output is written to stdout. Use --output to write to a file.

Examples:
  # Convert KeePass database to CXF (stdout)
  cxporter convert --source keepass vault.kdbx > credentials.cxf

  # Convert with output file
  cxporter convert --source keepass vault.kdbx --output credentials.cxf

  # Auto-detect source type
  cxporter convert passwords.csv --output credentials.cxf

  # Generate encrypted CXP archive (stdout)
  cxporter convert --source chrome passwords.csv --encrypt --recipient-key @pubkey.pem > out.cxp

  # Pipe to another tool
  cxporter convert --source ssh ~/.ssh | jq .accounts[0]`,
	Args: cobra.MaximumNArgs(1),
	RunE: runConvert,
}

func init() {
	convertCmd.Flags().StringVarP(&convertFlags.source, "source", "s", "", "source type (keepass|chrome|firefox|bitwarden|ssh)")
	convertCmd.Flags().StringVarP(&convertFlags.output, "output", "o", "", "output file path (default: stdout)")
	convertCmd.Flags().StringVarP(&convertFlags.password, "password", "p", "", "password for encrypted sources")
	convertCmd.Flags().StringVarP(&convertFlags.keyFile, "key-file", "k", "", "key file path (for KeePass)")
	convertCmd.Flags().BoolVarP(&convertFlags.encrypt, "encrypt", "e", false, "generate HPKE-encrypted CXP output")
	convertCmd.Flags().StringVar(&convertFlags.recipientKey, "recipient-key", "", "recipient public key (base64 or @filepath)")
	convertCmd.Flags().StringVarP(&convertFlags.filter, "filter", "f", "", "filter by tag, folder, or title substring")
}

func runConvert(cmd *cobra.Command, args []string) error {
	// Show help if no args provided
	if len(args) == 0 {
		cmd.Help()
		return nil
	}

	inputPath := args[0]

	// Validate input file exists
	if err := validateInput(inputPath); err != nil {
		return err
	}

	// Detect or get source adapter
	source, err := getSourceAdapter(convertFlags.source, inputPath)
	if err != nil {
		return err
	}

	// Open source with appropriate credentials
	if err := openSourceWithAuth(source, inputPath); err != nil {
		return err
	}
	defer source.Close()

	// Read and filter credentials
	creds, err := readAndFilterCredentials(source)
	if err != nil {
		return err
	}

	if len(creds) == 0 {
		return nil
	}

	// Generate CXF format
	header, err := generateCXF(creds)
	if err != nil {
		return err
	}

	// Write output (stdout or file)
	if err := writeOutput(header); err != nil {
		return err
	}

	return nil
}

// validateInput checks if the input path exists.
func validateInput(inputPath string) error {
	if inputPath == "" {
		return fmt.Errorf("input path is required")
	}

	if _, err := os.Stat(inputPath); os.IsNotExist(err) {
		return fmt.Errorf("input path does not exist: %s", inputPath)
	}

	return nil
}

// getSourceAdapter retrieves the source adapter by name or auto-detects it.
func getSourceAdapter(sourceName, inputPath string) (sources.Source, error) {
	registry := sources.DefaultRegistry()

	if sourceName != "" {
		source, ok := registry.Get(sourceName)
		if !ok {
			return nil, fmt.Errorf("unknown source type: %s (try: keepass, chrome, firefox, bitwarden, ssh)", sourceName)
		}
		return source, nil
	}

	// Auto-detect source
	detected, err := registry.DetectSource(inputPath)
	if err != nil || detected == nil {
		return nil, fmt.Errorf("could not auto-detect source type for: %s (use --source to specify)", inputPath)
	}

	return detected, nil
}

// openSourceWithAuth opens the source adapter with authentication if needed.
func openSourceWithAuth(source sources.Source, inputPath string) error {
	opts := sources.OpenOptions{}

	// Check if source needs password
	if needsPassword(source.Name()) {
		password := convertFlags.password
		if password == "" {
			var err error
			password, err = promptPassword(fmt.Sprintf("Enter password for %s: ", inputPath))
			if err != nil {
				return fmt.Errorf("failed to read password: %w", err)
			}
		}
		opts.Password = password
		opts.KeyFilePath = convertFlags.keyFile
	}

	if err := source.Open(inputPath, opts); err != nil {
		return fmt.Errorf("failed to open source: %w", err)
	}

	return nil
}

// readAndFilterCredentials reads credentials from source and applies filters.
func readAndFilterCredentials(source sources.Source) ([]model.Credential, error) {
	creds, err := source.Read()
	if err != nil {
		// Check for partial read errors
		if !sources.IsPartialRead(err) {
			return nil, fmt.Errorf("failed to read credentials: %w", err)
		}
	}

	// Apply filter if specified
	if convertFlags.filter != "" {
		creds = filterCredentials(creds, convertFlags.filter)
	}

	return creds, nil
}

// generateCXF generates CXF format from credentials.
func generateCXF(creds []model.Credential) (*gocxf.Header, error) {
	opts := cxf.DefaultOptions()
	opts.PreserveHierarchy = true

	header, err := cxf.Generate(creds, opts)
	if err != nil {
		return nil, fmt.Errorf("failed to generate CXF: %w", err)
	}

	return header, nil
}

// writeOutput writes the CXF header to stdout or a file.
func writeOutput(header *gocxf.Header) error {
	exportOpts := cxp.ExportOptions{
		Encrypt: convertFlags.encrypt,
	}

	if convertFlags.encrypt {
		pubKey, err := loadRecipientKey(convertFlags.recipientKey)
		if err != nil {
			return fmt.Errorf("failed to load recipient key: %w", err)
		}
		exportOpts.RecipientPubKey = pubKey
	}

	// Generate bytes (encrypted or unencrypted)
	data, err := cxp.ExportToBytes(header, exportOpts)
	if err != nil {
		return fmt.Errorf("failed to generate output: %w", err)
	}

	// Write to stdout or file
	if convertFlags.output == "" {
		// Write to stdout
		if _, err := os.Stdout.Write(data); err != nil {
			return fmt.Errorf("failed to write to stdout: %w", err)
		}
	} else {
		// Write to file
		if err := os.WriteFile(convertFlags.output, data, 0600); err != nil {
			return fmt.Errorf("failed to write to file: %w", err)
		}
	}

	return nil
}

// needsPassword returns true if the source requires a password.
func needsPassword(sourceName string) bool {
	return sourceName == "keepass"
}

// promptPassword prompts the user for a password securely.
func promptPassword(prompt string) (string, error) {
	fmt.Fprint(os.Stderr, prompt)
	password, err := term.ReadPassword(int(os.Stdin.Fd()))
	fmt.Fprintln(os.Stderr) // newline after password
	if err != nil {
		return "", err
	}
	return string(password), nil
}

// loadRecipientKey loads a recipient public key from base64 or file.
func loadRecipientKey(keySpec string) ([]byte, error) {
	if keySpec == "" {
		return nil, fmt.Errorf("recipient key is required for encryption (use --recipient-key)")
	}

	var keyData string
	if strings.HasPrefix(keySpec, "@") {
		// Load from file
		data, err := os.ReadFile(keySpec[1:])
		if err != nil {
			return nil, fmt.Errorf("failed to read key file: %w", err)
		}
		keyData = strings.TrimSpace(string(data))
	} else {
		keyData = keySpec
	}

	// Decode base64
	decoded, err := base64.StdEncoding.DecodeString(keyData)
	if err != nil {
		// Try RawURLEncoding
		decoded, err = base64.RawURLEncoding.DecodeString(keyData)
		if err != nil {
			return nil, fmt.Errorf("invalid base64 key encoding")
		}
	}

	return decoded, nil
}

// filterCredentials filters credentials by tag, folder, or title.
func filterCredentials(creds []model.Credential, filter string) []model.Credential {
	var filtered []model.Credential
	filterLower := strings.ToLower(filter)

	for _, cred := range creds {
		// Match by tag
		for _, tag := range cred.Tags {
			if strings.Contains(strings.ToLower(tag), filterLower) {
				filtered = append(filtered, cred)
				goto nextCred
			}
		}

		// Match by folder
		if strings.Contains(strings.ToLower(cred.FolderPath), filterLower) {
			filtered = append(filtered, cred)
			continue
		}

		// Match by title
		if strings.Contains(strings.ToLower(cred.Title), filterLower) {
			filtered = append(filtered, cred)
			continue
		}

	nextCred:
	}

	return filtered
}
