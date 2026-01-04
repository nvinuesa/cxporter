package main

import (
	"encoding/base64"
	"encoding/json"
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
	source     string
	output     string
	keyFile    string
	encryptKey string
	filter     string
}

var convertCmd = &cobra.Command{
	Use:   "convert [input-file]",
	Short: "Convert credentials to CXF format",
	Long: `Convert credentials from a source format to CXF.

The convert command reads credentials from a source (KeePass, Chrome, Firefox,
SSH key, etc.) and outputs them in the FIDO Alliance Credential Exchange
Format (CXF).

By default, output is written to stdout. Use --output to write to a file.

To enable HPKE encryption (CXP format), provide an X25519 public key via
--encrypt-key. The key can be base64-encoded or loaded from a file using
the @filepath syntax.

Examples:
  # Convert KeePass database to CXF (stdout)
  cxporter convert --source keepass vault.kdbx > credentials.cxf

  # Convert with output file
  cxporter convert --source keepass vault.kdbx --output credentials.cxf

  # Auto-detect source type
  cxporter convert passwords.csv --output credentials.cxf

  # Generate encrypted CXP output (provide recipient's public key)
  cxporter convert --source chrome passwords.csv --encrypt-key @pubkey.pem -o out.cxp

  # Convert a single SSH key
  cxporter convert --source ssh ~/.ssh/id_ed25519 --output ssh-key.cxf`,
	Args: cobra.MaximumNArgs(1),
	RunE: runConvert,
}

func init() {
	convertCmd.Flags().StringVarP(&convertFlags.source, "source", "s", "", "source type (keepass|chrome|firefox|bitwarden|ssh)")
	convertCmd.Flags().StringVarP(&convertFlags.output, "output", "o", "", "output file path (default: stdout)")
	convertCmd.Flags().StringVarP(&convertFlags.keyFile, "key-file", "k", "", "key file path (for KeePass)")
	convertCmd.Flags().StringVarP(&convertFlags.encryptKey, "encrypt-key", "e", "", "X25519 public key for HPKE encryption (base64 or @filepath)")
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
// Passwords are only accepted via interactive prompt for security.
func openSourceWithAuth(source sources.Source, inputPath string) error {
	opts := sources.OpenOptions{}

	// Check if source needs password
	if needsPassword(source.Name()) {
		password, err := promptPassword(fmt.Sprintf("Enter password for %s: ", inputPath))
		if err != nil {
			return fmt.Errorf("failed to read password: %w", err)
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
	// Check for PCI-DSS compliance issues
	pciWarnings := cxf.CheckPCICompliance(creds)
	if len(pciWarnings) > 0 {
		fmt.Fprintln(os.Stderr, "\n[WARNING] PCI-DSS Compliance Issue Detected:")
		fmt.Fprintln(os.Stderr, "PCI-DSS 4.0.1 Section 3.3.1 prohibits storing CVV and PIN values.")
		fmt.Fprintln(os.Stderr, "The following credentials contain sensitive payment card data:")
		for _, w := range pciWarnings {
			fields := []string{}
			if w.HasCVV {
				fields = append(fields, "CVV")
			}
			if w.HasPIN {
				fields = append(fields, "PIN")
			}
			fmt.Fprintf(os.Stderr, "  - %s: contains %s\n", w.CredentialTitle, strings.Join(fields, ", "))
		}
		fmt.Fprintln(os.Stderr, "Consider removing these values before exporting.")
		fmt.Fprintln(os.Stderr, "")
	}

	opts := cxf.DefaultOptions()
	opts.PreserveHierarchy = true

	header, err := cxf.Generate(creds, opts)
	if err != nil {
		return nil, fmt.Errorf("failed to generate CXF: %w", err)
	}

	return header, nil
}

// writeOutput writes the CXF header to stdout or a file.
// For encrypted output, returns a proper CXP ExportResponse JSON object.
// For unencrypted output, returns raw CXF JSON.
func writeOutput(header *gocxf.Header) error {
	var data []byte
	var err error

	encrypt := convertFlags.encryptKey != ""

	if encrypt {
		// Encrypted: generate proper CXP ExportResponse object
		pubKey, err := loadEncryptKey(convertFlags.encryptKey)
		if err != nil {
			return fmt.Errorf("failed to load encryption key: %w", err)
		}

		response, err := cxp.ExportResponse(header, pubKey)
		if err != nil {
			return fmt.Errorf("failed to generate CXP response: %w", err)
		}

		// Serialize to JSON
		data, err = json.MarshalIndent(response, "", "  ")
		if err != nil {
			return fmt.Errorf("failed to serialize CXP response: %w", err)
		}
	} else {
		// Unencrypted: raw CXF JSON
		exportOpts := cxp.ExportOptions{
			Encrypt: false,
		}
		data, err = cxp.ExportToBytes(header, exportOpts)
		if err != nil {
			return fmt.Errorf("failed to generate output: %w", err)
		}
	}

	// Write to stdout or file
	if convertFlags.output == "" {
		// Warn about unencrypted output to stdout
		if !encrypt {
			fmt.Fprintln(os.Stderr, "[WARNING] Writing unencrypted credentials to stdout.")
			fmt.Fprintln(os.Stderr, "This data may be visible in terminal scrollback, logs, or piped to insecure destinations.")
			fmt.Fprintln(os.Stderr, "Consider using --encrypt-key for sensitive data or --output to write to a file.")
			fmt.Fprintln(os.Stderr, "")
		}
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

// loadEncryptKey loads a public key for encryption from base64 or file.
func loadEncryptKey(keySpec string) ([]byte, error) {
	if keySpec == "" {
		return nil, fmt.Errorf("encryption key is required (use --encrypt-key)")
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
