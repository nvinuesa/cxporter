package main

import (
	"encoding/base64"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/spf13/cobra"
	"golang.org/x/term"

	"github.com/nvinuesa/cxporter/internal/cxf"
	"github.com/nvinuesa/cxporter/internal/cxp"
	"github.com/nvinuesa/cxporter/internal/model"
	"github.com/nvinuesa/cxporter/internal/sources"
)

var convertFlags struct {
	source       string
	input        string
	output       string
	password     string
	keyFile      string
	encrypt      bool
	recipientKey string
	filter       string
	dryRun       bool
	verbose      bool
	quiet        bool
}

var convertCmd = &cobra.Command{
	Use:   "convert",
	Short: "Convert credentials to CXF format",
	Long: `Convert credentials from a source format to CXF.

The convert command reads credentials from a source (KeePass, Chrome, Firefox,
SSH keys, etc.) and outputs them in the FIDO Alliance Credential Exchange
Format (CXF).

Examples:
  # Convert KeePass database to CXF
  cxporter convert -s keepass -i vault.kdbx -o credentials.cxf

  # Convert with password from command line
  cxporter convert -s keepass -i vault.kdbx -p "mypassword" -o out.cxf

  # Auto-detect source type
  cxporter convert -i passwords.csv -o credentials.cxf

  # Generate encrypted CXP archive
  cxporter convert -s chrome -i passwords.csv --encrypt --recipient-key @pubkey.pem

  # Preview without writing output
  cxporter convert -s ssh -i ~/.ssh --dry-run`,
	RunE: runConvert,
}

func init() {
	convertCmd.Flags().StringVarP(&convertFlags.source, "source", "s", "", "Source type (keepass|chrome|firefox|bitwarden|ssh)")
	convertCmd.Flags().StringVarP(&convertFlags.input, "input", "i", "", "Input file or directory path (required)")
	convertCmd.Flags().StringVarP(&convertFlags.output, "output", "o", "", "Output file path (default: stdout or input_name.cxf)")
	convertCmd.Flags().StringVarP(&convertFlags.password, "password", "p", "", "Password for encrypted sources")
	convertCmd.Flags().StringVarP(&convertFlags.keyFile, "key-file", "k", "", "Key file path (for KeePass)")
	convertCmd.Flags().BoolVarP(&convertFlags.encrypt, "encrypt", "e", false, "Generate HPKE-encrypted output")
	convertCmd.Flags().StringVar(&convertFlags.recipientKey, "recipient-key", "", "Recipient public key (base64 or @filepath)")
	convertCmd.Flags().StringVarP(&convertFlags.filter, "filter", "f", "", "Filter by tag, folder, or glob pattern")
	convertCmd.Flags().BoolVar(&convertFlags.dryRun, "dry-run", false, "Preview only, no output file")
	convertCmd.Flags().BoolVarP(&convertFlags.verbose, "verbose", "v", false, "Verbose output")
	convertCmd.Flags().BoolVarP(&convertFlags.quiet, "quiet", "q", false, "Suppress all output except errors")

	convertCmd.MarkFlagRequired("input")
}

func runConvert(cmd *cobra.Command, args []string) error {
	// Validate input
	if convertFlags.input == "" {
		return fmt.Errorf("input path is required")
	}

	// Check input exists
	if _, err := os.Stat(convertFlags.input); os.IsNotExist(err) {
		return fmt.Errorf("input path does not exist: %s", convertFlags.input)
	}

	// Get or detect source
	var source sources.Source
	registry := sources.DefaultRegistry()

	if convertFlags.source != "" {
		var ok bool
		source, ok = registry.Get(convertFlags.source)
		if !ok {
			return fmt.Errorf("unknown source type: %s", convertFlags.source)
		}
	} else {
		// Auto-detect source
		detected, err := registry.DetectSource(convertFlags.input)
		if err != nil || detected == nil {
			return fmt.Errorf("could not auto-detect source type for: %s", convertFlags.input)
		}
		source = detected
		if !convertFlags.quiet {
			fmt.Fprintf(os.Stderr, "Auto-detected source: %s\n", source.Name())
		}
	}

	// Check if source needs password
	opts := sources.OpenOptions{}
	if needsPassword(source.Name()) {
		password := convertFlags.password
		if password == "" && !convertFlags.quiet {
			var err error
			password, err = promptPassword(fmt.Sprintf("Enter password for %s: ", convertFlags.input))
			if err != nil {
				return fmt.Errorf("failed to read password: %w", err)
			}
		}
		opts.Password = password
		opts.KeyFilePath = convertFlags.keyFile
	}

	// Open source
	if err := source.Open(convertFlags.input, opts); err != nil {
		return fmt.Errorf("failed to open source: %w", err)
	}
	defer source.Close()

	// Read credentials
	if convertFlags.verbose && !convertFlags.quiet {
		fmt.Fprintf(os.Stderr, "Reading credentials from %s...\n", convertFlags.input)
	}

	creds, err := source.Read()
	if err != nil {
		// Check for partial read
		if sources.IsPartialRead(err) {
			if !convertFlags.quiet {
				fmt.Fprintf(os.Stderr, "Warning: %v\n", err)
			}
		} else {
			return fmt.Errorf("failed to read credentials: %w", err)
		}
	}

	if len(creds) == 0 {
		if !convertFlags.quiet {
			fmt.Fprintln(os.Stderr, "No credentials found")
		}
		return nil
	}

	// Apply filter if specified
	if convertFlags.filter != "" {
		creds = filterCredentials(creds, convertFlags.filter)
		if len(creds) == 0 {
			if !convertFlags.quiet {
				fmt.Fprintln(os.Stderr, "No credentials matched filter")
			}
			return nil
		}
	}

	// Generate CXF
	genOpts := cxf.DefaultOptions()
	genOpts.PreserveHierarchy = true

	header, err := cxf.Generate(creds, genOpts)
	if err != nil {
		return fmt.Errorf("failed to generate CXF: %w", err)
	}

	// Print summary
	if !convertFlags.quiet {
		printConversionSummary(creds, source.Name())
	}

	// Handle dry-run
	if convertFlags.dryRun {
		if !convertFlags.quiet {
			fmt.Fprintln(os.Stderr, "\n[Dry run - no output written]")
		}
		return nil
	}

	// Prepare output
	outputPath := convertFlags.output
	if outputPath == "" {
		// Generate output filename
		base := filepath.Base(convertFlags.input)
		ext := filepath.Ext(base)
		name := strings.TrimSuffix(base, ext)
		if convertFlags.encrypt {
			outputPath = name + ".cxp"
		} else {
			outputPath = name + ".cxf.json"
		}
	}

	// Export
	exportOpts := cxp.ExportOptions{
		OutputPath: outputPath,
		Encrypt:    convertFlags.encrypt,
	}

	if convertFlags.encrypt {
		pubKey, err := loadRecipientKey(convertFlags.recipientKey)
		if err != nil {
			return fmt.Errorf("failed to load recipient key: %w", err)
		}
		exportOpts.RecipientPubKey = pubKey
	}

	if err := cxp.Export(header, exportOpts); err != nil {
		return fmt.Errorf("failed to write output: %w", err)
	}

	if !convertFlags.quiet {
		fmt.Fprintf(os.Stderr, "\nOutput written to: %s\n", outputPath)
	}

	return nil
}

func needsPassword(sourceName string) bool {
	return sourceName == "keepass"
}

func promptPassword(prompt string) (string, error) {
	fmt.Fprint(os.Stderr, prompt)
	password, err := term.ReadPassword(int(os.Stdin.Fd()))
	fmt.Fprintln(os.Stderr) // newline after password
	return string(password), err
}

func loadRecipientKey(keySpec string) ([]byte, error) {
	if keySpec == "" {
		return nil, fmt.Errorf("recipient key is required for encryption")
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

func filterCredentials(creds []model.Credential, filter string) []model.Credential {
	var filtered []model.Credential
	filterLower := strings.ToLower(filter)

	for _, cred := range creds {
		matched := false
		// Match by tag
		for _, tag := range cred.Tags {
			if strings.ToLower(tag) == filterLower {
				matched = true
				break
			}
		}
		if matched {
			filtered = append(filtered, cred)
			continue
		}
		// Match by folder
		if strings.Contains(strings.ToLower(cred.FolderPath), filterLower) {
			filtered = append(filtered, cred)
			continue
		}
		// Match by title
		if strings.Contains(strings.ToLower(cred.Title), filterLower) {
			filtered = append(filtered, cred)
		}
	}

	return filtered
}

func printConversionSummary(creds []model.Credential, sourceName string) {
	// Count by type
	typeCounts := make(map[string]int)
	for _, cred := range creds {
		typeCounts[cred.Type.String()]++
	}

	fmt.Fprintf(os.Stderr, "\nSource: %s (%s)\n", sourceName, convertFlags.input)
	fmt.Fprintf(os.Stderr, "Credentials: %d total\n", len(creds))

	for typeName, count := range typeCounts {
		fmt.Fprintf(os.Stderr, "  - %d %s\n", count, typeName)
	}
}
