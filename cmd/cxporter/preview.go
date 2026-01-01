package main

import (
	"fmt"
	"os"
	"sort"
	"strings"

	"github.com/spf13/cobra"

	"github.com/nvinuesa/cxporter/internal/model"
	"github.com/nvinuesa/cxporter/internal/sources"
)

var previewFlags struct {
	source   string
	password string
	keyFile  string
	filter   string
}

var previewCmd = &cobra.Command{
	Use:   "preview [input-file]",
	Short: "Preview credentials without conversion",
	Long: `Preview credentials from a source without writing any output.

The preview command shows a summary of what would be converted, including
credential counts by type and the folder hierarchy.

Examples:
  # Preview a KeePass database
  cxporter preview --source keepass vault.kdbx

  # Preview Chrome passwords
  cxporter preview --source chrome passwords.csv

  # Preview with filter
  cxporter preview vault.kdbx --filter work`,
	Args: cobra.MaximumNArgs(1),
	RunE: runPreview,
}

func init() {
	previewCmd.Flags().StringVarP(&previewFlags.source, "source", "s", "", "source type (keepass|chrome|firefox|bitwarden|ssh)")
	previewCmd.Flags().StringVarP(&previewFlags.password, "password", "p", "", "password for encrypted sources")
	previewCmd.Flags().StringVarP(&previewFlags.keyFile, "key-file", "k", "", "key file path (for KeePass)")
	previewCmd.Flags().StringVarP(&previewFlags.filter, "filter", "f", "", "filter by tag, folder, or title substring")
}

func runPreview(cmd *cobra.Command, args []string) error {
	// Show help if no args provided
	if len(args) == 0 {
		cmd.Help()
		return nil
	}

	inputPath := args[0]

	// Validate input exists
	if err := validatePreviewInput(inputPath); err != nil {
		return err
	}

	// Get or detect source
	source, err := getPreviewSourceAdapter(previewFlags.source, inputPath)
	if err != nil {
		return err
	}

	// Open source with authentication
	if err := openPreviewSource(source, inputPath); err != nil {
		return err
	}
	defer source.Close()

	// Read credentials
	creds, warnings, err := readPreviewCredentials(source)
	if err != nil {
		return err
	}

	// Apply filter if specified
	if previewFlags.filter != "" {
		originalCount := len(creds)
		creds = filterPreviewCredentials(creds, previewFlags.filter)
		if originalCount != len(creds) {
			fmt.Printf("Filtered: %d of %d credentials matched\n\n", len(creds), originalCount)
		}
	}

	// Print preview to stdout
	printPreview(source.Name(), inputPath, creds, warnings)

	return nil
}

// validatePreviewInput checks if the input path exists.
func validatePreviewInput(inputPath string) error {
	if inputPath == "" {
		return fmt.Errorf("input path is required")
	}

	if _, err := os.Stat(inputPath); os.IsNotExist(err) {
		return fmt.Errorf("input path does not exist: %s", inputPath)
	}

	return nil
}

// getPreviewSourceAdapter retrieves the source adapter by name or auto-detects it.
func getPreviewSourceAdapter(sourceName, inputPath string) (sources.Source, error) {
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

	fmt.Fprintf(os.Stderr, "Auto-detected source: %s\n", detected.Name())
	return detected, nil
}

// openPreviewSource opens the source adapter with authentication if needed.
func openPreviewSource(source sources.Source, inputPath string) error {
	opts := sources.OpenOptions{}

	if needsPassword(source.Name()) {
		password := previewFlags.password
		if password == "" {
			var err error
			password, err = promptPassword(fmt.Sprintf("Enter password for %s: ", inputPath))
			if err != nil {
				return fmt.Errorf("failed to read password: %w", err)
			}
		}
		opts.Password = password
		opts.KeyFilePath = previewFlags.keyFile
	}

	if err := source.Open(inputPath, opts); err != nil {
		return fmt.Errorf("failed to open source: %w", err)
	}

	return nil
}

// readPreviewCredentials reads credentials from the source and collects warnings.
func readPreviewCredentials(source sources.Source) ([]model.Credential, []string, error) {
	creds, err := source.Read()
	var warnings []string

	if err != nil {
		if sources.IsPartialRead(err) {
			warnings = append(warnings, err.Error())
		} else {
			return nil, nil, fmt.Errorf("failed to read credentials: %w", err)
		}
	}

	return creds, warnings, nil
}

// filterPreviewCredentials filters credentials by tag, folder, or title.
func filterPreviewCredentials(creds []model.Credential, filter string) []model.Credential {
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

// printPreview outputs the credential preview to stdout.
func printPreview(sourceName, inputPath string, creds []model.Credential, warnings []string) {
	fmt.Printf("Source: %s (%s)\n", sourceName, inputPath)
	fmt.Printf("Credentials: %d total\n", len(creds))

	// Count by type
	typeCounts := make(map[string]int)
	for _, cred := range creds {
		typeCounts[cred.Type.String()]++
	}

	// Sort types for consistent output
	typeNames := make([]string, 0, len(typeCounts))
	for t := range typeCounts {
		typeNames = append(typeNames, t)
	}
	sort.Strings(typeNames)

	for _, typeName := range typeNames {
		count := typeCounts[typeName]
		fmt.Printf("  - %d %s\n", count, typeName)
	}

	// Build and print folder tree
	folders := buildFolderTree(creds)
	if len(folders) > 0 {
		fmt.Println("\nCollections:")
		printFolderTree(folders, "  ")
	}

	// Print warnings
	if len(warnings) > 0 {
		fmt.Println("\nWarnings:")
		for _, w := range warnings {
			fmt.Printf("  - %s\n", w)
		}
	}

}

// folderNode represents a node in the folder hierarchy tree.
type folderNode struct {
	name     string
	count    int
	children map[string]*folderNode
}

// buildFolderTree constructs a hierarchical tree of folders from credentials.
func buildFolderTree(creds []model.Credential) map[string]*folderNode {
	root := make(map[string]*folderNode)

	for _, cred := range creds {
		if cred.FolderPath == "" {
			continue
		}

		parts := strings.Split(strings.Trim(cred.FolderPath, "/"), "/")
		current := root

		for _, part := range parts {
			part = strings.TrimSpace(part)
			if part == "" {
				continue
			}

			if _, ok := current[part]; !ok {
				current[part] = &folderNode{
					name:     part,
					children: make(map[string]*folderNode),
				}
			}
			current[part].count++
			current = current[part].children
		}
	}

	return root
}

// printFolderTree recursively prints the folder tree with indentation.
func printFolderTree(nodes map[string]*folderNode, indent string) {
	// Sort folder names for consistent output
	names := make([]string, 0, len(nodes))
	for name := range nodes {
		names = append(names, name)
	}
	sort.Strings(names)

	for _, name := range names {
		node := nodes[name]
		fmt.Printf("%s- %s (%d items)\n", indent, node.name, node.count)
		if len(node.children) > 0 {
			printFolderTree(node.children, indent+"  ")
		}
	}
}
