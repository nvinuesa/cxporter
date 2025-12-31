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
	input    string
	password string
	keyFile  string
	filter   string
	verbose  bool
}

var previewCmd = &cobra.Command{
	Use:   "preview",
	Short: "Preview credentials without conversion",
	Long: `Preview credentials from a source without writing any output.

The preview command shows a summary of what would be converted, including
credential counts by type and the folder hierarchy.

Examples:
  # Preview a KeePass database
  cxporter preview -s keepass -i vault.kdbx

  # Preview Chrome passwords
  cxporter preview -s chrome -i passwords.csv

  # Preview with filter
  cxporter preview -i vault.kdbx -f "work"`,
	RunE: runPreview,
}

func init() {
	previewCmd.Flags().StringVarP(&previewFlags.source, "source", "s", "", "Source type (keepass|chrome|firefox|bitwarden|ssh)")
	previewCmd.Flags().StringVarP(&previewFlags.input, "input", "i", "", "Input file or directory path (required)")
	previewCmd.Flags().StringVarP(&previewFlags.password, "password", "p", "", "Password for encrypted sources")
	previewCmd.Flags().StringVarP(&previewFlags.keyFile, "key-file", "k", "", "Key file path (for KeePass)")
	previewCmd.Flags().StringVarP(&previewFlags.filter, "filter", "f", "", "Filter by tag, folder, or glob pattern")
	previewCmd.Flags().BoolVarP(&previewFlags.verbose, "verbose", "v", false, "Show detailed output")

	previewCmd.MarkFlagRequired("input")
}

func runPreview(cmd *cobra.Command, args []string) error {
	// Validate input
	if previewFlags.input == "" {
		return fmt.Errorf("input path is required")
	}

	// Check input exists
	if _, err := os.Stat(previewFlags.input); os.IsNotExist(err) {
		return fmt.Errorf("input path does not exist: %s", previewFlags.input)
	}

	// Get or detect source
	var source sources.Source
	registry := sources.DefaultRegistry()

	if previewFlags.source != "" {
		var ok bool
		source, ok = registry.Get(previewFlags.source)
		if !ok {
			return fmt.Errorf("unknown source type: %s", previewFlags.source)
		}
	} else {
		// Auto-detect source
		detected, err := registry.DetectSource(previewFlags.input)
		if err != nil || detected == nil {
			return fmt.Errorf("could not auto-detect source type for: %s", previewFlags.input)
		}
		source = detected
	}

	// Check if source needs password
	opts := sources.OpenOptions{}
	if needsPassword(source.Name()) {
		password := previewFlags.password
		if password == "" {
			var err error
			password, err = promptPassword(fmt.Sprintf("Enter password for %s: ", previewFlags.input))
			if err != nil {
				return fmt.Errorf("failed to read password: %w", err)
			}
		}
		opts.Password = password
		opts.KeyFilePath = previewFlags.keyFile
	}

	// Open source
	if err := source.Open(previewFlags.input, opts); err != nil {
		return fmt.Errorf("failed to open source: %w", err)
	}
	defer source.Close()

	// Read credentials
	creds, err := source.Read()
	var warnings []string
	if err != nil {
		if sources.IsPartialRead(err) {
			warnings = append(warnings, err.Error())
		} else {
			return fmt.Errorf("failed to read credentials: %w", err)
		}
	}

	// Apply filter if specified
	if previewFlags.filter != "" {
		originalCount := len(creds)
		creds = filterCredentials(creds, previewFlags.filter)
		if originalCount != len(creds) {
			fmt.Printf("Filtered: %d of %d credentials matched\n\n", len(creds), originalCount)
		}
	}

	// Print preview
	printPreview(source.Name(), previewFlags.input, creds, warnings)

	return nil
}

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

	// Print sample items in verbose mode
	if previewFlags.verbose && len(creds) > 0 {
		fmt.Println("\nSample items:")
		maxItems := 5
		if len(creds) < maxItems {
			maxItems = len(creds)
		}
		for i := 0; i < maxItems; i++ {
			cred := creds[i]
			fmt.Printf("  - %s (%s)", cred.Title, cred.Type.String())
			if cred.URL != "" {
				fmt.Printf(" - %s", cred.URL)
			}
			fmt.Println()
		}
		if len(creds) > 5 {
			fmt.Printf("  ... and %d more\n", len(creds)-5)
		}
	}
}

type folderNode struct {
	name     string
	count    int
	children map[string]*folderNode
}

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

func printFolderTree(nodes map[string]*folderNode, indent string) {
	// Sort folder names
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
