package main

import (
	"fmt"
	"sort"
	"strings"

	"github.com/spf13/cobra"

	"github.com/nvinuesa/cxporter/internal/sources"
)

var sourcesCmd = &cobra.Command{
	Use:   "sources",
	Short: "List available source adapters",
	Long: `List all available source adapters that can be used for credential import.

Each source adapter supports specific file formats and extensions. Use the
--source flag with the convert command to specify which adapter to use.

Examples:
  # List all sources
  cxporter sources`,
	Run: runSources,
}

func runSources(cmd *cobra.Command, args []string) {
	registry := sources.DefaultRegistry()
	sourceList := registry.List()

	// Sort by name
	sort.Slice(sourceList, func(i, j int) bool {
		return sourceList[i].Name() < sourceList[j].Name()
	})

	fmt.Println("Available source adapters:")
	fmt.Println()

	for _, source := range sourceList {
		exts := source.SupportedExtensions()
		extStr := strings.Join(exts, ", ")
		if extStr == "" {
			extStr = "(directory)"
		}

		fmt.Printf("  %-12s %s\n", source.Name(), source.Description())
		fmt.Printf("  %-12s Extensions: %s\n", "", extStr)
		fmt.Println()
	}

	fmt.Println("Use 'cxporter convert -s <source> -i <input>' to convert credentials.")
}
