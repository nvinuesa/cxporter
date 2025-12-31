// Package main provides the entry point for the cxporter CLI tool.
package main

import (
	"os"

	"github.com/spf13/cobra"
)

// Version information set at build time.
var (
	Version   = "0.1.0-dev"
	GitCommit = "unknown"
	BuildDate = "unknown"
)

var rootCmd = &cobra.Command{
	Use:   "cxporter",
	Short: "Convert credentials to CXF format",
	Long: `cxporter converts credentials from legacy password managers
(KeePass, Chrome, Firefox, etc.) to the FIDO Alliance CXF format.

The Credential Exchange Format (CXF) is an open standard for securely
exchanging credentials between password managers and other applications.

Examples:
  # Convert a KeePass database to CXF
  cxporter convert -s keepass -i vault.kdbx -o credentials.cxf

  # Preview Chrome passwords without conversion
  cxporter preview -s chrome -i passwords.csv

  # Export SSH keys as encrypted CXP archive
  cxporter convert -s ssh -i ~/.ssh -o ssh-keys.cxp --encrypt

  # List available source adapters
  cxporter sources`,
	SilenceUsage:  true,
	SilenceErrors: true,
}

func init() {
	rootCmd.AddCommand(convertCmd)
	rootCmd.AddCommand(previewCmd)
	rootCmd.AddCommand(sourcesCmd)
	rootCmd.AddCommand(versionCmd)
}

func main() {
	if err := rootCmd.Execute(); err != nil {
		os.Exit(1)
	}
}
