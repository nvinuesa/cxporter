// Package main provides the entry point for the cxporter CLI tool.
package main

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
)

// Version information set at build time.
var (
	Version   = "0.1.0-edge"
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

By default, output is written to stdout. Use --output to write to a file.

Examples:
  # Convert to stdout
  cxporter convert --source keepass vault.kdbx > credentials.cxf

  # Convert to file
  cxporter convert --source keepass vault.kdbx --output credentials.cxf

  # Preview without conversion
  cxporter preview --source chrome passwords.csv`,
	SilenceUsage:  true,
	SilenceErrors: true,
}

func init() {
	// Disable completion command
	rootCmd.CompletionOptions.DisableDefaultCmd = true

	rootCmd.AddCommand(convertCmd)
	rootCmd.AddCommand(previewCmd)
	rootCmd.AddCommand(versionCmd)
}

func main() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, "Error:", err)
		os.Exit(1)
	}
}
