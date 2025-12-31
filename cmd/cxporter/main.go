// Package main provides the entry point for the cxporter CLI tool.
package main

import (
	"fmt"
	"os"
)

// Version information set at build time.
var (
	Version   = "0.1.0-dev"
	GitCommit = "unknown"
	BuildDate = "unknown"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
}

func run() error {
	fmt.Printf("cxporter %s\n", Version)
	return nil
}
