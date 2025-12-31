// Package sources provides adapters for reading credentials from various formats.
package sources

import (
	"github.com/nvinuesa/cxporter/internal/model"
)

// Source defines the interface for credential source adapters.
// Each adapter reads credentials from a specific format (KeePass, Chrome CSV, etc.)
// and converts them to the internal model representation.
type Source interface {
	// Name returns the unique identifier for this source (e.g., "keepass", "chrome").
	Name() string

	// Description returns a human-readable description of the source.
	Description() string

	// SupportedExtensions returns file extensions this source handles (e.g., [".kdbx"]).
	// Return empty slice for directory-based sources.
	SupportedExtensions() []string

	// Detect checks if the given path is valid for this source.
	// Returns a confidence score from 0-100 (100 = definitely this format).
	// A score of 0 means this source cannot handle the path.
	Detect(path string) (confidence int, err error)

	// Open initializes the source with the given path and options.
	// This may prompt for credentials if Interactive is true and credentials are needed.
	Open(path string, opts OpenOptions) error

	// Read returns all credentials from the source.
	// May be called multiple times; should return the same results.
	// Returns ErrPartialRead if some credentials couldn't be read.
	Read() ([]model.Credential, error)

	// Close releases any resources held by the source.
	// Should clear sensitive data from memory where possible.
	Close() error
}

// OpenOptions provides configuration for opening a source.
type OpenOptions struct {
	// Password for encrypted sources (KeePass, encrypted exports).
	Password string

	// KeyFilePath for sources that support key files (KeePass).
	KeyFilePath string

	// Interactive indicates whether the source may prompt for missing credentials.
	// If true, PasswordFunc will be called when a password is needed.
	Interactive bool

	// PasswordFunc is a callback for interactive password entry.
	// It receives a prompt string and should return the password or an error.
	// Only used when Interactive is true.
	PasswordFunc func(prompt string) (string, error)

	// Recursive indicates whether to search directories recursively.
	// Only applicable to directory-based sources like SSH.
	Recursive bool

	// IncludeHidden indicates whether to include hidden files.
	// Only applicable to file-discovery sources.
	IncludeHidden bool
}

// PasswordPromptFunc is the signature for interactive password callbacks.
type PasswordPromptFunc func(prompt string) (string, error)
