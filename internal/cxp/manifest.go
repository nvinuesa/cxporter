// Package cxp provides manifest generation for CXP archives.
package cxp

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"time"

	"github.com/nvinuesa/go-cxf"
)

// ManifestVersion is the current manifest format version.
const ManifestVersion = "1.0"

// Manifest contains metadata and integrity information for a CXP archive.
type Manifest struct {
	// Version of the manifest format
	Version string `json:"version"`
	
	// Created timestamp (ISO 8601)
	Created string `json:"created"`
	
	// ItemCount is the total number of items in the archive
	ItemCount int `json:"itemCount"`
	
	// Hashes contains SHA-256 hashes of archive files for integrity verification
	Hashes map[string]string `json:"hashes"`
	
	// ExporterInfo contains information about the exporter
	ExporterInfo ExporterInfo `json:"exporterInfo"`
}

// ExporterInfo contains metadata about the exporting application.
type ExporterInfo struct {
	// RpId is the relying party identifier of the exporter
	RpId string `json:"rpId"`
	
	// DisplayName is the human-readable name of the exporter
	DisplayName string `json:"displayName"`
	
	// Version is the version of the exporter application
	Version string `json:"version,omitempty"`
}

// BuildManifest creates a manifest from a CXF header and archive contents.
func BuildManifest(header *cxf.Header, archiveContents map[string][]byte) (*Manifest, error) {
	if header == nil {
		return nil, fmt.Errorf("header is nil")
	}

	// Count total items
	itemCount := 0
	for _, account := range header.Accounts {
		itemCount += len(account.Items)
	}

	// Build hash map
	hashes := make(map[string]string)
	for path, data := range archiveContents {
		hash := sha256.Sum256(data)
		hashes[path] = "sha256:" + hex.EncodeToString(hash[:])
	}

	manifest := &Manifest{
		Version:   ManifestVersion,
		Created:   time.Now().UTC().Format(time.RFC3339),
		ItemCount: itemCount,
		Hashes:    hashes,
		ExporterInfo: ExporterInfo{
			RpId:        header.ExporterRpId,
			DisplayName: header.ExporterDisplayName,
		},
	}

	return manifest, nil
}

// MarshalJSON returns the JSON encoding of the manifest.
func (m *Manifest) MarshalJSON() ([]byte, error) {
	return json.MarshalIndent(m, "", "  ")
}

// ValidateManifest validates a manifest structure.
func ValidateManifest(m *Manifest) error {
	if m == nil {
		return fmt.Errorf("manifest is nil")
	}

	if m.Version == "" {
		return fmt.Errorf("manifest version is required")
	}

	if m.Created == "" {
		return fmt.Errorf("manifest created timestamp is required")
	}

	// Validate timestamp format
	if _, err := time.Parse(time.RFC3339, m.Created); err != nil {
		return fmt.Errorf("invalid created timestamp format: %w", err)
	}

	if m.ItemCount < 0 {
		return fmt.Errorf("item count cannot be negative")
	}

	if m.Hashes == nil || len(m.Hashes) == 0 {
		return fmt.Errorf("manifest must contain file hashes")
	}

	// Validate hash format
	for path, hash := range m.Hashes {
		if path == "" {
			return fmt.Errorf("hash entry has empty path")
		}
		if len(hash) < 8 || hash[:7] != "sha256:" {
			return fmt.Errorf("invalid hash format for %s: expected 'sha256:' prefix", path)
		}
	}

	if m.ExporterInfo.RpId == "" {
		return fmt.Errorf("exporter RP ID is required")
	}

	if m.ExporterInfo.DisplayName == "" {
		return fmt.Errorf("exporter display name is required")
	}

	return nil
}

// VerifyArchiveIntegrity verifies that archive contents match the manifest hashes.
func VerifyArchiveIntegrity(manifest *Manifest, archiveContents map[string][]byte) error {
	if err := ValidateManifest(manifest); err != nil {
		return fmt.Errorf("invalid manifest: %w", err)
	}

	// Check that all files in manifest exist in archive
	for path := range manifest.Hashes {
		if _, exists := archiveContents[path]; !exists {
			return fmt.Errorf("file in manifest not found in archive: %s", path)
		}
	}

	// Verify hashes
	for path, data := range archiveContents {
		expectedHash, exists := manifest.Hashes[path]
		if !exists {
			// File in archive not in manifest - this is a warning, not an error
			continue
		}

		actualHash := sha256.Sum256(data)
		actualHashStr := "sha256:" + hex.EncodeToString(actualHash[:])

		if actualHashStr != expectedHash {
			return fmt.Errorf("hash mismatch for %s: expected %s, got %s",
				path, expectedHash, actualHashStr)
		}
	}

	return nil
}
