// Package cxp provides validation utilities for CXP metadata.
package cxp

import (
	"fmt"
	"time"

	"github.com/nvinuesa/go-cxf"
	"github.com/nvinuesa/cxporter/internal/security"
)

// ValidateHeader validates a CXF header according to CXP requirements.
func ValidateHeader(header *cxf.Header) error {
	if header == nil {
		return fmt.Errorf("header is nil")
	}

	// Validate exporter RP ID
	if header.ExporterRpId == "" {
		return fmt.Errorf("exporter RP ID is required")
	}
	if err := security.ValidateRPID(header.ExporterRpId); err != nil {
		return fmt.Errorf("invalid exporter RP ID: %w", err)
	}

	// Validate exporter display name
	if header.ExporterDisplayName == "" {
		return fmt.Errorf("exporter display name is required")
	}
	if err := security.ValidateStringLength(header.ExporterDisplayName, 256, "exporter display name"); err != nil {
		return err
	}

	// Validate timestamp
	if header.Timestamp == 0 {
		return fmt.Errorf("timestamp is required")
	}
	// Timestamp should be Unix milliseconds, reasonable range check
	minTime := time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC).Unix() * 1000
	maxTime := time.Now().Add(24 * time.Hour).Unix() * 1000
	if int64(header.Timestamp) < minTime || int64(header.Timestamp) > maxTime {
		return fmt.Errorf("timestamp is out of reasonable range")
	}

	// Validate accounts
	if err := security.ValidateItemCount(len(header.Accounts)); err != nil {
		return fmt.Errorf("too many accounts: %w", err)
	}

	for i, account := range header.Accounts {
		if err := ValidateAccount(account); err != nil {
			return fmt.Errorf("account %d: %w", i, err)
		}
	}

	return nil
}

// ValidateAccount validates a CXF account.
func ValidateAccount(account cxf.Account) error {
	// Validate account ID
	if err := security.ValidateCredentialID(account.ID); err != nil {
		return fmt.Errorf("invalid account ID: %w", err)
	}

	// At least one of username or email should be present
	if account.Username == "" && account.Email == "" {
		return fmt.Errorf("account must have username or email")
	}

	// Validate collections
	if err := security.ValidateCollectionCount(len(account.Collections)); err != nil {
		return err
	}

	// Build collection ID map for reference validation
	collectionMap := make(map[string]bool)
	for i, coll := range account.Collections {
		if err := ValidateCollection(coll); err != nil {
			return fmt.Errorf("collection %d: %w", i, err)
		}
		if collectionMap[coll.ID] {
			return fmt.Errorf("duplicate collection ID: %s", coll.ID)
		}
		collectionMap[coll.ID] = true
	}

	// Validate items
	if err := security.ValidateItemCount(len(account.Items)); err != nil {
		return err
	}

	for i, item := range account.Items {
		if err := ValidateItem(item); err != nil {
			return fmt.Errorf("item %d: %w", i, err)
		}
	}

	return nil
}

// ValidateCollection validates a CXF collection.
func ValidateCollection(coll cxf.Collection) error {
	// Validate collection ID
	if err := security.ValidateCredentialID(coll.ID); err != nil {
		return fmt.Errorf("invalid collection ID: %w", err)
	}

	// Validate title
	if coll.Title == "" {
		return fmt.Errorf("collection title is required")
	}
	if err := security.ValidateStringLength(coll.Title, security.MaxTitleLength, "collection title"); err != nil {
		return err
	}

	return nil
}

// ValidateItem validates a CXF item.
func ValidateItem(item cxf.Item) error {
	// Validate item ID
	if err := security.ValidateCredentialID(item.ID); err != nil {
		return fmt.Errorf("invalid item ID: %w", err)
	}

	// Validate title
	if item.Title == "" {
		return fmt.Errorf("item title is required")
	}
	if err := security.ValidateStringLength(item.Title, security.MaxTitleLength, "item title"); err != nil {
		return err
	}

	// Validate scope if present
	if item.Scope != nil {
		if err := ValidateScope(item.Scope); err != nil {
			return fmt.Errorf("invalid scope: %w", err)
		}
	}

	// Validate tags
	if len(item.Tags) > security.MaxTagCount {
		return fmt.Errorf("too many tags: %d (max %d)", len(item.Tags), security.MaxTagCount)
	}
	for _, tag := range item.Tags {
		if err := security.ValidateStringLength(tag, security.MaxTagLength, "tag"); err != nil {
			return err
		}
	}

	return nil
}

// ValidateScope validates a credential scope per CXP specification.
func ValidateScope(scope *cxf.CredentialScope) error {
	if scope == nil {
		return nil
	}

	// Note: The actual fields in cxf.CredentialScope may differ
	// This is a placeholder for proper scope validation
	// when the actual CXF type structure is known
	
	return nil
}

// ValidateArchiveStructure validates the structure of a CXP archive.
func ValidateArchiveStructure(files []string) error {
	hasManifest := false
	hasIndex := false
	hasDocsDir := false

	for _, file := range files {
		switch file {
		case archiveManifestFile:
			hasManifest = true
		case archiveIndexFile:
			hasIndex = true
		case archiveDocsDir:
			hasDocsDir = true
		}
	}

	if !hasManifest {
		return fmt.Errorf("archive missing required manifest file")
	}
	if !hasIndex {
		return fmt.Errorf("archive missing required index file")
	}
	if !hasDocsDir {
		return fmt.Errorf("archive missing required documents directory")
	}

	return nil
}
