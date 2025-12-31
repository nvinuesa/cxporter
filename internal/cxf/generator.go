package cxf

import (
	"encoding/base64"
	"errors"
	"time"

	"github.com/google/uuid"
	"github.com/nvinuesa/go-cxf"

	"github.com/nvinuesa/cxporter/internal/model"
)

// Generator errors.
var (
	ErrNoCredentials   = errors.New("no credentials provided")
	ErrMissingRpID     = errors.New("exporter RP ID is required")
	ErrMissingExporter = errors.New("exporter name is required")
)

// GeneratorOptions configures CXF generation.
type GeneratorOptions struct {
	// ExporterRpID is the FIDO RP ID of the exporting application.
	ExporterRpID string
	// ExporterName is the human-readable display name for the exporter.
	ExporterName string
	// AccountID is the unique identifier for the account (auto-generated if empty).
	AccountID string
	// AccountUsername is the username for the account.
	AccountUsername string
	// AccountEmail is the email address for the account.
	AccountEmail string
	// AccountFullName is the full name of the account holder.
	AccountFullName string
	// PreserveHierarchy maps FolderPath to Collections when true.
	PreserveHierarchy bool
}

// DefaultOptions returns GeneratorOptions with sensible defaults.
func DefaultOptions() GeneratorOptions {
	return GeneratorOptions{
		ExporterRpID:      "cxporter.local",
		ExporterName:      "cxporter",
		PreserveHierarchy: true,
	}
}

// Generate creates a CXF Header from credentials.
func Generate(creds []model.Credential, opts GeneratorOptions) (*cxf.Header, error) {
	if len(creds) == 0 {
		return nil, ErrNoCredentials
	}

	if opts.ExporterRpID == "" {
		return nil, ErrMissingRpID
	}

	if opts.ExporterName == "" {
		return nil, ErrMissingExporter
	}

	// Generate account ID if not provided
	accountID := opts.AccountID
	if accountID == "" {
		accountID = generateBase64URLID()
	}

	// Build items from credentials
	items, err := mapCredentialsToItems(creds)
	if err != nil {
		return nil, err
	}

	// Build collections from folder paths if hierarchy preservation is enabled
	var collections []cxf.Collection
	if opts.PreserveHierarchy {
		collections = BuildCollections(creds)
	}

	// Create account
	account := cxf.Account{
		ID:          accountID,
		Username:    opts.AccountUsername,
		Email:       opts.AccountEmail,
		FullName:    opts.AccountFullName,
		Collections: collections,
		Items:       items,
	}

	// Create header
	header := &cxf.Header{
		Version: cxf.Version{
			Major: cxf.VersionMajor,
			Minor: cxf.VersionMinor,
		},
		ExporterRpId:        opts.ExporterRpID,
		ExporterDisplayName: opts.ExporterName,
		Timestamp:           uint64(time.Now().Unix()),
		Accounts:            []cxf.Account{account},
	}

	return header, nil
}

// mapCredentialsToItems converts model.Credential slice to cxf.Item slice.
func mapCredentialsToItems(creds []model.Credential) ([]cxf.Item, error) {
	items := make([]cxf.Item, 0, len(creds))

	for i := range creds {
		item, err := mapCredentialToItem(&creds[i])
		if err != nil {
			return nil, err
		}
		items = append(items, item)
	}

	return items, nil
}

// generateBase64URLID generates a base64url-encoded UUID.
func generateBase64URLID() string {
	id := uuid.New()
	return base64.RawURLEncoding.EncodeToString(id[:])
}

// uintPtr returns a pointer to the given uint64 value.
func uintPtr(v uint64) *uint64 {
	return &v
}
