package cxp

import (
	"encoding/base64"
	"errors"
	"os"
	"path/filepath"

	"github.com/nvinuesa/go-cxf"
	"github.com/nvinuesa/go-cxp"
)

// Exporter errors.
var (
	ErrNilHeader        = errors.New("header is nil")
	ErrNoOutputPath     = errors.New("output path is required")
	ErrMissingPubKey    = errors.New("recipient public key required for encryption")
	ErrCreateOutputFile = errors.New("failed to create output file")
)

// ExportResponseFull extends cxp.ExportResponse with the archive field.
// The archive field is required by CXP specification but missing from go-cxp.
type ExportResponseFull struct {
	Version  cxp.Version        `json:"version"`
	Hpke     cxp.HpkeParameters `json:"hpke"`
	Exporter string             `json:"exporter"`
	// Archive algorithm ("deflate")
	Archive string `json:"archive"`
	Payload string `json:"payload"` // base64url encoded
}

// ExportOptions configures CXP export behavior.
type ExportOptions struct {
	// OutputPath is the destination file path.
	OutputPath string
	// Encrypt enables HPKE encryption. If false, outputs unencrypted JSON.
	Encrypt bool
	// RecipientPubKey is the X25519 public key for HPKE encryption.
	RecipientPubKey []byte
	// HPKEParams overrides default HPKE parameters if provided.
	HPKEParams *cxp.HpkeParameters
}

// Export writes a CXF Header to disk, optionally encrypted.
func Export(header *cxf.Header, opts ExportOptions) error {
	data, err := ExportToBytes(header, opts)
	if err != nil {
		return err
	}

	if opts.OutputPath == "" {
		return ErrNoOutputPath
	}

	// Ensure parent directory exists
	dir := filepath.Dir(opts.OutputPath)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return err
	}

	// Write to file
	if err := os.WriteFile(opts.OutputPath, data, 0600); err != nil {
		return err
	}

	return nil
}

// ExportToBytes returns the export as bytes (for testing or piping).
func ExportToBytes(header *cxf.Header, opts ExportOptions) ([]byte, error) {
	if header == nil {
		return nil, ErrNilHeader
	}

	if !opts.Encrypt {
		// Unencrypted JSON export
		return CreateUnencryptedArchive(header)
	}

	// Encrypted export
	if len(opts.RecipientPubKey) == 0 {
		return nil, ErrMissingPubKey
	}

	// Get HPKE parameters
	params := DefaultHPKEParams()
	if opts.HPKEParams != nil {
		params = *opts.HPKEParams
	}

	// Create HPKE context
	hpkeCtx, err := NewHPKEContext(opts.RecipientPubKey, params)
	if err != nil {
		return nil, err
	}

	// Create encrypted archive
	return CreateArchive(header, hpkeCtx)
}

// ExportResponse creates a CXP ExportResponse from a header and encryption context.
// Payload is base64url encoded per CXP specification.
// Deprecated: Use ExportResponseFull for full CXP specification compliance.
func ExportResponse(header *cxf.Header, recipientPubKey []byte) (*cxp.ExportResponse, error) {
	if header == nil {
		return nil, ErrNilHeader
	}
	if len(recipientPubKey) == 0 {
		return nil, ErrMissingPubKey
	}

	params := DefaultHPKEParams()

	// Create HPKE context
	hpkeCtx, err := NewHPKEContext(recipientPubKey, params)
	if err != nil {
		return nil, err
	}

	// Create archive
	archiveData, err := CreateArchive(header, hpkeCtx)
	if err != nil {
		return nil, err
	}

	// Build response
	// CXP-DEV-003: Payload must be base64url encoded per CXP specification
	response := &cxp.ExportResponse{
		Version:  cxp.VersionV0,
		Hpke:     params,
		Exporter: header.ExporterRpId,
		Payload:  base64.RawURLEncoding.EncodeToString(archiveData),
	}

	return response, nil
}

// ExportResponseWithArchive creates a fully CXP-compliant ExportResponse.
// This includes the archive field required by CXP specification.
// CXP-DEV-003: Payload is base64url encoded.
// CXP-DEV-004: Archive field specifies the compression algorithm ("deflate").
func ExportResponseWithArchive(header *cxf.Header, recipientPubKey []byte) (*ExportResponseFull, error) {
	if header == nil {
		return nil, ErrNilHeader
	}
	if len(recipientPubKey) == 0 {
		return nil, ErrMissingPubKey
	}

	params := DefaultHPKEParams()

	// Create HPKE context
	hpkeCtx, err := NewHPKEContext(recipientPubKey, params)
	if err != nil {
		return nil, err
	}

	// Create archive
	archiveData, err := CreateArchive(header, hpkeCtx)
	if err != nil {
		return nil, err
	}

	// Build full response with archive field
	response := &ExportResponseFull{
		Version:  cxp.VersionV0,
		Hpke:     params,
		Exporter: header.ExporterRpId,
		Archive:  ArchiveAlgorithmDeflate, // CXP-DEV-004: Required archive algorithm field
		Payload:  base64.RawURLEncoding.EncodeToString(archiveData),
	}

	return response, nil
}
