package cxp

import (
	"archive/zip"
	"bytes"
	"encoding/json"
	"fmt"

	"github.com/nvinuesa/go-cxf"
)

// Archive directory structure.
const (
	archiveRootDir     = "CXP-Export/"
	archiveIndexFile   = "CXP-Export/index.jwe"
	archiveDocsDir     = "CXP-Export/documents/"
	archiveDocFileFmt  = "CXP-Export/documents/%s.jwe"
)

// IndexDocument contains account metadata without secrets.
type IndexDocument struct {
	Version             cxf.Version     `json:"version"`
	ExporterRpId        string          `json:"exporterRpId"`
	ExporterDisplayName string          `json:"exporterDisplayName"`
	Timestamp           uint64          `json:"timestamp"`
	Accounts            []IndexAccount  `json:"accounts"`
}

// IndexAccount contains account metadata for the index.
type IndexAccount struct {
	ID          string           `json:"id"`
	Username    string           `json:"username"`
	Email       string           `json:"email"`
	FullName    string           `json:"fullName,omitempty"`
	Collections []cxf.Collection `json:"collections"`
	Items       []IndexItem      `json:"items"`
}

// IndexItem contains item metadata without credentials.
type IndexItem struct {
	ID         string              `json:"id"`
	CreationAt *uint64             `json:"creationAt,omitempty"`
	ModifiedAt *uint64             `json:"modifiedAt,omitempty"`
	Title      string              `json:"title"`
	Subtitle   string              `json:"subtitle,omitempty"`
	Favorite   *bool               `json:"favorite,omitempty"`
	Scope      *cxf.CredentialScope `json:"scope,omitempty"`
	Tags       []string            `json:"tags,omitempty"`
}

// CreateArchive builds the CXP ZIP archive structure.
func CreateArchive(header *cxf.Header, hpke *HPKEContext) ([]byte, error) {
	buf := new(bytes.Buffer)
	zipWriter := zip.NewWriter(buf)

	// Create root directory
	if _, err := zipWriter.Create(archiveRootDir); err != nil {
		return nil, fmt.Errorf("failed to create root directory: %w", err)
	}

	// Create documents directory
	if _, err := zipWriter.Create(archiveDocsDir); err != nil {
		return nil, fmt.Errorf("failed to create documents directory: %w", err)
	}

	// Build index document (metadata without secrets)
	indexDoc := buildIndexDocument(header)
	indexJSON, err := json.Marshal(indexDoc)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal index document: %w", err)
	}

	// Encrypt and write index
	indexJWE, err := hpke.EncryptToJWE(indexJSON)
	if err != nil {
		return nil, fmt.Errorf("failed to encrypt index: %w", err)
	}

	indexFile, err := zipWriter.Create(archiveIndexFile)
	if err != nil {
		return nil, fmt.Errorf("failed to create index file: %w", err)
	}
	if _, err := indexFile.Write(indexJWE); err != nil {
		return nil, fmt.Errorf("failed to write index file: %w", err)
	}

	// Write each item as a separate encrypted document
	for _, account := range header.Accounts {
		for _, item := range account.Items {
			itemJSON, err := json.Marshal(item)
			if err != nil {
				return nil, fmt.Errorf("failed to marshal item %s: %w", item.ID, err)
			}

			itemJWE, err := hpke.EncryptToJWE(itemJSON)
			if err != nil {
				return nil, fmt.Errorf("failed to encrypt item %s: %w", item.ID, err)
			}

			itemPath := fmt.Sprintf(archiveDocFileFmt, item.ID)
			itemFile, err := zipWriter.Create(itemPath)
			if err != nil {
				return nil, fmt.Errorf("failed to create item file %s: %w", item.ID, err)
			}
			if _, err := itemFile.Write(itemJWE); err != nil {
				return nil, fmt.Errorf("failed to write item file %s: %w", item.ID, err)
			}
		}
	}

	if err := zipWriter.Close(); err != nil {
		return nil, fmt.Errorf("failed to close zip: %w", err)
	}

	return buf.Bytes(), nil
}

// buildIndexDocument creates an IndexDocument from a CXF Header.
func buildIndexDocument(header *cxf.Header) *IndexDocument {
	indexDoc := &IndexDocument{
		Version:             header.Version,
		ExporterRpId:        header.ExporterRpId,
		ExporterDisplayName: header.ExporterDisplayName,
		Timestamp:           header.Timestamp,
		Accounts:            make([]IndexAccount, len(header.Accounts)),
	}

	for i, account := range header.Accounts {
		indexAccount := IndexAccount{
			ID:          account.ID,
			Username:    account.Username,
			Email:       account.Email,
			FullName:    account.FullName,
			Collections: account.Collections,
			Items:       make([]IndexItem, len(account.Items)),
		}

		for j, item := range account.Items {
			indexAccount.Items[j] = IndexItem{
				ID:         item.ID,
				CreationAt: item.CreationAt,
				ModifiedAt: item.ModifiedAt,
				Title:      item.Title,
				Subtitle:   item.Subtitle,
				Favorite:   item.Favorite,
				Scope:      item.Scope,
				Tags:       item.Tags,
			}
		}

		indexDoc.Accounts[i] = indexAccount
	}

	return indexDoc
}

// CreateUnencryptedArchive creates a simple JSON export without encryption.
func CreateUnencryptedArchive(header *cxf.Header) ([]byte, error) {
	return json.MarshalIndent(header, "", "  ")
}
