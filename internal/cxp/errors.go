// Package cxp provides error types compliant with CXP v1.0 specification.
package cxp

import (
	"encoding/json"
	"fmt"
)

// CXP error codes per specification Section 4.4.
const (
	// ErrCodeInvalidRequest indicates the request is malformed or invalid.
	ErrCodeInvalidRequest = "invalid_request"
	
	// ErrCodeInvalidGrant indicates authentication or authorization failed.
	ErrCodeInvalidGrant = "invalid_grant"
	
	// ErrCodeUnauthorizedClient indicates the client is not authorized.
	ErrCodeUnauthorizedClient = "unauthorized_client"
	
	// ErrCodeUnsupportedVersion indicates the CXP version is not supported.
	ErrCodeUnsupportedVersion = "unsupported_version"
	
	// ErrCodeUnsupportedAlgorithm indicates the HPKE algorithm is not supported.
	ErrCodeUnsupportedAlgorithm = "unsupported_algorithm"
	
	// ErrCodeInvalidKey indicates the encryption key is invalid.
	ErrCodeInvalidKey = "invalid_key"
	
	// ErrCodeInvalidArchive indicates the archive format is invalid.
	ErrCodeInvalidArchive = "invalid_archive"
	
	// ErrCodeServerError indicates an internal server error occurred.
	ErrCodeServerError = "server_error"
)

// CXPError represents a standardized error response per CXP v1.0 specification.
type CXPError struct {
	// ErrorCode identifies the error type
	ErrorCode string `json:"error"`
	
	// ErrorDescription provides additional human-readable information
	ErrorDescription string `json:"error_description,omitempty"`
	
	// ErrorURI is a URI to documentation about the error
	ErrorURI string `json:"error_uri,omitempty"`
}

// NewCXPError creates a new CXP error with the given code and description.
func NewCXPError(code, description string) *CXPError {
	return &CXPError{
		ErrorCode:        code,
		ErrorDescription: description,
	}
}

// WithURI adds a documentation URI to the error.
func (e *CXPError) WithURI(uri string) *CXPError {
	e.ErrorURI = uri
	return e
}

// Error implements the error interface.
func (e *CXPError) Error() string {
	if e.ErrorDescription != "" {
		return fmt.Sprintf("%s: %s", e.ErrorCode, e.ErrorDescription)
	}
	return e.ErrorCode
}

// JSON returns the JSON representation of the error.
func (e *CXPError) JSON() ([]byte, error) {
	return json.Marshal(e)
}

// Predefined CXP errors.
var (
	// ErrInvalidRequest is returned when the request is malformed.
	ErrInvalidRequest = NewCXPError(ErrCodeInvalidRequest, "The request is malformed or invalid")
	
	// ErrInvalidGrant is returned when authentication fails.
	ErrInvalidGrant = NewCXPError(ErrCodeInvalidGrant, "Authentication or authorization failed")
	
	// ErrUnauthorizedClient is returned when the client is not authorized.
	ErrUnauthorizedClient = NewCXPError(ErrCodeUnauthorizedClient, "Client is not authorized")
	
	// ErrUnsupportedVersion is returned when the CXP version is not supported.
	ErrUnsupportedVersion = NewCXPError(ErrCodeUnsupportedVersion, "CXP version is not supported")
	
	// ErrUnsupportedAlgorithm is returned when the HPKE algorithm is not supported.
	ErrUnsupportedAlgorithm = NewCXPError(ErrCodeUnsupportedAlgorithm, "HPKE algorithm is not supported")
	
	// ErrInvalidKey is returned when the encryption key is invalid.
	ErrInvalidKey = NewCXPError(ErrCodeInvalidKey, "Encryption key is invalid")
	
	// ErrInvalidArchive is returned when the archive format is invalid.
	ErrInvalidArchive = NewCXPError(ErrCodeInvalidArchive, "Archive format is invalid")
	
	// ErrServerError is returned for internal server errors.
	ErrServerError = NewCXPError(ErrCodeServerError, "Internal server error")
)

// IsCXPError checks if an error is a CXPError.
func IsCXPError(err error) bool {
	_, ok := err.(*CXPError)
	return ok
}

// ToCXPError converts a standard error to a CXPError if it isn't already.
func ToCXPError(err error) *CXPError {
	if cxpErr, ok := err.(*CXPError); ok {
		return cxpErr
	}
	return NewCXPError(ErrCodeServerError, err.Error())
}
