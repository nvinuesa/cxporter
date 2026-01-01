// Package security provides security utilities for handling sensitive data.
package security

import (
	"crypto/subtle"
)

// SecureBytes wraps a byte slice and ensures it's zeroed when no longer needed.
type SecureBytes struct {
	data []byte
}

// NewSecureBytes creates a new SecureBytes with the given capacity.
func NewSecureBytes(size int) *SecureBytes {
	return &SecureBytes{
		data: make([]byte, size),
	}
}

// FromBytes creates a SecureBytes from existing bytes and clears the source.
func FromBytes(data []byte) *SecureBytes {
	s := &SecureBytes{
		data: make([]byte, len(data)),
	}
	copy(s.data, data)
	// Clear source
	for i := range data {
		data[i] = 0
	}
	return s
}

// Bytes returns the underlying byte slice. Caller must not retain this reference.
func (s *SecureBytes) Bytes() []byte {
	if s == nil {
		return nil
	}
	return s.data
}

// String returns the data as a string. The string will not be secured.
// Use sparingly and only when necessary for APIs that require strings.
func (s *SecureBytes) String() string {
	if s == nil {
		return ""
	}
	return string(s.data)
}

// Len returns the length of the secure bytes.
func (s *SecureBytes) Len() int {
	if s == nil {
		return 0
	}
	return len(s.data)
}

// Zero securely clears the bytes using constant-time operations.
func (s *SecureBytes) Zero() {
	if s == nil || s.data == nil {
		return
	}
	for i := range s.data {
		s.data[i] = 0
	}
	// Double-check using subtle to prevent compiler optimization
	if len(s.data) > 0 {
		subtle.ConstantTimeCopy(1, s.data, make([]byte, len(s.data)))
	}
	s.data = nil
}

// Clone creates a secure copy of the bytes.
func (s *SecureBytes) Clone() *SecureBytes {
	if s == nil || s.data == nil {
		return nil
	}
	clone := &SecureBytes{
		data: make([]byte, len(s.data)),
	}
	copy(clone.data, s.data)
	return clone
}

// Equal compares two SecureBytes in constant time.
func (s *SecureBytes) Equal(other *SecureBytes) bool {
	if s == nil || other == nil {
		return s == other
	}
	if len(s.data) != len(other.data) {
		return false
	}
	return subtle.ConstantTimeCompare(s.data, other.data) == 1
}

// Wipe is a convenience method to zero and nil out a slice.
// This should be called via defer to ensure cleanup.
func Wipe(data *[]byte) {
	if data == nil || *data == nil {
		return
	}
	for i := range *data {
		(*data)[i] = 0
	}
	*data = nil
}

// WipeString attempts to clear a string's backing array.
// Note: This is best-effort as Go strings are immutable.
// Use SecureBytes instead of strings for sensitive data.
func WipeString(s *string) {
	if s == nil {
		return
	}
	// Convert to byte slice and wipe
	// This may not work if the string is interned or shared
	b := []byte(*s)
	for i := range b {
		b[i] = 0
	}
	*s = ""
}
