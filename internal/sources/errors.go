package sources

import (
	"errors"
	"fmt"
	"strings"
)

// Common errors that can be returned by source adapters.
var (
	// ErrNotOpen is returned when Read is called before Open.
	ErrNotOpen = errors.New("source not open")

	// ErrAlreadyOpen is returned when Open is called on an already-open source.
	ErrAlreadyOpen = errors.New("source already open")

	// ErrClosed is returned when operations are attempted on a closed source.
	ErrClosed = errors.New("source is closed")
)

// ErrSourceNotFound indicates that no source adapter could handle the given path.
type ErrSourceNotFound struct {
	Path          string
	MinConfidence int
}

func (e *ErrSourceNotFound) Error() string {
	if e.MinConfidence > 0 {
		return fmt.Sprintf("no source found for %q with confidence >= %d", e.Path, e.MinConfidence)
	}
	return fmt.Sprintf("no source found for %q", e.Path)
}

// ErrInvalidFormat indicates that the source file has an invalid or corrupted format.
type ErrInvalidFormat struct {
	Source  string // Source adapter name
	Path    string // File path
	Details string // What was wrong
	Err     error  // Underlying error, if any
}

func (e *ErrInvalidFormat) Error() string {
	msg := fmt.Sprintf("%s: invalid format for %q", e.Source, e.Path)
	if e.Details != "" {
		msg += ": " + e.Details
	}
	if e.Err != nil {
		msg += ": " + e.Err.Error()
	}
	return msg
}

func (e *ErrInvalidFormat) Unwrap() error {
	return e.Err
}

// ErrAuthenticationFailed indicates that authentication failed (wrong password, key, etc.).
type ErrAuthenticationFailed struct {
	Source string // Source adapter name
	Path   string // File path
	Reason string // Why authentication failed
	Err    error  // Underlying error, if any
}

func (e *ErrAuthenticationFailed) Error() string {
	msg := fmt.Sprintf("%s: authentication failed for %q", e.Source, e.Path)
	if e.Reason != "" {
		msg += ": " + e.Reason
	}
	if e.Err != nil {
		msg += ": " + e.Err.Error()
	}
	return msg
}

func (e *ErrAuthenticationFailed) Unwrap() error {
	return e.Err
}

// ErrPermissionDenied indicates a file access permission issue.
type ErrPermissionDenied struct {
	Path string
	Op   string // Operation that failed (read, open, etc.)
	Err  error  // Underlying error
}

func (e *ErrPermissionDenied) Error() string {
	msg := fmt.Sprintf("permission denied: cannot %s %q", e.Op, e.Path)
	if e.Err != nil {
		msg += ": " + e.Err.Error()
	}
	return msg
}

func (e *ErrPermissionDenied) Unwrap() error {
	return e.Err
}

// ErrPartialRead indicates that some credentials couldn't be read.
// The source will still return the credentials that were successfully read.
type ErrPartialRead struct {
	Source     string   // Source adapter name
	TotalItems int      // Total items attempted
	ReadItems  int      // Items successfully read
	Failures   []string // Descriptions of failures
	Errs       []error  // Individual errors
}

func (e *ErrPartialRead) Error() string {
	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("%s: partial read - %d of %d items succeeded",
		e.Source, e.ReadItems, e.TotalItems))

	if len(e.Failures) > 0 {
		sb.WriteString("\nFailures:\n")
		for i, f := range e.Failures {
			sb.WriteString(fmt.Sprintf("  - %s", f))
			if i < len(e.Failures)-1 {
				sb.WriteString("\n")
			}
		}
	}

	return sb.String()
}

// AddFailure adds a failure to the partial read error.
func (e *ErrPartialRead) AddFailure(description string, err error) {
	e.Failures = append(e.Failures, description)
	if err != nil {
		e.Errs = append(e.Errs, err)
	}
}

// HasFailures returns true if there are any failures recorded.
func (e *ErrPartialRead) HasFailures() bool {
	return len(e.Failures) > 0
}

// ErrFileNotFound indicates the specified file does not exist.
type ErrFileNotFound struct {
	Path string
}

func (e *ErrFileNotFound) Error() string {
	return fmt.Sprintf("file not found: %q", e.Path)
}

// ErrUnsupportedFeature indicates a feature is not supported by the source.
type ErrUnsupportedFeature struct {
	Source  string
	Feature string
}

func (e *ErrUnsupportedFeature) Error() string {
	return fmt.Sprintf("%s: unsupported feature: %s", e.Source, e.Feature)
}

// IsAuthError returns true if the error is an authentication error.
func IsAuthError(err error) bool {
	var authErr *ErrAuthenticationFailed
	return errors.As(err, &authErr)
}

// IsFormatError returns true if the error is a format error.
func IsFormatError(err error) bool {
	var formatErr *ErrInvalidFormat
	return errors.As(err, &formatErr)
}

// IsPartialRead returns true if the error is a partial read error.
func IsPartialRead(err error) bool {
	var partialErr *ErrPartialRead
	return errors.As(err, &partialErr)
}

// IsNotFound returns true if the error is a not found error.
func IsNotFound(err error) bool {
	var notFoundErr *ErrFileNotFound
	var sourceNotFoundErr *ErrSourceNotFound
	return errors.As(err, &notFoundErr) || errors.As(err, &sourceNotFoundErr)
}
