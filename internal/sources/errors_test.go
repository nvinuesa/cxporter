package sources

import (
	"errors"
	"strings"
	"testing"
)

func TestErrSourceNotFound(t *testing.T) {
	t.Run("Basic error", func(t *testing.T) {
		err := &ErrSourceNotFound{Path: "/path/to/file.xyz"}
		msg := err.Error()
		if !strings.Contains(msg, "/path/to/file.xyz") {
			t.Errorf("Error message should contain path: %s", msg)
		}
	})

	t.Run("With min confidence", func(t *testing.T) {
		err := &ErrSourceNotFound{Path: "/path/to/file", MinConfidence: 50}
		msg := err.Error()
		if !strings.Contains(msg, "50") {
			t.Errorf("Error message should contain confidence: %s", msg)
		}
	})
}

func TestErrInvalidFormat(t *testing.T) {
	t.Run("Basic error", func(t *testing.T) {
		err := &ErrInvalidFormat{
			Source: "keepass",
			Path:   "/vault.kdbx",
		}
		msg := err.Error()
		if !strings.Contains(msg, "keepass") || !strings.Contains(msg, "/vault.kdbx") {
			t.Errorf("Error message should contain source and path: %s", msg)
		}
	})

	t.Run("With details", func(t *testing.T) {
		err := &ErrInvalidFormat{
			Source:  "chrome",
			Path:    "/passwords.csv",
			Details: "missing header row",
		}
		msg := err.Error()
		if !strings.Contains(msg, "missing header row") {
			t.Errorf("Error message should contain details: %s", msg)
		}
	})

	t.Run("With underlying error", func(t *testing.T) {
		underlying := errors.New("parse error")
		err := &ErrInvalidFormat{
			Source: "keepass",
			Path:   "/vault.kdbx",
			Err:    underlying,
		}
		msg := err.Error()
		if !strings.Contains(msg, "parse error") {
			t.Errorf("Error message should contain underlying error: %s", msg)
		}

		if err.Unwrap() != underlying {
			t.Error("Unwrap should return underlying error")
		}
	})
}

func TestErrAuthenticationFailed(t *testing.T) {
	t.Run("Basic error", func(t *testing.T) {
		err := &ErrAuthenticationFailed{
			Source: "keepass",
			Path:   "/vault.kdbx",
		}
		msg := err.Error()
		if !strings.Contains(msg, "authentication failed") {
			t.Errorf("Error message should mention authentication: %s", msg)
		}
	})

	t.Run("With reason", func(t *testing.T) {
		err := &ErrAuthenticationFailed{
			Source: "keepass",
			Path:   "/vault.kdbx",
			Reason: "wrong password",
		}
		msg := err.Error()
		if !strings.Contains(msg, "wrong password") {
			t.Errorf("Error message should contain reason: %s", msg)
		}
	})

	t.Run("With underlying error", func(t *testing.T) {
		underlying := errors.New("crypto error")
		err := &ErrAuthenticationFailed{
			Source: "keepass",
			Path:   "/vault.kdbx",
			Err:    underlying,
		}

		if err.Unwrap() != underlying {
			t.Error("Unwrap should return underlying error")
		}
	})
}

func TestErrPermissionDenied(t *testing.T) {
	t.Run("Basic error", func(t *testing.T) {
		err := &ErrPermissionDenied{
			Path: "/restricted/file",
			Op:   "read",
		}
		msg := err.Error()
		if !strings.Contains(msg, "permission denied") {
			t.Errorf("Error message should mention permission: %s", msg)
		}
		if !strings.Contains(msg, "read") {
			t.Errorf("Error message should contain operation: %s", msg)
		}
	})

	t.Run("With underlying error", func(t *testing.T) {
		underlying := errors.New("EACCES")
		err := &ErrPermissionDenied{
			Path: "/file",
			Op:   "open",
			Err:  underlying,
		}

		if err.Unwrap() != underlying {
			t.Error("Unwrap should return underlying error")
		}
	})
}

func TestErrPartialRead(t *testing.T) {
	t.Run("Basic error", func(t *testing.T) {
		err := &ErrPartialRead{
			Source:     "keepass",
			TotalItems: 100,
			ReadItems:  95,
		}
		msg := err.Error()
		if !strings.Contains(msg, "95 of 100") {
			t.Errorf("Error message should contain counts: %s", msg)
		}
	})

	t.Run("With failures", func(t *testing.T) {
		err := &ErrPartialRead{
			Source:     "keepass",
			TotalItems: 100,
			ReadItems:  95,
			Failures:   []string{"Entry 1: corrupted", "Entry 2: missing field"},
		}
		msg := err.Error()
		if !strings.Contains(msg, "Entry 1: corrupted") {
			t.Errorf("Error message should contain failures: %s", msg)
		}
	})

	t.Run("AddFailure", func(t *testing.T) {
		err := &ErrPartialRead{Source: "test"}
		err.AddFailure("test failure", errors.New("underlying"))

		if len(err.Failures) != 1 {
			t.Errorf("AddFailure should add to Failures: %d", len(err.Failures))
		}
		if len(err.Errs) != 1 {
			t.Errorf("AddFailure should add to Errs: %d", len(err.Errs))
		}
	})

	t.Run("AddFailure with nil error", func(t *testing.T) {
		err := &ErrPartialRead{Source: "test"}
		err.AddFailure("test failure", nil)

		if len(err.Failures) != 1 {
			t.Error("AddFailure should add to Failures even with nil error")
		}
		if len(err.Errs) != 0 {
			t.Error("AddFailure should not add nil to Errs")
		}
	})

	t.Run("HasFailures", func(t *testing.T) {
		err := &ErrPartialRead{Source: "test"}
		if err.HasFailures() {
			t.Error("HasFailures should return false for empty failures")
		}

		err.AddFailure("failure", nil)
		if !err.HasFailures() {
			t.Error("HasFailures should return true after adding failure")
		}
	})
}

func TestErrFileNotFound(t *testing.T) {
	err := &ErrFileNotFound{Path: "/nonexistent/file.txt"}
	msg := err.Error()
	if !strings.Contains(msg, "file not found") {
		t.Errorf("Error message should mention file not found: %s", msg)
	}
	if !strings.Contains(msg, "/nonexistent/file.txt") {
		t.Errorf("Error message should contain path: %s", msg)
	}
}

func TestErrUnsupportedFeature(t *testing.T) {
	err := &ErrUnsupportedFeature{
		Source:  "chrome",
		Feature: "attachments",
	}
	msg := err.Error()
	if !strings.Contains(msg, "chrome") {
		t.Errorf("Error message should contain source: %s", msg)
	}
	if !strings.Contains(msg, "attachments") {
		t.Errorf("Error message should contain feature: %s", msg)
	}
}

func TestErrorHelpers(t *testing.T) {
	t.Run("IsAuthError", func(t *testing.T) {
		authErr := &ErrAuthenticationFailed{Source: "test"}
		if !IsAuthError(authErr) {
			t.Error("IsAuthError should return true for ErrAuthenticationFailed")
		}

		otherErr := errors.New("other error")
		if IsAuthError(otherErr) {
			t.Error("IsAuthError should return false for other errors")
		}
	})

	t.Run("IsFormatError", func(t *testing.T) {
		formatErr := &ErrInvalidFormat{Source: "test"}
		if !IsFormatError(formatErr) {
			t.Error("IsFormatError should return true for ErrInvalidFormat")
		}

		otherErr := errors.New("other error")
		if IsFormatError(otherErr) {
			t.Error("IsFormatError should return false for other errors")
		}
	})

	t.Run("IsPartialRead", func(t *testing.T) {
		partialErr := &ErrPartialRead{Source: "test"}
		if !IsPartialRead(partialErr) {
			t.Error("IsPartialRead should return true for ErrPartialRead")
		}

		otherErr := errors.New("other error")
		if IsPartialRead(otherErr) {
			t.Error("IsPartialRead should return false for other errors")
		}
	})

	t.Run("IsNotFound", func(t *testing.T) {
		fileNotFound := &ErrFileNotFound{Path: "/test"}
		if !IsNotFound(fileNotFound) {
			t.Error("IsNotFound should return true for ErrFileNotFound")
		}

		sourceNotFound := &ErrSourceNotFound{Path: "/test"}
		if !IsNotFound(sourceNotFound) {
			t.Error("IsNotFound should return true for ErrSourceNotFound")
		}

		otherErr := errors.New("other error")
		if IsNotFound(otherErr) {
			t.Error("IsNotFound should return false for other errors")
		}
	})
}

func TestCommonErrors(t *testing.T) {
	// Test that common errors are defined
	if ErrNotOpen == nil {
		t.Error("ErrNotOpen should not be nil")
	}
	if ErrAlreadyOpen == nil {
		t.Error("ErrAlreadyOpen should not be nil")
	}
	if ErrClosed == nil {
		t.Error("ErrClosed should not be nil")
	}
}
