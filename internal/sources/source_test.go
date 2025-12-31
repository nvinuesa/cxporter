package sources

import (
	"errors"
	"testing"

	"github.com/nvinuesa/cxporter/internal/model"
)

// MockSource is a test implementation of the Source interface.
type MockSource struct {
	name        string
	description string
	extensions  []string
	detectFunc  func(path string) (int, error)
	openFunc    func(path string, opts OpenOptions) error
	readFunc    func() ([]model.Credential, error)
	closeFunc   func() error
	isOpen      bool
}

func NewMockSource(name string) *MockSource {
	return &MockSource{
		name:        name,
		description: "Mock source for testing",
		extensions:  []string{".mock"},
		detectFunc: func(path string) (int, error) {
			return 50, nil
		},
		openFunc: func(path string, opts OpenOptions) error {
			return nil
		},
		readFunc: func() ([]model.Credential, error) {
			return []model.Credential{}, nil
		},
		closeFunc: func() error {
			return nil
		},
	}
}

func (m *MockSource) Name() string                  { return m.name }
func (m *MockSource) Description() string           { return m.description }
func (m *MockSource) SupportedExtensions() []string { return m.extensions }

func (m *MockSource) Detect(path string) (int, error) {
	if m.detectFunc != nil {
		return m.detectFunc(path)
	}
	return 0, nil
}

func (m *MockSource) Open(path string, opts OpenOptions) error {
	if m.isOpen {
		return ErrAlreadyOpen
	}
	if m.openFunc != nil {
		err := m.openFunc(path, opts)
		if err == nil {
			m.isOpen = true
		}
		return err
	}
	m.isOpen = true
	return nil
}

func (m *MockSource) Read() ([]model.Credential, error) {
	if !m.isOpen {
		return nil, ErrNotOpen
	}
	if m.readFunc != nil {
		return m.readFunc()
	}
	return []model.Credential{}, nil
}

func (m *MockSource) Close() error {
	if m.closeFunc != nil {
		err := m.closeFunc()
		m.isOpen = false
		return err
	}
	m.isOpen = false
	return nil
}

func (m *MockSource) WithDetect(f func(path string) (int, error)) *MockSource {
	m.detectFunc = f
	return m
}

func (m *MockSource) WithOpen(f func(path string, opts OpenOptions) error) *MockSource {
	m.openFunc = f
	return m
}

func (m *MockSource) WithRead(f func() ([]model.Credential, error)) *MockSource {
	m.readFunc = f
	return m
}

func (m *MockSource) WithExtensions(exts []string) *MockSource {
	m.extensions = exts
	return m
}

// TestRegistry tests the source registry.
func TestRegistry(t *testing.T) {
	t.Run("NewRegistry", func(t *testing.T) {
		r := NewRegistry()
		if r == nil {
			t.Fatal("NewRegistry returned nil")
		}
		if r.Count() != 0 {
			t.Errorf("New registry should be empty, got %d sources", r.Count())
		}
	})

	t.Run("Register and Get", func(t *testing.T) {
		r := NewRegistry()
		mock := NewMockSource("test")

		r.Register(mock)

		got, ok := r.Get("test")
		if !ok {
			t.Fatal("Get returned false for registered source")
		}
		if got.Name() != "test" {
			t.Errorf("Get returned wrong source: %s", got.Name())
		}
	})

	t.Run("Get non-existent", func(t *testing.T) {
		r := NewRegistry()

		_, ok := r.Get("nonexistent")
		if ok {
			t.Error("Get should return false for non-existent source")
		}
	})

	t.Run("Unregister", func(t *testing.T) {
		r := NewRegistry()
		mock := NewMockSource("test")

		r.Register(mock)
		r.Unregister("test")

		_, ok := r.Get("test")
		if ok {
			t.Error("Source should not exist after unregister")
		}
	})

	t.Run("List", func(t *testing.T) {
		r := NewRegistry()
		r.Register(NewMockSource("zebra"))
		r.Register(NewMockSource("alpha"))
		r.Register(NewMockSource("beta"))

		list := r.List()
		if len(list) != 3 {
			t.Fatalf("List returned %d sources, expected 3", len(list))
		}

		// Should be sorted by name
		if list[0].Name() != "alpha" {
			t.Errorf("First source should be 'alpha', got '%s'", list[0].Name())
		}
		if list[1].Name() != "beta" {
			t.Errorf("Second source should be 'beta', got '%s'", list[1].Name())
		}
		if list[2].Name() != "zebra" {
			t.Errorf("Third source should be 'zebra', got '%s'", list[2].Name())
		}
	})

	t.Run("Names", func(t *testing.T) {
		r := NewRegistry()
		r.Register(NewMockSource("zebra"))
		r.Register(NewMockSource("alpha"))

		names := r.Names()
		if len(names) != 2 {
			t.Fatalf("Names returned %d names, expected 2", len(names))
		}
		if names[0] != "alpha" || names[1] != "zebra" {
			t.Errorf("Names not sorted: %v", names)
		}
	})

	t.Run("Count", func(t *testing.T) {
		r := NewRegistry()
		r.Register(NewMockSource("one"))
		r.Register(NewMockSource("two"))

		if r.Count() != 2 {
			t.Errorf("Count returned %d, expected 2", r.Count())
		}
	})

	t.Run("Replace existing", func(t *testing.T) {
		r := NewRegistry()
		mock1 := NewMockSource("test")
		mock1.description = "first"
		mock2 := NewMockSource("test")
		mock2.description = "second"

		r.Register(mock1)
		r.Register(mock2)

		got, _ := r.Get("test")
		if got.Description() != "second" {
			t.Error("Register should replace existing source with same name")
		}
	})
}

func TestRegistry_DetectSource(t *testing.T) {
	t.Run("Detect by extension", func(t *testing.T) {
		r := NewRegistry()
		kdbx := NewMockSource("keepass").WithExtensions([]string{".kdbx"}).WithDetect(func(path string) (int, error) {
			return 100, nil
		})
		csv := NewMockSource("chrome").WithExtensions([]string{".csv"}).WithDetect(func(path string) (int, error) {
			return 50, nil
		})

		r.Register(kdbx)
		r.Register(csv)

		source, err := r.DetectSource("vault.kdbx")
		if err != nil {
			t.Fatalf("DetectSource failed: %v", err)
		}
		if source.Name() != "keepass" {
			t.Errorf("Expected keepass, got %s", source.Name())
		}
	})

	t.Run("Detect by confidence", func(t *testing.T) {
		r := NewRegistry()
		low := NewMockSource("low").WithExtensions([]string{".test"}).WithDetect(func(path string) (int, error) {
			return 30, nil
		})
		high := NewMockSource("high").WithExtensions([]string{".test"}).WithDetect(func(path string) (int, error) {
			return 90, nil
		})

		r.Register(low)
		r.Register(high)

		source, err := r.DetectSource("file.test")
		if err != nil {
			t.Fatalf("DetectSource failed: %v", err)
		}
		if source.Name() != "high" {
			t.Errorf("Expected high confidence source, got %s", source.Name())
		}
	})

	t.Run("No match returns error", func(t *testing.T) {
		r := NewRegistry()
		mock := NewMockSource("test").WithDetect(func(path string) (int, error) {
			return 0, nil
		})
		r.Register(mock)

		_, err := r.DetectSource("unknown.xyz")
		if err == nil {
			t.Error("Expected error for no match")
		}

		var notFound *ErrSourceNotFound
		if !errors.As(err, &notFound) {
			t.Errorf("Expected ErrSourceNotFound, got %T", err)
		}
	})

	t.Run("Detection error skips source", func(t *testing.T) {
		r := NewRegistry()
		failing := NewMockSource("failing").WithDetect(func(path string) (int, error) {
			return 0, errors.New("detection failed")
		})
		working := NewMockSource("working").WithDetect(func(path string) (int, error) {
			return 50, nil
		})

		r.Register(failing)
		r.Register(working)

		source, err := r.DetectSource("file.txt")
		if err != nil {
			t.Fatalf("DetectSource failed: %v", err)
		}
		if source.Name() != "working" {
			t.Errorf("Expected working source, got %s", source.Name())
		}
	})

	t.Run("Empty registry", func(t *testing.T) {
		r := NewRegistry()

		_, err := r.DetectSource("file.txt")
		if err == nil {
			t.Error("Expected error for empty registry")
		}
	})
}

func TestRegistry_DetectSourceWithThreshold(t *testing.T) {
	r := NewRegistry()
	low := NewMockSource("low").WithDetect(func(path string) (int, error) {
		return 30, nil
	})
	high := NewMockSource("high").WithDetect(func(path string) (int, error) {
		return 70, nil
	})

	r.Register(low)
	r.Register(high)

	t.Run("Above threshold", func(t *testing.T) {
		source, err := r.DetectSourceWithThreshold("file.txt", 50)
		if err != nil {
			t.Fatalf("DetectSourceWithThreshold failed: %v", err)
		}
		if source.Name() != "high" {
			t.Errorf("Expected high, got %s", source.Name())
		}
	})

	t.Run("Below threshold", func(t *testing.T) {
		_, err := r.DetectSourceWithThreshold("file.txt", 80)
		if err == nil {
			t.Error("Expected error for below threshold")
		}
	})
}

func TestMockSource(t *testing.T) {
	t.Run("Basic operations", func(t *testing.T) {
		mock := NewMockSource("test")

		// Test Open
		if err := mock.Open("path", OpenOptions{}); err != nil {
			t.Fatalf("Open failed: %v", err)
		}

		// Test Read
		creds, err := mock.Read()
		if err != nil {
			t.Fatalf("Read failed: %v", err)
		}
		if creds == nil {
			t.Error("Read returned nil")
		}

		// Test Close
		if err := mock.Close(); err != nil {
			t.Fatalf("Close failed: %v", err)
		}
	})

	t.Run("Read before Open", func(t *testing.T) {
		mock := NewMockSource("test")

		_, err := mock.Read()
		if !errors.Is(err, ErrNotOpen) {
			t.Errorf("Expected ErrNotOpen, got %v", err)
		}
	})

	t.Run("Double Open", func(t *testing.T) {
		mock := NewMockSource("test")

		if err := mock.Open("path", OpenOptions{}); err != nil {
			t.Fatalf("First Open failed: %v", err)
		}

		err := mock.Open("path", OpenOptions{})
		if !errors.Is(err, ErrAlreadyOpen) {
			t.Errorf("Expected ErrAlreadyOpen, got %v", err)
		}
	})

	t.Run("Custom read function", func(t *testing.T) {
		creds := []model.Credential{
			{ID: "1", Title: "Test"},
		}

		mock := NewMockSource("test").WithRead(func() ([]model.Credential, error) {
			return creds, nil
		})

		_ = mock.Open("path", OpenOptions{})
		got, err := mock.Read()
		if err != nil {
			t.Fatalf("Read failed: %v", err)
		}
		if len(got) != 1 || got[0].ID != "1" {
			t.Error("Custom read function not called correctly")
		}
	})
}

func TestDefaultRegistry(t *testing.T) {
	r1 := DefaultRegistry()
	r2 := DefaultRegistry()

	if r1 != r2 {
		t.Error("DefaultRegistry should return the same instance")
	}
}
