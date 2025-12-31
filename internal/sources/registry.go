package sources

import (
	"path/filepath"
	"sort"
	"strings"
	"sync"
)

// Registry manages available source adapters.
// It provides lookup by name and auto-detection by file extension or content.
type Registry struct {
	mu      sync.RWMutex
	sources map[string]Source
}

// NewRegistry creates a new empty source registry.
func NewRegistry() *Registry {
	return &Registry{
		sources: make(map[string]Source),
	}
}

// Register adds a source adapter to the registry.
// If a source with the same name already exists, it will be replaced.
func (r *Registry) Register(s Source) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.sources[s.Name()] = s
}

// Unregister removes a source adapter from the registry.
func (r *Registry) Unregister(name string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	delete(r.sources, name)
}

// Get retrieves a source adapter by name.
// Returns the source and true if found, or nil and false if not found.
func (r *Registry) Get(name string) (Source, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	s, ok := r.sources[name]
	return s, ok
}

// List returns all registered source adapters sorted by name.
func (r *Registry) List() []Source {
	r.mu.RLock()
	defer r.mu.RUnlock()

	result := make([]Source, 0, len(r.sources))
	for _, s := range r.sources {
		result = append(result, s)
	}

	// Sort by name for consistent ordering
	sort.Slice(result, func(i, j int) bool {
		return result[i].Name() < result[j].Name()
	})

	return result
}

// Names returns the names of all registered sources sorted alphabetically.
func (r *Registry) Names() []string {
	r.mu.RLock()
	defer r.mu.RUnlock()

	names := make([]string, 0, len(r.sources))
	for name := range r.sources {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

// DetectSource attempts to auto-detect the appropriate source for a path.
// It first tries extension matching, then content detection.
// Returns the best matching source or ErrSourceNotFound if no match.
func (r *Registry) DetectSource(path string) (Source, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	ext := strings.ToLower(filepath.Ext(path))

	// First pass: find sources that support this extension
	var candidates []Source
	for _, s := range r.sources {
		for _, supportedExt := range s.SupportedExtensions() {
			if strings.ToLower(supportedExt) == ext {
				candidates = append(candidates, s)
				break
			}
		}
	}

	// If no extension matches, try all sources
	if len(candidates) == 0 {
		for _, s := range r.sources {
			candidates = append(candidates, s)
		}
	}

	// Run detection on candidates
	var bestSource Source
	var bestConfidence int

	for _, s := range candidates {
		confidence, err := s.Detect(path)
		if err != nil {
			// Detection error, skip this source
			continue
		}
		if confidence > bestConfidence {
			bestConfidence = confidence
			bestSource = s
		}
	}

	if bestSource == nil || bestConfidence == 0 {
		return nil, &ErrSourceNotFound{Path: path}
	}

	return bestSource, nil
}

// DetectSourceWithThreshold is like DetectSource but requires a minimum confidence.
func (r *Registry) DetectSourceWithThreshold(path string, minConfidence int) (Source, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	var bestSource Source
	var bestConfidence int

	for _, s := range r.sources {
		confidence, err := s.Detect(path)
		if err != nil {
			continue
		}
		if confidence >= minConfidence && confidence > bestConfidence {
			bestConfidence = confidence
			bestSource = s
		}
	}

	if bestSource == nil {
		return nil, &ErrSourceNotFound{Path: path, MinConfidence: minConfidence}
	}

	return bestSource, nil
}

// Count returns the number of registered sources.
func (r *Registry) Count() int {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return len(r.sources)
}

// defaultRegistry is the global registry instance.
var defaultRegistry *Registry
var defaultRegistryOnce sync.Once

// DefaultRegistry returns the default global registry with all built-in sources.
// This function is safe for concurrent use.
func DefaultRegistry() *Registry {
	defaultRegistryOnce.Do(func() {
		defaultRegistry = NewRegistry()
		// Built-in sources will be registered here as they are implemented
		// This is done in init() functions of each source file
	})
	return defaultRegistry
}

// RegisterDefault registers a source with the default registry.
func RegisterDefault(s Source) {
	DefaultRegistry().Register(s)
}
