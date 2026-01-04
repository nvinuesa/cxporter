# Contributing to cxporter

Thank you for your interest in contributing to cxporter! This document provides guidelines for development, testing, and submitting contributions.

## Development Setup

### Prerequisites

- Go 1.23 or later
- Make
- Git

### Clone and Build

```bash
git clone https://github.com/nvinuesa/cxporter.git
cd cxporter
make build
```

### Run Tests

```bash
make test
```

### Run Linter

```bash
make lint
```

## Project Structure

```
cxporter/
├── cmd/cxporter/       # CLI application
│   ├── main.go         # Entry point
│   ├── convert.go      # Convert command
│   └── version.go      # Version command
├── internal/
│   ├── model/          # Internal credential model
│   ├── sources/        # Source adapters
│   │   ├── source.go   # Source interface
│   │   ├── registry.go # Source registry
│   │   ├── chrome.go   # Chrome CSV adapter
│   │   ├── firefox.go  # Firefox CSV adapter
│   │   ├── bitwarden.go# Bitwarden JSON adapter
│   │   ├── keepass.go  # KeePass adapter
│   │   └── ssh.go      # SSH keys adapter
│   ├── cxf/            # CXF generation
│   └── cxp/            # CXP export
├── testdata/           # Test fixtures
├── test/               # Integration tests
├── docs/               # Documentation
└── examples/           # Example scripts
```

## Adding a New Source

### 1. Create the Source File

Create `internal/sources/newsource.go`:

```go
package sources

import (
    "github.com/nvinuesa/cxporter/internal/model"
)

type NewSource struct {
    // fields
}

func NewNewSource() *NewSource {
    return &NewSource{}
}

func (s *NewSource) Name() string {
    return "newsource"
}

func (s *NewSource) Description() string {
    return "Description of the new source"
}

func (s *NewSource) SupportedExtensions() []string {
    return []string{".ext"}
}

func (s *NewSource) Detect(path string) (int, error) {
    // Return confidence 0-100
}

func (s *NewSource) Open(path string, opts OpenOptions) error {
    // Initialize source
}

func (s *NewSource) Read() ([]model.Credential, error) {
    // Parse and return credentials
}

func (s *NewSource) Close() error {
    // Cleanup
}

func init() {
    RegisterDefault(NewNewSource())
}

var _ Source = (*NewSource)(nil)
```

### 2. Create Tests

Create `internal/sources/newsource_test.go` with table-driven tests.

### 3. Add Test Fixtures

Create `testdata/newsource/` with sample files.

### 4. Update Documentation

Update `docs/SOURCES.md` with the new source format.

## Coding Standards

### Go Style
- Follow [Effective Go](https://golang.org/doc/effective_go)
- Use `gofmt` for formatting
- Use `go vet` and `staticcheck` for linting

### Documentation
- All exported functions need doc comments
- Use complete sentences in comments
- Include examples where helpful

### Error Handling
- Use structured errors from `internal/sources/errors.go`
- Wrap errors with context: `fmt.Errorf("context: %w", err)`
- Never panic; return errors

### Testing
- Write table-driven tests
- Aim for >80% coverage
- Test error cases
- Use subtests for organization

## Pull Request Process

### Before Submitting

1. Fork the repository
2. Create a feature branch: `git checkout -b feature/my-feature`
3. Make your changes
4. Run tests: `make test`
5. Run linter: `make lint`
6. Commit with conventional commits: `feat: add new feature`

### Conventional Commits

Use this format for commit messages:

```
type(scope): description

[optional body]

[optional footer]
```

Types:
- `feat`: New feature
- `fix`: Bug fix
- `docs`: Documentation changes
- `test`: Test additions/changes
- `refactor`: Code refactoring
- `chore`: Maintenance tasks

### Submitting

1. Push your branch: `git push origin feature/my-feature`
2. Open a Pull Request against `main`
3. Fill out the PR template
4. Wait for CI checks to pass
5. Request review

### Review Process

- Maintainers will review within 1-2 business days
- Address feedback in new commits
- Squash commits before merging

## Testing Guidelines

### Unit Tests

Test individual functions with table-driven tests:

```go
func TestFunction(t *testing.T) {
    tests := []struct {
        name    string
        input   string
        want    string
        wantErr bool
    }{
        {"valid input", "foo", "bar", false},
        {"invalid input", "", "", true},
    }

    for _, tt := range tests {
        t.Run(tt.name, func(t *testing.T) {
            got, err := Function(tt.input)
            if (err != nil) != tt.wantErr {
                t.Errorf("error = %v, wantErr %v", err, tt.wantErr)
            }
            if got != tt.want {
                t.Errorf("got = %v, want %v", got, tt.want)
            }
        })
    }
}
```

### Integration Tests

Integration tests are in `test/integration_test.go`:

```bash
make test-integration
```

### Coverage

Check coverage:

```bash
make test
go tool cover -html=coverage.out
```

## Release Process

1. Update version in `cmd/cxporter/version.go`
2. Create changelog entry
3. Tag release: `git tag v1.0.0`
4. Push tag: `git push origin v1.0.0`
5. CI will build and publish binaries

## Getting Help

- Open an issue for bugs or feature requests
- Start a discussion for questions
- Check existing issues before creating new ones

## License

By contributing, you agree that your contributions will be licensed under the AGPL-3.0 license.
