# Bash Integration Tests

Bash-based integration tests for the cxporter CLI tool.

## Overview

These tests validate the end-to-end behavior of the `cxporter` binary by executing it as a subprocess and verifying its output. Unlike the Go unit tests, these integration tests:

- Test the actual compiled binary (not Go code directly)
- Validate real CLI argument parsing and output
- Test auto-detection of source formats
- Verify JSON output structure and validity
- Test error handling and edge cases
- Support concurrent execution

## Prerequisites

- **Built binary**: Run `make build` to create `./bin/cxporter`
- **jq**: JSON query tool for parsing and validating output
  ```bash
  # Install on Ubuntu/Debian
  sudo apt-get install jq
  
  # Install on macOS
  brew install jq
  ```

## Running Tests

### Run all integration tests
```bash
make test-integration
```

### Run a specific test suite
```bash
./test/test_chrome.sh
./test/test_firefox.sh
./test/test_bitwarden.sh
./test/test_ssh.sh
./test/test_cli.sh
```

### Run all tests (unit + integration)
```bash
make test-all
```

## Test Structure

```
test/
├── common.sh           # Shared utilities and assertion functions
├── run_all.sh          # Main test runner (runs all suites)
├── test_chrome.sh      # Chrome CSV source tests
├── test_firefox.sh     # Firefox CSV source tests
├── test_bitwarden.sh   # Bitwarden JSON source tests
├── test_ssh.sh         # SSH key source tests
├── test_cli.sh         # General CLI functionality tests
└── README.md           # This file
```

## Test Suites

### `test_cli.sh` - General CLI Tests
- Version and help commands
- Flag variations (`-s`/`--source`, `-o`/`--output`)
- Error handling (invalid commands, missing files)
- Stdout/stderr behavior
- Filter flag functionality
- Exit codes
- Concurrent conversions

### `test_chrome.sh` - Chrome Source Tests
- Basic conversion from CSV
- Auto-detection of Chrome format
- Stdout output
- Preview command
- Edge cases (empty passwords, special characters)
- Old format compatibility
- Field mapping (username, password, URL)
- Invalid/nonexistent file handling

### `test_firefox.sh` - Firefox Source Tests
- Basic conversion from CSV
- Auto-detection of Firefox format
- Timestamp handling
- HTTP realm support
- URL mapping
- Field validation
- Error cases

### `test_bitwarden.sh` - Bitwarden Source Tests
- JSON export parsing
- Folder hierarchy (collections)
- Multiple credential types (logins, notes, cards, identities)
- TOTP extraction
- Custom fields
- Encrypted exports
- Timestamp conversion

### `test_ssh.sh` - SSH Source Tests
- Directory scanning for SSH keys
- Multiple key types (RSA, Ed25519, ECDSA)
- Encrypted key handling
- Public key skipping (`.pub` files)
- Non-key file filtering (`config`, `known_hosts`, etc.)
- Invalid key graceful handling

## Writing Tests

### Test Function Structure

```bash
test_my_feature() {
    print_test "Description of what's being tested"
    
    # Setup
    local input="${TESTDATA}/source/file.csv"
    local output
    output=$(temp_file "prefix")
    
    # Skip if test data not available
    if [[ ! -f "${input}" ]]; then
        skip "Test file not found: ${input}"
        return
    fi
    
    # Execute
    run_cxporter convert -s chrome "${input}" -o "${output}" || return 1
    
    # Assertions
    assert_file_exists "${output}" || return 1
    assert_valid_json "${output}" || return 1
    
    local item_count
    item_count=$(json_array_length "${output}" ".accounts[0].items")
    assert_equals "4" "${item_count}" || return 1
    
    pass
}
```

### Available Assertions

#### File Assertions
- `assert_file_exists <file>` - File exists
- `assert_file_not_empty <file>` - File has content

#### String Assertions
- `assert_contains <haystack> <needle>` - String contains substring
- `assert_not_contains <haystack> <needle>` - String doesn't contain substring
- `assert_equals <expected> <actual>` - Strings are equal

#### Number Assertions
- `assert_greater_than <actual> <threshold>` - Number comparison

#### JSON Assertions
- `assert_valid_json <file>` - File contains valid JSON
- `assert_json_has_key <file> <jq_path>` - JSON contains key

#### Command Assertions
- `assert_success` - Last command succeeded (exit 0)
- `assert_failure` - Last command failed (exit non-zero)

### Utility Functions

#### Running cxporter
```bash
# Run and capture exit code
run_cxporter convert -s chrome input.csv -o output.json

# Run and capture stdout only
output=$(run_cxporter_stdout convert -s chrome input.csv)

# Run and capture stderr only
errors=$(run_cxporter_stderr convert -s chrome invalid.csv)
```

#### JSON Queries
```bash
# Get a JSON value
version=$(get_json_value "${file}" ".version.major")

# Count array length
count=$(json_array_length "${file}" ".accounts[0].items")
```

#### Temporary Files
```bash
# Create temp file in test directory
temp_file=$(temp_file "prefix")
```

### Test Result Functions
- `pass` - Mark test as passed
- `fail <message>` - Mark test as failed with message
- `skip <reason>` - Skip test with reason

## Best Practices

### 1. Always Check Test Data
```bash
if [[ ! -f "${input}" ]]; then
    skip "Test file not found: ${input}"
    return
fi
```

### 2. Use Temporary Files
```bash
# Good - uses temp directory
output=$(temp_file "chrome-test")

# Bad - hardcoded path
output="/tmp/output.json"
```

### 3. Chain Assertions with ||
```bash
assert_file_exists "${output}" || return 1
assert_valid_json "${output}" || return 1
```

### 4. Provide Descriptive Messages
```bash
# Good
assert_equals "4" "${count}" "Expected 4 items from Chrome CSV" || return 1

# Less helpful
assert_equals "4" "${count}" || return 1
```

### 5. Test Both Success and Failure
```bash
# Test successful conversion
run_cxporter convert -s chrome valid.csv -o output.json || return 1

# Test error handling
if run_cxporter convert -s chrome invalid.csv -o output.json 2>/dev/null; then
    fail "Should have failed with invalid input"
    return 1
fi
```

### 6. Clean Up Resources
```bash
# Temp files in TMP_DIR are auto-cleaned
# For other resources:
test_cleanup() {
    rm -rf "${my_temp_dir}"
}
```

## Debugging Failed Tests

### Verbose Output
```bash
# Run with full output
./test/integration/test_chrome.sh

# Run specific test by editing the file temporarily
# Comment out other tests in main()
```

### Inspect Test Outputs
```bash
# Temp directory persists during test execution
# Add 'echo "${TMP_DIR}"' in your test to see location
# Files are cleaned up on exit
```

### Manual Reproduction
```bash
# Copy the failing command from test output
./bin/cxporter convert -s chrome testdata/chrome/passwords.csv -o /tmp/debug.json

# Inspect output
jq . /tmp/debug.json
```

## Continuous Integration

These tests are designed to run in CI environments:

```yaml
# Example GitHub Actions workflow
- name: Build
  run: make build

- name: Run Integration Tests
  run: make test-integration
```

## Exit Codes

- **0**: All tests passed
- **1**: One or more tests failed

Individual test suites also return 0/1 for pass/fail.

## Adding New Test Suites

1. Create `test/test_newsource.sh`
2. Source `common.sh`
3. Define test functions
4. Create `main()` function
5. Make executable: `chmod +x test/test_newsource.sh`
6. Add to `TEST_SUITES` array in `run_all.sh`

Example template:

```bash
#!/usr/bin/env bash

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/common.sh"

test_basic_conversion() {
    print_test "Basic conversion"
    # ... test implementation
    pass
}

main() {
    print_header "My New Source Tests"
    
    check_binary
    check_jq
    setup_test_env
    
    test_basic_conversion
    # ... more tests
    
    print_summary
}

main "$@"
```
