#!/usr/bin/env bash

# Common utilities for cxporter integration tests

set -euo pipefail

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Test counters
TESTS_RUN=0
TESTS_PASSED=0
TESTS_FAILED=0

# Directories
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
BINARY="${PROJECT_ROOT}/bin/cxporter"
TESTDATA="${PROJECT_ROOT}/testdata"
TMP_DIR=""

# Setup temporary directory for test outputs
setup_test_env() {
    TMP_DIR="$(mktemp -d -t cxporter-test.XXXXXX)"
    export TMP_DIR
}

# Cleanup temporary directory
cleanup_test_env() {
    if [[ -n "${TMP_DIR:-}" && -d "${TMP_DIR}" ]]; then
        rm -rf "${TMP_DIR}"
    fi
}

# Ensure cleanup happens on exit
trap cleanup_test_env EXIT INT TERM

# Check if binary exists
check_binary() {
    if [[ ! -x "${BINARY}" ]]; then
        echo -e "${RED}ERROR: Binary not found at ${BINARY}${NC}" >&2
        echo "Run 'make build' first" >&2
        exit 1
    fi
}

# Print test header
print_header() {
    local title="$1"
    echo ""
    echo -e "${BLUE}========================================${NC}"
    echo -e "${BLUE}  ${title}${NC}"
    echo -e "${BLUE}========================================${NC}"
    echo ""
}

# Print test name
print_test() {
    local test_name="$1"
    echo -n "  ${test_name}... "
    TESTS_RUN=$((TESTS_RUN + 1))
}

# Print test result - pass
pass() {
    echo -e "${GREEN}PASS${NC}"
    TESTS_PASSED=$((TESTS_PASSED + 1))
}

# Print test result - fail
fail() {
    local message="${1:-}"
    echo -e "${RED}FAIL${NC}"
    if [[ -n "${message}" ]]; then
        echo -e "    ${RED}${message}${NC}"
    fi
    TESTS_FAILED=$((TESTS_FAILED + 1))
}

# Print test result - skip
skip() {
    local reason="${1:-}"
    echo -e "${YELLOW}SKIP${NC}"
    if [[ -n "${reason}" ]]; then
        echo -e "    ${YELLOW}${reason}${NC}"
    fi
    TESTS_RUN=$((TESTS_RUN - 1))
}

# Print test summary
print_summary() {
    echo ""
    echo -e "${BLUE}========================================${NC}"
    echo -e "Tests run:    ${TESTS_RUN}"
    echo -e "${GREEN}Tests passed: ${TESTS_PASSED}${NC}"
    if [[ ${TESTS_FAILED} -gt 0 ]]; then
        echo -e "${RED}Tests failed: ${TESTS_FAILED}${NC}"
    else
        echo -e "Tests failed: ${TESTS_FAILED}"
    fi
    echo -e "${BLUE}========================================${NC}"
    echo ""
    
    if [[ ${TESTS_FAILED} -gt 0 ]]; then
        return 1
    fi
    return 0
}

# Assert file exists
assert_file_exists() {
    local file="$1"
    local message="${2:-File does not exist: ${file}}"
    
    if [[ ! -f "${file}" ]]; then
        fail "${message}"
        return 1
    fi
    return 0
}

# Assert file not empty
assert_file_not_empty() {
    local file="$1"
    local message="${2:-File is empty: ${file}}"
    
    if [[ ! -s "${file}" ]]; then
        fail "${message}"
        return 1
    fi
    return 0
}

# Assert command succeeds
assert_success() {
    if [[ $? -ne 0 ]]; then
        fail "Command failed with exit code $?"
        return 1
    fi
    return 0
}

# Assert command fails
assert_failure() {
    if [[ $? -eq 0 ]]; then
        fail "Command succeeded but should have failed"
        return 1
    fi
    return 0
}

# Assert string contains substring
assert_contains() {
    local haystack="$1"
    local needle="$2"
    local message="${3:-String does not contain '${needle}'}"
    
    if [[ ! "${haystack}" == *"${needle}"* ]]; then
        fail "${message}"
        return 1
    fi
    return 0
}

# Assert string does not contain substring
assert_not_contains() {
    local haystack="$1"
    local needle="$2"
    local message="${3:-String contains '${needle}' but should not}"
    
    if [[ "${haystack}" == *"${needle}"* ]]; then
        fail "${message}"
        return 1
    fi
    return 0
}

# Assert strings are equal
assert_equals() {
    local expected="$1"
    local actual="$2"
    local message="${3:-Expected '${expected}' but got '${actual}'}"
    
    if [[ "${expected}" != "${actual}" ]]; then
        fail "${message}"
        return 1
    fi
    return 0
}

# Assert number greater than
assert_greater_than() {
    local actual="$1"
    local threshold="$2"
    local message="${3:-Expected > ${threshold} but got ${actual}}"
    
    if [[ ${actual} -le ${threshold} ]]; then
        fail "${message}"
        return 1
    fi
    return 0
}

# Assert valid JSON
assert_valid_json() {
    local file="$1"
    local message="${2:-Invalid JSON in file: ${file}}"
    
    if ! jq empty "${file}" 2>/dev/null; then
        fail "${message}"
        return 1
    fi
    return 0
}

# Assert JSON contains key
assert_json_has_key() {
    local file="$1"
    local key="$2"
    local message="${3:-JSON missing key: ${key}}"
    
    local value
    value=$(jq -r "${key}" "${file}" 2>/dev/null)
    if [[ "${value}" == "null" ]]; then
        fail "${message}"
        return 1
    fi
    return 0
}

# Get JSON value
get_json_value() {
    local file="$1"
    local key="$2"
    jq -r "${key}" "${file}" 2>/dev/null || echo ""
}

# Count JSON array length
json_array_length() {
    local file="$1"
    local key="$2"
    jq -r "${key} | length" "${file}" 2>/dev/null || echo "0"
}

# Run cxporter command and capture output
run_cxporter() {
    "${BINARY}" "$@"
}

# Run cxporter and capture stdout
run_cxporter_stdout() {
    "${BINARY}" "$@" 2>/dev/null
}

# Run cxporter and capture stderr
run_cxporter_stderr() {
    "${BINARY}" "$@" 2>&1 >/dev/null
}

# Check if jq is available
check_jq() {
    if ! command -v jq &> /dev/null; then
        echo -e "${RED}ERROR: jq is not installed${NC}" >&2
        echo "Install jq to run these tests" >&2
        exit 1
    fi
}

# Generate temporary file path
temp_file() {
    local prefix="${1:-cxporter-test}"
    mktemp "${TMP_DIR}/${prefix}.XXXXXX"
}

# Export functions for use in subshells
export -f print_test pass fail skip
export -f assert_file_exists assert_file_not_empty assert_success assert_failure
export -f assert_contains assert_not_contains assert_equals assert_greater_than
export -f assert_valid_json assert_json_has_key get_json_value json_array_length
export -f run_cxporter run_cxporter_stdout run_cxporter_stderr temp_file
