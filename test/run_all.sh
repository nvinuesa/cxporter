#!/usr/bin/env bash

# Main test runner for cxporter integration tests
# Runs all integration test suites and reports overall results

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/common.sh"

# Test suite files
TEST_SUITES=(
    "test_cli.sh"
    "test_chrome.sh"
    "test_firefox.sh"
    "test_bitwarden.sh"
    "test_ssh.sh"
)

# Track overall results
TOTAL_SUITES=0
PASSED_SUITES=0
FAILED_SUITES=0
OVERALL_TESTS_RUN=0
OVERALL_TESTS_PASSED=0
OVERALL_TESTS_FAILED=0

# Run a single test suite
run_suite() {
    local suite_file="$1"
    local suite_name
    suite_name=$(basename "${suite_file}" .sh)
    
    if [[ ! -x "${suite_file}" ]]; then
        echo -e "${YELLOW}Skipping ${suite_name}: not executable${NC}"
        return
    fi
    
    TOTAL_SUITES=$((TOTAL_SUITES + 1))
    
    # Run the suite and capture its exit code
    if "${suite_file}"; then
        PASSED_SUITES=$((PASSED_SUITES + 1))
        echo -e "${GREEN}✓ ${suite_name} passed${NC}"
    else
        FAILED_SUITES=$((FAILED_SUITES + 1))
        echo -e "${RED}✗ ${suite_name} failed${NC}"
    fi
    
    echo ""
}

# Print overall summary
print_overall_summary() {
    echo ""
    echo -e "${BLUE}========================================${NC}"
    echo -e "${BLUE}  Overall Test Results${NC}"
    echo -e "${BLUE}========================================${NC}"
    echo -e "Test suites run:    ${TOTAL_SUITES}"
    echo -e "${GREEN}Test suites passed: ${PASSED_SUITES}${NC}"
    if [[ ${FAILED_SUITES} -gt 0 ]]; then
        echo -e "${RED}Test suites failed: ${FAILED_SUITES}${NC}"
    else
        echo -e "Test suites failed: ${FAILED_SUITES}"
    fi
    echo -e "${BLUE}========================================${NC}"
    echo ""
    
    if [[ ${FAILED_SUITES} -gt 0 ]]; then
        echo -e "${RED}OVERALL: FAILED${NC}"
        return 1
    else
        echo -e "${GREEN}OVERALL: PASSED${NC}"
        return 0
    fi
}

# Main execution
main() {
    print_header "cxporter Integration Test Suite"
    
    echo "Running all integration tests..."
    echo ""
    
    # Check prerequisites
    check_binary
    check_jq
    
    # Run each test suite
    for suite in "${TEST_SUITES[@]}"; do
        suite_path="${SCRIPT_DIR}/${suite}"
        if [[ -f "${suite_path}" ]]; then
            run_suite "${suite_path}"
        else
            echo -e "${YELLOW}Warning: Test suite not found: ${suite_path}${NC}"
        fi
    done
    
    # Print overall summary
    print_overall_summary
}

main "$@"
