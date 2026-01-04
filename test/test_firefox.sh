#!/usr/bin/env bash

# Integration tests for Firefox CSV source

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/common.sh"

test_firefox_basic_convert() {
    print_test "Firefox basic convert"
    
    local input="${TESTDATA}/firefox/logins.csv"
    local output
    output=$(temp_file "firefox-basic")
    
    if [[ ! -f "${input}" ]]; then
        skip "Test file not found: ${input}"
        return
    fi
    
    run_cxporter convert -s firefox "${input}" -o "${output}" || return 1
    
    assert_file_exists "${output}" || return 1
    assert_file_not_empty "${output}" || return 1
    assert_valid_json "${output}" || return 1
    
    # Verify CXF structure
    assert_json_has_key "${output}" ".version" || return 1
    assert_json_has_key "${output}" ".accounts" || return 1
    
    # Check version
    local version_major
    version_major=$(get_json_value "${output}" ".version.major")
    assert_equals "1" "${version_major}" || return 1
    
    # Count items (3 entries in logins.csv)
    local item_count
    item_count=$(json_array_length "${output}" ".accounts[0].items")
    assert_equals "3" "${item_count}" "Expected 3 items from Firefox CSV" || return 1
    
    pass
}

test_firefox_stdout() {
    print_test "Firefox convert to stdout"
    
    local input="${TESTDATA}/firefox/logins.csv"
    
    if [[ ! -f "${input}" ]]; then
        skip "Test file not found: ${input}"
        return
    fi
    
    local output
    output=$(run_cxporter_stdout convert -s firefox "${input}")
    
    # Verify it's valid JSON
    if ! echo "${output}" | jq empty 2>/dev/null; then
        fail "Output is not valid JSON"
        return 1
    fi
    
    # Verify it contains expected structure
    if ! echo "${output}" | jq -e '.version' >/dev/null 2>&1; then
        fail "Output missing .version field"
        return 1
    fi
    
    pass
}

test_firefox_auto_detect() {
    print_test "Firefox auto-detection"
    
    local input="${TESTDATA}/firefox/logins.csv"
    local output
    output=$(temp_file "firefox-auto")
    
    if [[ ! -f "${input}" ]]; then
        skip "Test file not found: ${input}"
        return
    fi
    
    # Don't specify -s flag, let it auto-detect
    run_cxporter convert "${input}" -o "${output}" || return 1
    
    assert_file_exists "${output}" || return 1
    assert_valid_json "${output}" || return 1
    
    local item_count
    item_count=$(json_array_length "${output}" ".accounts[0].items")
    assert_equals "3" "${item_count}" || return 1
    
    pass
}

test_firefox_invalid_file() {
    print_test "Firefox handles invalid file"
    
    local input
    input=$(temp_file "invalid")
    echo "invalid,firefox,csv,data" > "${input}"
    
    local output
    output=$(temp_file "firefox-invalid")
    
    # Should fail or produce empty output
    if run_cxporter convert -s firefox "${input}" -o "${output}" 2>/dev/null; then
        # If it succeeds, check that output has 0 items
        if [[ -f "${output}" ]]; then
            local item_count
            item_count=$(json_array_length "${output}" ".accounts[0].items" 2>/dev/null || echo "0")
            if [[ "${item_count}" != "0" ]]; then
                fail "Expected 0 items from invalid CSV"
                return 1
            fi
        fi
    fi
    
    pass
}

test_firefox_nonexistent_file() {
    print_test "Firefox handles nonexistent file"
    
    local output
    output=$(temp_file "firefox-nofile")
    
    if run_cxporter convert -s firefox "/nonexistent/file.csv" -o "${output}" 2>/dev/null; then
        fail "Should have failed with nonexistent file"
        return 1
    fi
    
    pass
}

test_firefox_credential_fields() {
    print_test "Firefox credential fields mapping"
    
    local input="${TESTDATA}/firefox/logins.csv"
    local output
    output=$(temp_file "firefox-fields")
    
    if [[ ! -f "${input}" ]]; then
        skip "Test file not found: ${input}"
        return
    fi
    
    run_cxporter convert -s firefox "${input}" -o "${output}" || return 1
    
    # Verify first item has expected fields
    assert_json_has_key "${output}" ".accounts[0].items[0].id" || return 1
    assert_json_has_key "${output}" ".accounts[0].items[0].title" || return 1
    assert_json_has_key "${output}" ".accounts[0].items[0].credentials" || return 1
    
    # Verify credentials array is not empty
    local creds_count
    creds_count=$(json_array_length "${output}" ".accounts[0].items[0].credentials")
    assert_greater_than "${creds_count}" "0" || return 1
    
    pass
}

test_firefox_url_mapping() {
    print_test "Firefox URL to scope mapping"
    
    local input="${TESTDATA}/firefox/logins.csv"
    local output
    output=$(temp_file "firefox-url")
    
    if [[ ! -f "${input}" ]]; then
        skip "Test file not found: ${input}"
        return
    fi
    
    run_cxporter convert -s firefox "${input}" -o "${output}" || return 1
    
    # First item should have a scope with URLs
    local scope_urls
    scope_urls=$(get_json_value "${output}" ".accounts[0].items[0].scope.urls[0]")
    
    if [[ "${scope_urls}" == "null" || -z "${scope_urls}" ]]; then
        fail "Expected scope.urls to be populated"
        return 1
    fi
    
    pass
}

test_firefox_timestamp_handling() {
    print_test "Firefox timestamp handling"
    
    local input="${TESTDATA}/firefox/logins.csv"
    local output
    output=$(temp_file "firefox-time")
    
    if [[ ! -f "${input}" ]]; then
        skip "Test file not found: ${input}"
        return
    fi
    
    run_cxporter convert -s firefox "${input}" -o "${output}" || return 1
    
    # Check that timestamps are present - modifiedAt should be set
    local modified_at
    modified_at=$(get_json_value "${output}" ".accounts[0].items[0].modifiedAt")
    
    if [[ "${modified_at}" == "null" || "${modified_at}" == "0" ]]; then
        fail "Expected modifiedAt timestamp to be set"
        return 1
    fi
    
    pass
}

test_firefox_http_realm_handling() {
    print_test "Firefox HTTP realm handling"
    
    local input="${TESTDATA}/firefox/logins.csv"
    local output
    output=$(temp_file "firefox-realm")
    
    if [[ ! -f "${input}" ]]; then
        skip "Test file not found: ${input}"
        return
    fi
    
    run_cxporter convert -s firefox "${input}" -o "${output}" || return 1
    
    # The third entry in logins.csv has httpRealm
    local item_count
    item_count=$(json_array_length "${output}" ".accounts[0].items")
    
    if [[ "${item_count}" -lt 3 ]]; then
        fail "Expected at least 3 items"
        return 1
    fi
    
    pass
}

# Main execution
main() {
    print_header "Firefox Source Integration Tests"
    
    check_binary
    check_jq
    setup_test_env
    
    test_firefox_basic_convert
    test_firefox_stdout
    test_firefox_auto_detect
    test_firefox_invalid_file
    test_firefox_nonexistent_file
    test_firefox_credential_fields
    test_firefox_url_mapping
    test_firefox_timestamp_handling
    test_firefox_http_realm_handling
    
    print_summary
}

main "$@"
