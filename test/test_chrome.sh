#!/usr/bin/env bash

# Integration tests for Chrome CSV source

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/common.sh"

test_chrome_basic_convert() {
    print_test "Chrome basic convert"
    
    local input="${TESTDATA}/chrome/passwords.csv"
    local output
    output=$(temp_file "chrome-basic")
    
    if [[ ! -f "${input}" ]]; then
        skip "Test file not found: ${input}"
        return
    fi
    
    run_cxporter convert -s chrome "${input}" -o "${output}" || return 1
    
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
    
    # Count items (4 entries in passwords.csv)
    local item_count
    item_count=$(json_array_length "${output}" ".accounts[0].items")
    assert_equals "4" "${item_count}" "Expected 4 items from Chrome CSV" || return 1
    
    pass
}

test_chrome_stdout() {
    print_test "Chrome convert to stdout"
    
    local input="${TESTDATA}/chrome/passwords.csv"
    
    if [[ ! -f "${input}" ]]; then
        skip "Test file not found: ${input}"
        return
    fi
    
    local output
    output=$(run_cxporter_stdout convert -s chrome "${input}")
    
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

test_chrome_auto_detect() {
    print_test "Chrome auto-detection"
    
    local input="${TESTDATA}/chrome/passwords.csv"
    local output
    output=$(temp_file "chrome-auto")
    
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
    assert_equals "4" "${item_count}" || return 1
    
    pass
}

test_chrome_edge_cases() {
    print_test "Chrome edge cases"
    
    local input="${TESTDATA}/chrome/edge_cases.csv"
    local output
    output=$(temp_file "chrome-edge")
    
    if [[ ! -f "${input}" ]]; then
        skip "Test file not found: ${input}"
        return
    fi
    
    run_cxporter convert -s chrome "${input}" -o "${output}" || return 1
    
    assert_file_exists "${output}" || return 1
    assert_valid_json "${output}" || return 1
    
    pass
}

test_chrome_old_format() {
    print_test "Chrome old format compatibility"
    
    local input="${TESTDATA}/chrome/passwords_old_format.csv"
    local output
    output=$(temp_file "chrome-old")
    
    if [[ ! -f "${input}" ]]; then
        skip "Test file not found: ${input}"
        return
    fi
    
    run_cxporter convert -s chrome "${input}" -o "${output}" || return 1
    
    assert_file_exists "${output}" || return 1
    assert_valid_json "${output}" || return 1
    
    pass
}

test_chrome_preview() {
    print_test "Chrome preview command"
    
    local input="${TESTDATA}/chrome/passwords.csv"
    
    if [[ ! -f "${input}" ]]; then
        skip "Test file not found: ${input}"
        return
    fi
    
    local preview_output
    preview_output=$(run_cxporter_stdout preview -s chrome "${input}")
    
    assert_contains "${preview_output}" "Source: chrome" || return 1
    assert_contains "${preview_output}" "Credentials:" || return 1
    assert_contains "${preview_output}" "4 total" || return 1
    
    pass
}

test_chrome_preview_auto_detect() {
    print_test "Chrome preview with auto-detect"
    
    local input="${TESTDATA}/chrome/passwords.csv"
    
    if [[ ! -f "${input}" ]]; then
        skip "Test file not found: ${input}"
        return
    fi
    
    local preview_output
    preview_output=$(run_cxporter preview "${input}" 2>&1)
    
    assert_contains "${preview_output}" "chrome" || return 1
    assert_contains "${preview_output}" "Credentials:" || return 1
    
    pass
}

test_chrome_invalid_file() {
    print_test "Chrome handles invalid file"
    
    local input
    input=$(temp_file "invalid")
    echo "not,a,valid,chrome,csv" > "${input}"
    
    local output
    output=$(temp_file "chrome-invalid")
    
    # Should fail or produce empty output
    if run_cxporter convert -s chrome "${input}" -o "${output}" 2>/dev/null; then
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

test_chrome_nonexistent_file() {
    print_test "Chrome handles nonexistent file"
    
    local output
    output=$(temp_file "chrome-nofile")
    
    if run_cxporter convert -s chrome "/nonexistent/file.csv" -o "${output}" 2>/dev/null; then
        fail "Should have failed with nonexistent file"
        return 1
    fi
    
    pass
}

test_chrome_credential_fields() {
    print_test "Chrome credential fields mapping"
    
    local input="${TESTDATA}/chrome/passwords.csv"
    local output
    output=$(temp_file "chrome-fields")
    
    if [[ ! -f "${input}" ]]; then
        skip "Test file not found: ${input}"
        return
    fi
    
    run_cxporter convert -s chrome "${input}" -o "${output}" || return 1
    
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

test_chrome_url_mapping() {
    print_test "Chrome URL to scope mapping"
    
    local input="${TESTDATA}/chrome/passwords.csv"
    local output
    output=$(temp_file "chrome-url")
    
    if [[ ! -f "${input}" ]]; then
        skip "Test file not found: ${input}"
        return
    fi
    
    run_cxporter convert -s chrome "${input}" -o "${output}" || return 1
    
    # First item should have a scope with URLs
    local scope_urls
    scope_urls=$(get_json_value "${output}" ".accounts[0].items[0].scope.urls[0]")
    
    if [[ "${scope_urls}" == "null" || -z "${scope_urls}" ]]; then
        fail "Expected scope.urls to be populated"
        return 1
    fi
    
    pass
}

test_chrome_empty_password() {
    print_test "Chrome handles empty password"
    
    local input="${TESTDATA}/chrome/passwords.csv"
    local output
    output=$(temp_file "chrome-empty-pwd")
    
    if [[ ! -f "${input}" ]]; then
        skip "Test file not found: ${input}"
        return
    fi
    
    # The CSV has an entry with empty password
    run_cxporter convert -s chrome "${input}" -o "${output}" || return 1
    
    # Should still create item (4 items total including empty password one)
    local item_count
    item_count=$(json_array_length "${output}" ".accounts[0].items")
    assert_equals "4" "${item_count}" || return 1
    
    pass
}

# Main execution
main() {
    print_header "Chrome Source Integration Tests"
    
    check_binary
    check_jq
    setup_test_env
    
    test_chrome_basic_convert
    test_chrome_stdout
    test_chrome_auto_detect
    test_chrome_edge_cases
    test_chrome_old_format
    test_chrome_preview
    test_chrome_preview_auto_detect
    test_chrome_invalid_file
    test_chrome_nonexistent_file
    test_chrome_credential_fields
    test_chrome_url_mapping
    test_chrome_empty_password
    
    print_summary
}

main "$@"
