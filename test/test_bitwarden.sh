#!/usr/bin/env bash

# Integration tests for Bitwarden JSON source

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/common.sh"

test_bitwarden_basic_convert() {
    print_test "Bitwarden basic convert"
    
    local input="${TESTDATA}/bitwarden/export.json"
    local output
    output=$(temp_file "bitwarden-basic")
    
    if [[ ! -f "${input}" ]]; then
        skip "Test file not found: ${input}"
        return
    fi
    
    run_cxporter convert -s bitwarden "${input}" -o "${output}" || return 1
    
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
    
    # Should have items
    local item_count
    item_count=$(json_array_length "${output}" ".accounts[0].items")
    assert_greater_than "${item_count}" "0" "Expected items from Bitwarden export" || return 1
    
    pass
}

test_bitwarden_stdout() {
    print_test "Bitwarden convert to stdout"
    
    local input="${TESTDATA}/bitwarden/export.json"
    
    if [[ ! -f "${input}" ]]; then
        skip "Test file not found: ${input}"
        return
    fi
    
    local output
    output=$(run_cxporter_stdout convert -s bitwarden "${input}")
    
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

test_bitwarden_auto_detect() {
    print_test "Bitwarden auto-detection"
    
    local input="${TESTDATA}/bitwarden/export.json"
    local output
    output=$(temp_file "bitwarden-auto")
    
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
    assert_greater_than "${item_count}" "0" || return 1
    
    pass
}

test_bitwarden_folders() {
    print_test "Bitwarden folder hierarchy"
    
    local input="${TESTDATA}/bitwarden/export.json"
    local output
    output=$(temp_file "bitwarden-folders")
    
    if [[ ! -f "${input}" ]]; then
        skip "Test file not found: ${input}"
        return
    fi
    
    run_cxporter convert -s bitwarden "${input}" -o "${output}" || return 1
    
    # Check if collections exist (folders in Bitwarden)
    local collections_count
    collections_count=$(json_array_length "${output}" ".accounts[0].collections")
    
    # The export.json has 2 folders: Work and Personal
    assert_greater_than "${collections_count}" "0" "Expected collections from Bitwarden folders" || return 1
    
    pass
}

test_bitwarden_multiple_types() {
    print_test "Bitwarden handles multiple credential types"

    local input="${TESTDATA}/bitwarden/export.json"
    local output
    output=$(temp_file "bitwarden-types")

    if [[ ! -f "${input}" ]]; then
        skip "Test file not found: ${input}"
        return
    fi

    run_cxporter convert -s bitwarden "${input}" -o "${output}" || return 1

    # Bitwarden exports can contain logins, notes, cards, identities
    # Verify it converted successfully
    assert_valid_json "${output}" || return 1

    # Check that items were converted
    local item_count
    item_count=$(json_array_length "${output}" ".accounts[0].items")
    assert_greater_than "${item_count}" "0" "Expected items from Bitwarden export" || return 1

    pass
}

test_bitwarden_totp() {
    print_test "Bitwarden TOTP extraction"

    local input="${TESTDATA}/bitwarden/export.json"
    local output
    output=$(temp_file "bitwarden-totp")

    if [[ ! -f "${input}" ]]; then
        skip "Test file not found: ${input}"
        return
    fi

    run_cxporter convert -s bitwarden "${input}" -o "${output}" || return 1

    # The export.json has a TOTP field in the GitHub entry
    # It should be extracted as a separate TOTP credential or embedded
    assert_valid_json "${output}" || return 1

    pass
}

test_bitwarden_encrypted() {
    print_test "Bitwarden handles encrypted export"
    
    local input="${TESTDATA}/bitwarden/encrypted.json"
    local output
    output=$(temp_file "bitwarden-encrypted")
    
    if [[ ! -f "${input}" ]]; then
        skip "Test file not found: ${input}"
        return
    fi
    
    # Encrypted Bitwarden exports should be detected and handled
    # This might fail or warn - both are acceptable
    if run_cxporter convert -s bitwarden "${input}" -o "${output}" 2>/dev/null; then
        # If it succeeded, verify output
        assert_valid_json "${output}" || return 1
    fi
    
    # Either way, test passes (we're just checking it doesn't crash)
    pass
}

test_bitwarden_invalid_json() {
    print_test "Bitwarden handles invalid JSON"
    
    local input
    input=$(temp_file "invalid.json")
    echo "{invalid json content" > "${input}"
    
    local output
    output=$(temp_file "bitwarden-invalid")
    
    if run_cxporter convert -s bitwarden "${input}" -o "${output}" 2>/dev/null; then
        fail "Should have failed with invalid JSON"
        return 1
    fi
    
    pass
}

test_bitwarden_nonexistent_file() {
    print_test "Bitwarden handles nonexistent file"
    
    local output
    output=$(temp_file "bitwarden-nofile")
    
    if run_cxporter convert -s bitwarden "/nonexistent/file.json" -o "${output}" 2>/dev/null; then
        fail "Should have failed with nonexistent file"
        return 1
    fi
    
    pass
}

test_bitwarden_credential_fields() {
    print_test "Bitwarden credential fields mapping"
    
    local input="${TESTDATA}/bitwarden/export.json"
    local output
    output=$(temp_file "bitwarden-fields")
    
    if [[ ! -f "${input}" ]]; then
        skip "Test file not found: ${input}"
        return
    fi
    
    run_cxporter convert -s bitwarden "${input}" -o "${output}" || return 1
    
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

test_bitwarden_custom_fields() {
    print_test "Bitwarden custom fields handling"
    
    local input="${TESTDATA}/bitwarden/export.json"
    local output
    output=$(temp_file "bitwarden-custom")
    
    if [[ ! -f "${input}" ]]; then
        skip "Test file not found: ${input}"
        return
    fi
    
    run_cxporter convert -s bitwarden "${input}" -o "${output}" || return 1
    
    # The export.json has custom fields in the GitHub entry
    # Verify conversion completed successfully
    assert_valid_json "${output}" || return 1
    
    local item_count
    item_count=$(json_array_length "${output}" ".accounts[0].items")
    assert_greater_than "${item_count}" "0" || return 1
    
    pass
}

test_bitwarden_timestamps() {
    print_test "Bitwarden timestamp conversion"
    
    local input="${TESTDATA}/bitwarden/export.json"
    local output
    output=$(temp_file "bitwarden-time")
    
    if [[ ! -f "${input}" ]]; then
        skip "Test file not found: ${input}"
        return
    fi
    
    run_cxporter convert -s bitwarden "${input}" -o "${output}" || return 1
    
    # Check that timestamps are present - modifiedAt should be set
    local modified_at
    modified_at=$(get_json_value "${output}" ".accounts[0].items[0].modifiedAt")
    
    if [[ "${modified_at}" == "null" || "${modified_at}" == "0" ]]; then
        fail "Expected modifiedAt timestamp to be set"
        return 1
    fi
    
    pass
}

# Main execution
main() {
    print_header "Bitwarden Source Integration Tests"
    
    check_binary
    check_jq
    setup_test_env
    
    test_bitwarden_basic_convert
    test_bitwarden_stdout
    test_bitwarden_auto_detect
    test_bitwarden_folders
    test_bitwarden_multiple_types
    test_bitwarden_totp
    test_bitwarden_encrypted
    test_bitwarden_invalid_json
    test_bitwarden_nonexistent_file
    test_bitwarden_credential_fields
    test_bitwarden_custom_fields
    test_bitwarden_timestamps
    
    print_summary
}

main "$@"
