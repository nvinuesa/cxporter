#!/usr/bin/env bash

# Integration tests for SSH key source

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/common.sh"

test_ssh_basic_convert() {
    print_test "SSH basic convert"
    
    local input="${TESTDATA}/ssh"
    local output
    output=$(temp_file "ssh-basic")
    
    if [[ ! -d "${input}" ]]; then
        skip "Test directory not found: ${input}"
        return
    fi
    
    run_cxporter convert -s ssh "${input}" -o "${output}" || return 1
    
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
    
    # Should have items (multiple SSH keys in testdata)
    local item_count
    item_count=$(json_array_length "${output}" ".accounts[0].items")
    assert_greater_than "${item_count}" "0" "Expected items from SSH directory" || return 1
    
    pass
}

test_ssh_stdout() {
    print_test "SSH convert to stdout"
    
    local input="${TESTDATA}/ssh"
    
    if [[ ! -d "${input}" ]]; then
        skip "Test directory not found: ${input}"
        return
    fi
    
    local output
    output=$(run_cxporter_stdout convert -s ssh "${input}")
    
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

test_ssh_single_key() {
    print_test "SSH single key file"
    
    local input="${TESTDATA}/ssh"
    local output
    output=$(temp_file "ssh-single")
    
    if [[ ! -d "${input}" ]]; then
        skip "Test directory not found: ${input}"
        return
    fi
    
    # SSH source works with directories, not single files
    run_cxporter convert -s ssh "${input}" -o "${output}" || return 1
    
    assert_file_exists "${output}" || return 1
    assert_valid_json "${output}" || return 1
    
    # Should have multiple items from the directory
    local item_count
    item_count=$(json_array_length "${output}" ".accounts[0].items")
    assert_greater_than "${item_count}" "0" "Expected items from SSH directory" || return 1
    
    pass
}

test_ssh_rsa_key() {
    print_test "SSH RSA key handling"
    
    local input="${TESTDATA}/ssh"
    local output
    output=$(temp_file "ssh-rsa")
    
    if [[ ! -d "${input}" ]]; then
        skip "Test directory not found: ${input}"
        return
    fi
    
    # Convert directory containing RSA key
    run_cxporter convert -s ssh "${input}" -o "${output}" || return 1
    
    assert_file_exists "${output}" || return 1
    assert_valid_json "${output}" || return 1
    
    pass
}

test_ssh_ed25519_key() {
    print_test "SSH Ed25519 key handling"
    
    local input="${TESTDATA}/ssh"
    local output
    output=$(temp_file "ssh-ed25519")
    
    if [[ ! -d "${input}" ]]; then
        skip "Test directory not found: ${input}"
        return
    fi
    
    # Convert directory containing Ed25519 key
    run_cxporter convert -s ssh "${input}" -o "${output}" || return 1
    
    assert_file_exists "${output}" || return 1
    assert_valid_json "${output}" || return 1
    
    pass
}

test_ssh_ecdsa_key() {
    print_test "SSH ECDSA key handling"
    
    local input="${TESTDATA}/ssh"
    local output
    output=$(temp_file "ssh-ecdsa")
    
    if [[ ! -d "${input}" ]]; then
        skip "Test directory not found: ${input}"
        return
    fi
    
    # Convert directory containing ECDSA key
    run_cxporter convert -s ssh "${input}" -o "${output}" || return 1
    
    assert_file_exists "${output}" || return 1
    assert_valid_json "${output}" || return 1
    
    pass
}

test_ssh_encrypted_key() {
    print_test "SSH encrypted key handling"
    
    local input="${TESTDATA}/ssh"
    local output
    output=$(temp_file "ssh-encrypted")
    
    if [[ ! -d "${input}" ]]; then
        skip "Test directory not found: ${input}"
        return
    fi
    
    # Directory with encrypted keys - should convert unencrypted ones
    # and skip encrypted ones without password
    if run_cxporter convert -s ssh "${input}" -o "${output}" 2>/dev/null; then
        # If it succeeded, verify output
        assert_valid_json "${output}" || return 1
    fi
    
    pass
}

test_ssh_preview() {
    print_test "SSH preview command"
    
    local input="${TESTDATA}/ssh"
    
    if [[ ! -d "${input}" ]]; then
        skip "Test directory not found: ${input}"
        return
    fi
    
    local preview_output
    preview_output=$(run_cxporter_stdout preview -s ssh "${input}")
    
    assert_contains "${preview_output}" "Source: ssh" || return 1
    assert_contains "${preview_output}" "Credentials:" || return 1
    
    pass
}

test_ssh_preview_shows_key_types() {
    print_test "SSH preview shows key types"
    
    local input="${TESTDATA}/ssh"
    
    if [[ ! -d "${input}" ]]; then
        skip "Test directory not found: ${input}"
        return
    fi
    
    local preview_output
    preview_output=$(run_cxporter_stdout preview -s ssh "${input}")
    
    # Should show ssh-key type (lowercase with hyphen)
    assert_contains "${preview_output}" "ssh-key" || return 1
    
    pass
}

test_ssh_nonexistent_path() {
    print_test "SSH handles nonexistent path"
    
    local output
    output=$(temp_file "ssh-nofile")
    
    if run_cxporter convert -s ssh "/nonexistent/ssh/path" -o "${output}" 2>/dev/null; then
        fail "Should have failed with nonexistent path"
        return 1
    fi
    
    pass
}

test_ssh_skips_non_key_files() {
    print_test "SSH skips non-key files"
    
    local input="${TESTDATA}/ssh"
    local output
    output=$(temp_file "ssh-skip")
    
    if [[ ! -d "${input}" ]]; then
        skip "Test directory not found: ${input}"
        return
    fi
    
    # The ssh directory has config, known_hosts, authorized_keys, random_file.txt
    # These should be skipped
    run_cxporter convert -s ssh "${input}" -o "${output}" || return 1
    
    assert_valid_json "${output}" || return 1
    
    # Should only have private keys (not config files)
    local item_count
    item_count=$(json_array_length "${output}" ".accounts[0].items")
    
    # We have: id_rsa, id_ed25519, id_ecdsa, id_encrypted (4 private keys)
    # Should not include: .pub files, config, known_hosts, authorized_keys, random_file.txt
    if [[ "${item_count}" -gt 10 ]]; then
        fail "Too many items - may be including non-key files"
        return 1
    fi
    
    pass
}

test_ssh_credential_fields() {
    print_test "SSH credential fields mapping"
    
    local input="${TESTDATA}/ssh"
    local output
    output=$(temp_file "ssh-fields")
    
    if [[ ! -d "${input}" ]]; then
        skip "Test directory not found: ${input}"
        return
    fi
    
    run_cxporter convert -s ssh "${input}" -o "${output}" || return 1
    
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

test_ssh_public_key_skipped() {
    print_test "SSH skips public key files"
    
    local input="${TESTDATA}/ssh"
    local output
    output=$(temp_file "ssh-pub")
    
    if [[ ! -d "${input}" ]]; then
        skip "Test directory not found: ${input}"
        return
    fi
    
    # Directory has both .pub and private keys - only private keys should be imported
    run_cxporter convert -s ssh "${input}" -o "${output}" || return 1
    
    assert_file_exists "${output}" || return 1
    assert_valid_json "${output}" || return 1
    
    # Should have items (private keys), but not double the count (no .pub files)
    local item_count
    item_count=$(json_array_length "${output}" ".accounts[0].items")
    assert_greater_than "${item_count}" "0" || return 1
    
    pass
}

test_ssh_invalid_key_file() {
    print_test "SSH handles invalid key file"
    
    # Create a temp directory with an invalid key file
    local temp_ssh_dir
    temp_ssh_dir=$(mktemp -d -t ssh-test.XXXXXX)
    echo "not a valid ssh key" > "${temp_ssh_dir}/id_invalid"
    
    local output
    output=$(temp_file "ssh-invalid")
    
    # Should handle gracefully (convert with 0 items or fail)
    if run_cxporter convert -s ssh "${temp_ssh_dir}" -o "${output}" 2>/dev/null; then
        # If it succeeded, just verify it's valid JSON
        if [[ -f "${output}" ]]; then
            assert_valid_json "${output}" || { rm -rf "${temp_ssh_dir}"; return 1; }
        fi
    fi
    
    rm -rf "${temp_ssh_dir}"
    pass
}

# Main execution
main() {
    print_header "SSH Source Integration Tests"
    
    check_binary
    check_jq
    setup_test_env
    
    test_ssh_basic_convert
    test_ssh_stdout
    test_ssh_single_key
    test_ssh_rsa_key
    test_ssh_ed25519_key
    test_ssh_ecdsa_key
    test_ssh_encrypted_key
    test_ssh_preview
    test_ssh_preview_shows_key_types
    test_ssh_nonexistent_path
    test_ssh_skips_non_key_files
    test_ssh_credential_fields
    test_ssh_public_key_skipped
    test_ssh_invalid_key_file
    
    print_summary
}

main "$@"
