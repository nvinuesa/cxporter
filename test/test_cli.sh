#!/usr/bin/env bash

# Integration tests for general CLI functionality

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/common.sh"

test_cli_version() {
    print_test "CLI version command"
    
    local output
    output=$(run_cxporter_stdout version)
    
    assert_contains "${output}" "cxporter" || return 1
    
    pass
}

test_cli_help() {
    print_test "CLI help command"
    
    local output
    output=$(run_cxporter_stdout --help)
    
    assert_contains "${output}" "cxporter" || return 1
    assert_contains "${output}" "convert" || return 1
    assert_contains "${output}" "preview" || return 1
    
    pass
}

test_cli_convert_help() {
    print_test "CLI convert help"
    
    local output
    output=$(run_cxporter_stdout convert --help)
    
    assert_contains "${output}" "convert" || return 1
    assert_contains "${output}" "source" || return 1
    assert_contains "${output}" "output" || return 1
    
    pass
}

test_cli_preview_help() {
    print_test "CLI preview help"
    
    local output
    output=$(run_cxporter_stdout preview --help)
    
    assert_contains "${output}" "preview" || return 1
    assert_contains "${output}" "source" || return 1
    
    pass
}

test_cli_no_args() {
    print_test "CLI with no arguments shows help"
    
    local output
    output=$(run_cxporter_stdout 2>&1 || true)
    
    assert_contains "${output}" "cxporter" || return 1
    
    pass
}

test_cli_invalid_command() {
    print_test "CLI handles invalid command"
    
    if run_cxporter invalidcommand 2>/dev/null; then
        fail "Should have failed with invalid command"
        return 1
    fi
    
    pass
}

test_cli_convert_no_input() {
    print_test "CLI convert with no input shows help"
    
    local output
    output=$(run_cxporter_stdout convert 2>&1 || true)
    
    # Should show help or usage information
    assert_contains "${output}" "convert" || return 1
    
    pass
}

test_cli_unknown_source() {
    print_test "CLI handles unknown source type"
    
    local input
    input=$(temp_file "dummy.txt")
    echo "dummy" > "${input}"
    
    local output
    output=$(temp_file "cli-unknown")
    
    if run_cxporter convert -s unknownsource "${input}" -o "${output}" 2>/dev/null; then
        fail "Should have failed with unknown source"
        return 1
    fi
    
    pass
}

test_cli_output_file_creation() {
    print_test "CLI creates output file"
    
    local input="${TESTDATA}/chrome/passwords.csv"
    local output
    output=$(temp_file "cli-output")
    
    if [[ ! -f "${input}" ]]; then
        skip "Test file not found: ${input}"
        return
    fi
    
    # Remove output file to ensure it's created fresh
    rm -f "${output}"
    
    run_cxporter convert -s chrome "${input}" -o "${output}" || return 1
    
    assert_file_exists "${output}" || return 1
    assert_file_not_empty "${output}" || return 1
    
    pass
}

test_cli_stdout_redirect() {
    print_test "CLI stdout redirect works"
    
    local input="${TESTDATA}/chrome/passwords.csv"
    local output
    output=$(temp_file "cli-redirect")
    
    if [[ ! -f "${input}" ]]; then
        skip "Test file not found: ${input}"
        return
    fi
    
    run_cxporter convert -s chrome "${input}" > "${output}" 2>/dev/null || return 1
    
    assert_file_exists "${output}" || return 1
    assert_file_not_empty "${output}" || return 1
    assert_valid_json "${output}" || return 1
    
    pass
}

test_cli_multiple_conversions() {
    print_test "CLI handles multiple sequential conversions"
    
    local chrome_input="${TESTDATA}/chrome/passwords.csv"
    local firefox_input="${TESTDATA}/firefox/logins.csv"
    
    if [[ ! -f "${chrome_input}" ]]; then
        skip "Chrome test file not found"
        return
    fi
    
    if [[ ! -f "${firefox_input}" ]]; then
        skip "Firefox test file not found"
        return
    fi
    
    local output1
    output1=$(temp_file "cli-multi1")
    local output2
    output2=$(temp_file "cli-multi2")
    
    run_cxporter convert -s chrome "${chrome_input}" -o "${output1}" || return 1
    run_cxporter convert -s firefox "${firefox_input}" -o "${output2}" || return 1
    
    assert_file_exists "${output1}" || return 1
    assert_file_exists "${output2}" || return 1
    assert_valid_json "${output1}" || return 1
    assert_valid_json "${output2}" || return 1
    
    pass
}

test_cli_overwrite_output() {
    print_test "CLI overwrites existing output file"
    
    local input="${TESTDATA}/chrome/passwords.csv"
    local output
    output=$(temp_file "cli-overwrite")
    
    if [[ ! -f "${input}" ]]; then
        skip "Test file not found: ${input}"
        return
    fi
    
    # Create initial output
    echo "old content" > "${output}"
    
    # Convert and overwrite
    run_cxporter convert -s chrome "${input}" -o "${output}" || return 1
    
    assert_file_exists "${output}" || return 1
    
    # Verify it's valid JSON (not old content)
    assert_valid_json "${output}" || return 1
    
    pass
}

test_cli_filter_flag() {
    print_test "CLI filter flag"
    
    local input="${TESTDATA}/chrome/passwords.csv"
    local output
    output=$(temp_file "cli-filter")
    
    if [[ ! -f "${input}" ]]; then
        skip "Test file not found: ${input}"
        return
    fi
    
    # Filter for "example" - should match some entries
    run_cxporter convert -s chrome "${input}" -f "example" -o "${output}" || return 1
    
    assert_file_exists "${output}" || return 1
    assert_valid_json "${output}" || return 1
    
    pass
}

test_cli_preview_filter() {
    print_test "CLI preview with filter"
    
    local input="${TESTDATA}/chrome/passwords.csv"
    
    if [[ ! -f "${input}" ]]; then
        skip "Test file not found: ${input}"
        return
    fi
    
    local preview_output
    preview_output=$(run_cxporter_stdout preview -s chrome "${input}" -f "example")
    
    assert_contains "${preview_output}" "Filtered:" || return 1
    
    pass
}

test_cli_empty_filter() {
    print_test "CLI handles filter with no matches"
    
    local input="${TESTDATA}/chrome/passwords.csv"
    local output
    output=$(temp_file "cli-empty-filter")
    
    if [[ ! -f "${input}" ]]; then
        skip "Test file not found: ${input}"
        return
    fi
    
    # Filter for something that won't match - may not create output file
    if run_cxporter convert -s chrome "${input}" -f "xyznonexistent123" -o "${output}" 2>/dev/null; then
        # If it created output, verify it's valid JSON
        if [[ -f "${output}" ]]; then
            assert_valid_json "${output}" || return 1
        fi
    fi
    
    # Either way (file created or not), test passes
    pass
}

test_cli_source_flag_variations() {
    print_test "CLI accepts source flag variations"
    
    local input="${TESTDATA}/chrome/passwords.csv"
    local output1
    output1=$(temp_file "cli-s1")
    local output2
    output2=$(temp_file "cli-s2")
    
    if [[ ! -f "${input}" ]]; then
        skip "Test file not found: ${input}"
        return
    fi
    
    # Both -s and --source should work
    run_cxporter convert -s chrome "${input}" -o "${output1}" || return 1
    run_cxporter convert --source chrome "${input}" -o "${output2}" || return 1
    
    assert_file_exists "${output1}" || return 1
    assert_file_exists "${output2}" || return 1
    
    pass
}

test_cli_output_flag_variations() {
    print_test "CLI accepts output flag variations"
    
    local input="${TESTDATA}/chrome/passwords.csv"
    local output1
    output1=$(temp_file "cli-o1")
    local output2
    output2=$(temp_file "cli-o2")
    
    if [[ ! -f "${input}" ]]; then
        skip "Test file not found: ${input}"
        return
    fi
    
    # Both -o and --output should work
    run_cxporter convert -s chrome "${input}" -o "${output1}" || return 1
    run_cxporter convert -s chrome "${input}" --output "${output2}" || return 1
    
    assert_file_exists "${output1}" || return 1
    assert_file_exists "${output2}" || return 1
    
    pass
}

test_cli_exit_codes() {
    print_test "CLI returns proper exit codes"
    
    # Success case
    local input="${TESTDATA}/chrome/passwords.csv"
    local output
    output=$(temp_file "cli-exit")
    
    if [[ ! -f "${input}" ]]; then
        skip "Test file not found: ${input}"
        return
    fi
    
    if ! run_cxporter convert -s chrome "${input}" -o "${output}" 2>/dev/null; then
        fail "Successful conversion should return 0"
        return 1
    fi
    
    # Failure case
    if run_cxporter convert -s chrome "/nonexistent.csv" -o "${output}" 2>/dev/null; then
        fail "Failed conversion should return non-zero"
        return 1
    fi
    
    pass
}

test_cli_error_messages_to_stderr() {
    print_test "CLI writes errors to stderr"
    
    local stderr_output
    stderr_output=$(run_cxporter_stderr convert -s chrome "/nonexistent.csv" 2>&1 || true)
    
    # Should have some error message
    if [[ -z "${stderr_output}" ]]; then
        fail "Expected error message on stderr"
        return 1
    fi
    
    pass
}

test_cli_concurrent_conversions() {
    print_test "CLI handles concurrent conversions"
    
    local input="${TESTDATA}/chrome/passwords.csv"
    
    if [[ ! -f "${input}" ]]; then
        skip "Test file not found: ${input}"
        return
    fi
    
    local output1
    output1=$(temp_file "cli-concurrent1")
    local output2
    output2=$(temp_file "cli-concurrent2")
    local output3
    output3=$(temp_file "cli-concurrent3")
    
    # Run three conversions in parallel
    run_cxporter convert -s chrome "${input}" -o "${output1}" &
    local pid1=$!
    run_cxporter convert -s chrome "${input}" -o "${output2}" &
    local pid2=$!
    run_cxporter convert -s chrome "${input}" -o "${output3}" &
    local pid3=$!
    
    # Wait for all to complete
    wait ${pid1} || return 1
    wait ${pid2} || return 1
    wait ${pid3} || return 1
    
    assert_file_exists "${output1}" || return 1
    assert_file_exists "${output2}" || return 1
    assert_file_exists "${output3}" || return 1
    assert_valid_json "${output1}" || return 1
    assert_valid_json "${output2}" || return 1
    assert_valid_json "${output3}" || return 1
    
    pass
}

# Generate a random X25519 public key for testing encryption
generate_test_pubkey() {
    openssl rand -base64 32
}

test_cli_encrypt_produces_cxp_response() {
    print_test "CLI encrypt produces CXP ExportResponse JSON"

    local input="${TESTDATA}/chrome/passwords.csv"
    local output
    output=$(temp_file "cli-encrypt-response")
    local pubkey
    pubkey=$(generate_test_pubkey)

    if [[ ! -f "${input}" ]]; then
        skip "Test file not found: ${input}"
        return
    fi

    # Generate encrypted output
    run_cxporter convert -s chrome "${input}" --encrypt --recipient-key "${pubkey}" -o "${output}" 2>/dev/null || return 1

    # Verify output is valid JSON (not raw binary)
    assert_valid_json "${output}" || return 1

    pass
}

test_cli_encrypt_has_version_field() {
    print_test "CLI encrypt output has version field"

    local input="${TESTDATA}/chrome/passwords.csv"
    local output
    output=$(temp_file "cli-encrypt-version")
    local pubkey
    pubkey=$(generate_test_pubkey)

    if [[ ! -f "${input}" ]]; then
        skip "Test file not found: ${input}"
        return
    fi

    run_cxporter convert -s chrome "${input}" --encrypt --recipient-key "${pubkey}" -o "${output}" 2>/dev/null || return 1

    assert_json_has_key "${output}" ".version" || return 1

    pass
}

test_cli_encrypt_has_hpke_field() {
    print_test "CLI encrypt output has hpke field with sub-fields"

    local input="${TESTDATA}/chrome/passwords.csv"
    local output
    output=$(temp_file "cli-encrypt-hpke")
    local pubkey
    pubkey=$(generate_test_pubkey)

    if [[ ! -f "${input}" ]]; then
        skip "Test file not found: ${input}"
        return
    fi

    run_cxporter convert -s chrome "${input}" --encrypt --recipient-key "${pubkey}" -o "${output}" 2>/dev/null || return 1

    assert_json_has_key "${output}" ".hpke" || return 1
    assert_json_has_key "${output}" ".hpke.mode" || return 1
    assert_json_has_key "${output}" ".hpke.kem" || return 1
    assert_json_has_key "${output}" ".hpke.kdf" || return 1
    assert_json_has_key "${output}" ".hpke.aead" || return 1

    pass
}

test_cli_encrypt_has_exporter_field() {
    print_test "CLI encrypt output has exporter field"

    local input="${TESTDATA}/chrome/passwords.csv"
    local output
    output=$(temp_file "cli-encrypt-exporter")
    local pubkey
    pubkey=$(generate_test_pubkey)

    if [[ ! -f "${input}" ]]; then
        skip "Test file not found: ${input}"
        return
    fi

    run_cxporter convert -s chrome "${input}" --encrypt --recipient-key "${pubkey}" -o "${output}" 2>/dev/null || return 1

    assert_json_has_key "${output}" ".exporter" || return 1

    local exporter
    exporter=$(get_json_value "${output}" ".exporter")
    if [[ -z "${exporter}" || "${exporter}" == "null" ]]; then
        fail "exporter field is empty"
        return 1
    fi

    pass
}

test_cli_encrypt_has_payload_field() {
    print_test "CLI encrypt output has base64url payload field"

    local input="${TESTDATA}/chrome/passwords.csv"
    local output
    output=$(temp_file "cli-encrypt-payload")
    local pubkey
    pubkey=$(generate_test_pubkey)

    if [[ ! -f "${input}" ]]; then
        skip "Test file not found: ${input}"
        return
    fi

    run_cxporter convert -s chrome "${input}" --encrypt --recipient-key "${pubkey}" -o "${output}" 2>/dev/null || return 1

    assert_json_has_key "${output}" ".payload" || return 1

    local payload
    payload=$(get_json_value "${output}" ".payload")
    if [[ -z "${payload}" || "${payload}" == "null" ]]; then
        fail "payload field is empty"
        return 1
    fi

    # Verify it's base64url encoded (no + or / characters, may have - and _)
    if [[ "${payload}" =~ [+/] ]]; then
        fail "payload contains non-base64url characters"
        return 1
    fi

    pass
}

test_cli_encrypt_requires_recipient_key() {
    print_test "CLI encrypt requires recipient key"

    local input="${TESTDATA}/chrome/passwords.csv"
    local output
    output=$(temp_file "cli-encrypt-nokey")

    if [[ ! -f "${input}" ]]; then
        skip "Test file not found: ${input}"
        return
    fi

    # Should fail without recipient key
    if run_cxporter convert -s chrome "${input}" --encrypt -o "${output}" 2>/dev/null; then
        fail "Should have failed without recipient key"
        return 1
    fi

    pass
}

test_cli_encrypt_stdout() {
    print_test "CLI encrypt to stdout produces valid JSON"

    local input="${TESTDATA}/chrome/passwords.csv"
    local pubkey
    pubkey=$(generate_test_pubkey)

    if [[ ! -f "${input}" ]]; then
        skip "Test file not found: ${input}"
        return
    fi

    local json_output
    json_output=$(run_cxporter_stdout convert -s chrome "${input}" --encrypt --recipient-key "${pubkey}")

    # Verify output is valid JSON
    if ! echo "${json_output}" | jq empty 2>/dev/null; then
        fail "stdout output is not valid JSON"
        return 1
    fi

    # Verify it has required fields
    if ! echo "${json_output}" | jq -e '.version' >/dev/null 2>&1; then
        fail "stdout output missing version field"
        return 1
    fi

    pass
}

# Main execution
main() {
    print_header "General CLI Integration Tests"

    check_binary
    check_jq
    setup_test_env

    test_cli_version
    test_cli_help
    test_cli_convert_help
    test_cli_preview_help
    test_cli_no_args
    test_cli_invalid_command
    test_cli_convert_no_input
    test_cli_unknown_source
    test_cli_output_file_creation
    test_cli_stdout_redirect
    test_cli_multiple_conversions
    test_cli_overwrite_output
    test_cli_filter_flag
    test_cli_preview_filter
    test_cli_empty_filter
    test_cli_source_flag_variations
    test_cli_output_flag_variations
    test_cli_exit_codes
    test_cli_error_messages_to_stderr
    test_cli_concurrent_conversions

    # CXP encrypted response tests
    test_cli_encrypt_produces_cxp_response
    test_cli_encrypt_has_version_field
    test_cli_encrypt_has_hpke_field
    test_cli_encrypt_has_exporter_field
    test_cli_encrypt_has_payload_field
    test_cli_encrypt_requires_recipient_key
    test_cli_encrypt_stdout

    print_summary
}

main "$@"
