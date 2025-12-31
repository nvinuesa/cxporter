#!/bin/bash
# Encrypted export example for cxporter

set -e

echo "cxporter Encrypted Export Example"
echo "=================================="

# Check for required files
if [ ! -f "public.key" ]; then
    echo "Error: public.key not found"
    echo ""
    echo "Generate a keypair first:"
    echo "  openssl genpkey -algorithm X25519 -out private.pem"
    echo "  openssl pkey -in private.pem -pubout -out public.pem"
    echo "  openssl pkey -in public.pem -pubin -outform DER | tail -c 32 | base64 > public.key"
    exit 1
fi

# Read public key
PUBKEY=$(cat public.key)
echo "Using public key: ${PUBKEY:0:16}..."

# Find a source file
if [ -f "passwords.csv" ]; then
    SOURCE="-s chrome -i passwords.csv"
    OUTPUT="chrome-creds.cxp"
elif [ -f "bitwarden.json" ]; then
    SOURCE="-s bitwarden -i bitwarden.json"
    OUTPUT="bitwarden-creds.cxp"
else
    echo "Error: No source file found (passwords.csv or bitwarden.json)"
    exit 1
fi

# Create encrypted export
echo "Creating encrypted CXP archive..."
cxporter convert $SOURCE -o "$OUTPUT" --encrypt --recipient-key "$PUBKEY"

echo ""
echo "Created: $OUTPUT"
echo ""
echo "The CXP archive is encrypted and can only be decrypted"
echo "with the corresponding private key (private.pem)."
