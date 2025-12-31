#!/bin/bash
# Basic conversion examples for cxporter

set -e

echo "cxporter Basic Conversion Examples"
echo "==================================="

# Convert Chrome passwords
if [ -f "passwords.csv" ]; then
    echo "Converting Chrome passwords..."
    cxporter convert -s chrome -i passwords.csv -o chrome-creds.cxf.json
    echo "Created: chrome-creds.cxf.json"
fi

# Convert Firefox passwords
if [ -f "logins.csv" ]; then
    echo "Converting Firefox passwords..."
    cxporter convert -s firefox -i logins.csv -o firefox-creds.cxf.json
    echo "Created: firefox-creds.cxf.json"
fi

# Convert Bitwarden export
if [ -f "bitwarden.json" ]; then
    echo "Converting Bitwarden export..."
    cxporter convert -s bitwarden -i bitwarden.json -o bitwarden-creds.cxf.json
    echo "Created: bitwarden-creds.cxf.json"
fi

# Convert SSH keys
if [ -d "$HOME/.ssh" ]; then
    echo "Converting SSH keys..."
    cxporter convert -s ssh -i "$HOME/.ssh" -o ssh-keys.cxf.json
    echo "Created: ssh-keys.cxf.json"
fi

echo ""
echo "Done! Check the .cxf.json files for your exported credentials."
