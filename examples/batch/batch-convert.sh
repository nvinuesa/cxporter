#!/bin/bash
# Batch conversion script for cxporter
# Converts all supported files in a directory

set -e

# Configuration
INPUT_DIR="${1:-.}"
OUTPUT_DIR="${2:-./cxf-output}"

echo "cxporter Batch Conversion"
echo "========================="
echo "Input directory: $INPUT_DIR"
echo "Output directory: $OUTPUT_DIR"
echo ""

# Create output directory
mkdir -p "$OUTPUT_DIR"

# Counter
CONVERTED=0
FAILED=0

# Process Chrome CSV files
for file in "$INPUT_DIR"/*.csv; do
    [ -e "$file" ] || continue

    basename=$(basename "$file" .csv)
    output="$OUTPUT_DIR/$basename.cxf.json"

    echo "Processing: $file"

    # Try Chrome format first, then Firefox
    if cxporter convert -i "$file" -o "$output" -q 2>/dev/null; then
        echo "  -> Created: $output"
        ((CONVERTED++))
    else
        echo "  -> Failed (skipping)"
        ((FAILED++))
    fi
done

# Process Bitwarden JSON files
for file in "$INPUT_DIR"/*.json; do
    [ -e "$file" ] || continue

    basename=$(basename "$file" .json)
    output="$OUTPUT_DIR/$basename.cxf.json"

    echo "Processing: $file"

    if cxporter convert -s bitwarden -i "$file" -o "$output" -q 2>/dev/null; then
        echo "  -> Created: $output"
        ((CONVERTED++))
    else
        echo "  -> Failed (skipping)"
        ((FAILED++))
    fi
done

# Process KeePass databases
for file in "$INPUT_DIR"/*.kdbx; do
    [ -e "$file" ] || continue

    basename=$(basename "$file" .kdbx)
    output="$OUTPUT_DIR/$basename.cxf.json"

    echo "Processing: $file"
    echo "  Note: KeePass files require password input"

    if cxporter convert -s keepass -i "$file" -o "$output" 2>/dev/null; then
        echo "  -> Created: $output"
        ((CONVERTED++))
    else
        echo "  -> Failed (skipping)"
        ((FAILED++))
    fi
done

echo ""
echo "Summary"
echo "-------"
echo "Converted: $CONVERTED"
echo "Failed: $FAILED"
echo "Output: $OUTPUT_DIR"
