#!/bin/bash

# List of extensions to search for
extensions=(
    "mavxvnniint16"
    "mavx10.1"
    "mavx10.1-256"
    "mavx10.1-512"
    "msha512"
    "msm3"
    "msm4"
    "mapxf"
    "musermsr"
    "mavx10.2"
    "mamx-fp8"
    "mamx-tf32"
    "mamx-transpose"
    "mamx-avx512"
    "mamx-movrs"
)

echo "Searching for x86 extensions in Clang documentation..."
echo "=========================================="
echo ""

for ext in "${extensions[@]}"; do
    echo "Extension: -$ext"
    echo "---"
    found=false
    for file in clang-*.html; do
        version=$(echo $file | sed 's/clang-\(.*\)-x86-options.html/\1/')
        if grep -qi "$ext" "$file"; then
            echo "  ✓ Found in Clang $version"
            found=true
        fi
    done
    if [ "$found" = false ]; then
        echo "  ✗ Not found in any version"
    fi
    echo ""
done
