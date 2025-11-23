#!/bin/bash

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

versions=("13.0.0" "14.0.0" "15.0.0" "16.0.0" "17.0.1" "18.1.8" "19.1.0" "20.1.0")

echo "Finding MINIMUM version for each extension..."
echo "=============================================="
echo ""

for ext in "${extensions[@]}"; do
    echo "Extension: -$ext"
    min_version=""
    for ver in "${versions[@]}"; do
        file="clang-${ver}-x86-options.html"
        if [ -f "$file" ] && grep -qi "$ext" "$file"; then
            min_version=$ver
            break
        fi
    done
    
    if [ -n "$min_version" ]; then
        # Extract major version number
        major=$(echo $min_version | cut -d. -f1)
        echo "  ✓ Minimum version: Clang $major ($min_version)"
    else
        echo "  ✗ Not found in any version"
    fi
    echo ""
done
