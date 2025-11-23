#!/bin/bash

# Extensions currently set to None in GCC
extensions=(
    "mmxext"
    "xgetbv"
    "umip"
    "sgx"
    "mcommit"
    "rdpru"
    "invpcid"
    "sev"
)

versions=("5.5.0" "6.5.0" "7.5.0" "8.5.0" "9.5.0" "10.4.0" "11.3.0" "12.1.0" "13.4.0" "14.3.0" "15.2.0")

echo "Searching for None extensions in GCC documentation..."
echo "====================================================="
echo ""

for ext in "${extensions[@]}"; do
    echo "Extension: $ext"
    min_version=""
    for ver in "${versions[@]}"; do
        file="gcc-${ver}-x86-options.html"
        if [ -f "$file" ] && grep -qi "\-m${ext}" "$file"; then
            min_version=$ver
            break
        fi
    done
    
    if [ -n "$min_version" ]; then
        major=$(echo $min_version | cut -d. -f1)
        echo "  ✓ Found in: GCC $major ($min_version)"
        # Show context
        file="gcc-${min_version}-x86-options.html"
        echo "  Context:"
        grep -i "\-m${ext}" "$file" | head -2 | sed 's/^/    /' | sed 's/<[^>]*>//g'
    else
        echo "  ✗ Not found in any version"
    fi
    echo ""
done
