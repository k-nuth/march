#!/bin/bash

# Extensions currently set to None
extensions=(
    "mmxext"
    "xgetbv"
    "umip"
    "sgx"
    "mcommit"
    "rdpru"
    "invpcid"
    "sev"
    "mavxifma"
    "mavxvnniint8"
    "mavxneconvert"
    "mcmpccxadd"
    "mamx-fp16"
    "mprefetchi"
    "mraoint"
    "mamx-complex"
)

versions=("13.0.0" "14.0.0" "15.0.0" "16.0.0" "17.0.1" "18.1.8" "19.1.0" "20.1.0")

echo "Searching for None extensions in Clang documentation..."
echo "========================================================"
echo ""

for ext in "${extensions[@]}"; do
    echo "Extension: $ext"
    min_version=""
    for ver in "${versions[@]}"; do
        file="clang-${ver}-x86-options.html"
        if [ -f "$file" ] && grep -qi "$ext" "$file"; then
            min_version=$ver
            break
        fi
    done
    
    if [ -n "$min_version" ]; then
        major=$(echo $min_version | cut -d. -f1)
        echo "  ✓ Found in: Clang $major ($min_version)"
        # Show context
        file="clang-${min_version}-x86-options.html"
        echo "  Context:"
        grep -i "$ext" "$file" | head -3 | sed 's/^/    /'
    else
        echo "  ✗ Not found in any version"
    fi
    echo ""
done
