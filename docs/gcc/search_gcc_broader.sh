#!/bin/bash

# Search more broadly
extensions=(
    "mmxext:3dnowa:3dnow"
    "xgetbv:xsave"
    "umip:user.mode"
    "sgx:Software.Guard"
    "mcommit:commit"
    "rdpru:RDPRU"
    "invpcid:INVPCID"
    "sev:SEV:snp"
)

versions=("5.5.0" "6.5.0" "7.5.0" "8.5.0" "9.5.0" "10.4.0" "11.3.0" "12.1.0" "13.4.0" "14.3.0" "15.2.0")

echo "Broader search for None extensions in GCC documentation..."
echo "=========================================================="
echo ""

for ext_pattern in "${extensions[@]}"; do
    IFS=':' read -ra patterns <<< "$ext_pattern"
    ext_name="${patterns[0]}"
    
    echo "Extension: $ext_name"
    min_version=""
    found_pattern=""
    
    for ver in "${versions[@]}"; do
        file="gcc-${ver}-x86-options.html"
        if [ -f "$file" ]; then
            for pattern in "${patterns[@]}"; do
                if grep -qi "$pattern" "$file"; then
                    min_version=$ver
                    found_pattern=$pattern
                    break 2
                fi
            done
        fi
    done
    
    if [ -n "$min_version" ]; then
        major=$(echo $min_version | cut -d. -f1)
        echo "  ✓ Found '$found_pattern' in: GCC $major ($min_version)"
    else
        echo "  ✗ Not found in any version"
    fi
    echo ""
done
