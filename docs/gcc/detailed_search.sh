#!/bin/bash

echo "Detailed search for specific GCC flags..."
echo "=========================================="
echo ""

# Search for invlpgb
echo "1. invlpgb / INVLPGB:"
grep -h "invlpgb\|INVLPGB" gcc-*.html 2>/dev/null | head -3 || echo "  Not found"

echo ""
echo "2. mmxext / MMXEXT:"
grep -h "mmxext\|MMXEXT" gcc-*.html 2>/dev/null | head -3 || echo "  Not found"

echo ""
echo "3. umip / UMIP:"
grep -h "\-m.*umip\|UMIP" gcc-*.html 2>/dev/null | head -3 || echo "  Not found"

echo ""
echo "4. sgx_lc / SGX_LC / Launch Control:"
grep -h "sgx_lc\|SGX_LC\|launch.*control\|Launch.*Control" gcc-*.html 2>/dev/null | head -3 || echo "  Not found"

echo ""
echo "5. mcommit / MCOMMIT:"
grep -h "\-m.*mcommit\|MCOMMIT" gcc-*.html 2>/dev/null | head -3 || echo "  Not found"

echo ""
echo "6. rdpru / RDPRU:"
grep -h "\-m.*rdpru\|RDPRU" gcc-*.html 2>/dev/null | head -3 || echo "  Not found"

echo ""
echo "7. invpcid / INVPCID:"
grep -h "\-m.*invpcid\|INVPCID" gcc-*.html 2>/dev/null | head -3 || echo "  Not found"

echo ""
echo "8. sev_snp / SEV-SNP:"
grep -h "sev.*snp\|SEV.*SNP\|sev-snp" gcc-*.html 2>/dev/null | head -3 || echo "  Not found"

echo ""
echo "9. xgetbv_ecx1:"
grep -h "xgetbv.*ecx\|XGETBV.*ECX" gcc-*.html 2>/dev/null | head -3 || echo "  Not found"

