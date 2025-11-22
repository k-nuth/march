# microarch

[![PyPI version](https://badge.fury.io/py/microarch.svg)](https://badge.fury.io/py/microarch)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

**CPU Microarchitecture Detection and Feature Management for x86/x64**

A Python library for detecting x86/x64 CPU microarchitecture features and generating optimal compiler flags. Part of the [Knuth](https://github.com/k-nuth) project ecosystem.

> **⚠️ x86/x64 ONLY**: This library uses the CPUID instruction which is **exclusive to x86/x64 processors**. It will **NOT work on ARM** processors (Apple Silicon M1/M2/M3, Raspberry Pi, AWS Graviton, etc.).

## Features

- **CPU Feature Detection** - Detect support for SSE, AVX, AVX2, BMI, and more
- **x86-64 Microarchitecture Levels** - Identify v1 (baseline), v2, v3, v4 support
- **Compiler Flag Generation** - Generate optimal `-march` flags for GCC, Clang, MSVC
- **Conan Integration** - Generate Conan compiler settings automatically
- **Vendor Detection** - Identify Intel, AMD, and VIA processors
- **Zero Dependencies** - Only depends on [`cpuid`](https://github.com/fpelliccioni/cpuid-py) for hardware access

## Installation

```bash
pip install microarch
```

## Quick Start

```python
import microarch

# Detect CPU vendor
vendor = microarch.get_cpu_vendor()
print(f"CPU Vendor: {vendor}")  # e.g., "GenuineIntel" or "AuthenticAMD"

# Check specific CPU features
print(f"AVX Support: {microarch.support_avx()}")
print(f"AVX2 Support: {microarch.support_avx2()}")
print(f"BMI2 Support: {microarch.support_bmi2()}")

# Check x86-64 microarchitecture level support
print(f"x86-64-v1 (baseline): {microarch.support_level1_features()}")
print(f"x86-64-v2: {microarch.support_level2_features()}")
print(f"x86-64-v3: {microarch.support_level3_features()}")
print(f"x86-64-v4: {microarch.support_level4_features()}")

# Get optimal compiler march flag
march = microarch.get_march_conan("Linux", "gcc", "x86_64")
print(f"Optimal -march flag: {march}")
```

## CPU Feature Detection

### Level 1 (x86-64 baseline)
```python
microarch.support_long_mode()  # 64-bit support
microarch.support_cmov()       # Conditional move
microarch.support_cx8()        # CMPXCHG8B
microarch.support_fpu()        # x87 FPU
microarch.support_fxsr()       # FXSAVE/FXRSTOR
microarch.support_mmx()        # MMX
microarch.support_sse()        # SSE
microarch.support_sse2()       # SSE2
```

### Level 2 (x86-64-v2)
```python
microarch.support_cx16()       # CMPXCHG16B
microarch.support_lahf_sahf()  # LAHF/SAHF in 64-bit mode
microarch.support_popcnt()     # POPCNT
microarch.support_sse3()       # SSE3
microarch.support_sse4_1()     # SSE4.1
microarch.support_sse4_2()     # SSE4.2
microarch.support_ssse3()      # SSSE3
```

### Level 3 (x86-64-v3)
```python
microarch.support_avx()        # AVX
microarch.support_avx2()       # AVX2
microarch.support_bmi1()       # BMI1
microarch.support_bmi2()       # BMI2
microarch.support_f16c()       # F16C
microarch.support_fma()        # FMA3
microarch.support_lzcnt()      # LZCNT
microarch.support_movbe()      # MOVBE
microarch.support_osxsave()    # XSAVE enabled by OS
```

### Level 4 (x86-64-v4)
```python
microarch.support_avx512f()    # AVX-512 Foundation
microarch.support_avx512bw()   # AVX-512 Byte and Word
microarch.support_avx512cd()   # AVX-512 Conflict Detection
microarch.support_avx512dq()   # AVX-512 Doubleword and Quadword
microarch.support_avx512vl()   # AVX-512 Vector Length Extensions
```

## Compiler Flag Generation

### For Different Compilers
```python
import microarch

# GCC/Clang on Linux
march = microarch.get_march_conan("Linux", "gcc", "x86_64")
print(march)  # e.g., "-march=haswell" or "-march=skylake"

# MSVC on Windows
march = microarch.get_march_conan("Windows", "Visual Studio", "x86_64")
print(march)  # e.g., "/arch:AVX2"

# Clang on macOS
march = microarch.get_march_conan("Macos", "apple-clang", "x86_64")
print(march)  # e.g., "-march=native"
```

### Architecture-Specific Flags
```python
# Get architecture name
arch = microarch.microarchitecture_name()
print(arch)  # e.g., "haswell", "skylake", "zen2"

# Get Conan architecture setting
conan_arch = microarch.get_conan_archs()
print(conan_arch)  # e.g., "x86-64-v3"
```

## Real-World Example

```python
import microarch

def optimize_build_for_cpu():
    """Generate optimal build configuration for current CPU."""

    print("=== CPU Information ===")
    print(f"Vendor: {microarch.get_cpu_vendor()}")
    print(f"Microarchitecture: {microarch.microarchitecture_name()}")
    print(f"Conan Architecture: {microarch.get_conan_archs()}")
    print()

    print("=== x86-64 Feature Levels ===")
    levels = [
        ("x86-64-v1 (baseline)", microarch.support_level1_features()),
        ("x86-64-v2", microarch.support_level2_features()),
        ("x86-64-v3", microarch.support_level3_features()),
        ("x86-64-v4", microarch.support_level4_features()),
    ]

    for name, supported in levels:
        status = "✓" if supported else "✗"
        print(f"{status} {name}")
    print()

    print("=== Vector Instructions ===")
    features = {
        "SSE": microarch.support_sse(),
        "SSE2": microarch.support_sse2(),
        "SSE3": microarch.support_sse3(),
        "SSSE3": microarch.support_ssse3(),
        "SSE4.1": microarch.support_sse4_1(),
        "SSE4.2": microarch.support_sse4_2(),
        "AVX": microarch.support_avx(),
        "AVX2": microarch.support_avx2(),
        "AVX-512F": microarch.support_avx512f(),
    }

    for name, supported in features.items():
        status = "✓" if supported else "✗"
        print(f"{status} {name}")
    print()

    print("=== Recommended Compiler Flags ===")
    march_gcc = microarch.get_march_conan("Linux", "gcc", "x86_64")
    march_msvc = microarch.get_march_conan("Windows", "Visual Studio", "x86_64")
    print(f"GCC/Clang: {march_gcc}")
    print(f"MSVC: {march_msvc}")

if __name__ == "__main__":
    optimize_build_for_cpu()
```

Output example:
```
=== CPU Information ===
Vendor: GenuineIntel
Microarchitecture: skylake
Conan Architecture: x86-64-v3

=== x86-64 Feature Levels ===
✓ x86-64-v1 (baseline)
✓ x86-64-v2
✓ x86-64-v3
✗ x86-64-v4

=== Vector Instructions ===
✓ SSE
✓ SSE2
✓ SSE3
✓ SSSE3
✓ SSE4.1
✓ SSE4.2
✓ AVX
✓ AVX2
✗ AVX-512F

=== Recommended Compiler Flags ===
GCC/Clang: -march=skylake
MSVC: /arch:AVX2
```

## x86-64 Microarchitecture Levels

The library supports detection of the x86-64 microarchitecture levels defined by AMD and adopted industry-wide:

- **x86-64-v1 (baseline)**: Original x86-64 with SSE2 (2003+)
- **x86-64-v2**: Adds CMPXCHG16B, LAHF/SAHF, POPCNT, SSE3, SSE4.1, SSE4.2, SSSE3 (2009+)
- **x86-64-v3**: Adds AVX, AVX2, BMI1, BMI2, F16C, FMA, LZCNT, MOVBE, XSAVE (2015+)
- **x86-64-v4**: Adds AVX-512F, AVX-512BW, AVX-512CD, AVX-512DQ, AVX-512VL (2017+)

## Use Cases

- **Build Systems** - Auto-detect optimal compiler flags for native builds
- **CI/CD** - Generate architecture-specific binaries
- **Performance Optimization** - Select optimal code paths at build time
- **Conan Integration** - Automatic architecture detection for C/C++ packages
- **System Requirements** - Check if CPU meets minimum feature requirements
- **Cryptocurrency Mining** - Detect CPU capabilities for optimized mining

## Knuth Project Integration

This library is part of the [Knuth](https://github.com/k-nuth) cryptocurrency development platform. It's used to:

- Detect optimal compilation flags for Knuth node builds
- Generate architecture-specific Conan packages
- Ensure CPU compatibility for cryptocurrency operations
- Optimize performance-critical cryptographic operations

## API Reference

### Detection Functions

All detection functions return `True` if the feature is supported, `False` otherwise:

- `get_cpu_vendor()` - Returns vendor string ("GenuineIntel", "AuthenticAMD", "CentaurHauls")
- `microarchitecture_name()` - Returns microarchitecture name (e.g., "haswell", "skylake", "zen2")
- `support_*()` - Feature detection functions (see examples above)

### Compiler Flag Functions

- `get_march_conan(os, compiler, arch)` - Get `-march` flag for compiler
- `get_conan_archs()` - Get Conan architecture identifier
- `get_conan_compiler_march(os, compiler, arch)` - Get full compiler march configuration

## Requirements

- Python 3.7+
- x86/x64 processor (will not work on ARM)
- [`cpuid`](https://github.com/fpelliccioni/cpuid-py) >= 0.1.1

## License

MIT License - see [LICENSE](LICENSE) file for details.

## Credits

Created and maintained by [Fernando Pelliccioni](https://github.com/fpelliccioni) as part of the [Knuth Project](https://github.com/k-nuth).

## Related Projects

- [cpuid-native](https://github.com/fpelliccioni/cpuid-py-native) - Low-level CPUID bindings
- [cpuid](https://github.com/fpelliccioni/cpuid-py) - High-level CPU identification API
- [Knuth](https://github.com/k-nuth/kth) - Full-node cryptocurrency infrastructure
