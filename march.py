#TODO(fernando): marchs supported by: apple-clang 10.0 and greater
#                                     clang7, clang8 and clang9
#                                     gcc8, gcc9


# https://github.com/klauspost/cpuid/blob/master/cpuid.go
# https://docs.microsoft.com/es-es/cpp/intrinsics/cpuid-cpuidex?view=msvc-170
# https://en.wikipedia.org/wiki/CPUID
# https://www.felixcloutier.com/x86/
# file:///Users/fernando/Downloads/325383-sdm-vol-2abcd%20(1).pdf

# https://en.wikipedia.org/wiki/X86_Bit_manipulation_instruction_set#cite_note-fam16hsheet-4
# https://en.wikipedia.org/wiki/SSE4#POPCNT_and_LZCNT
# https://gcc.gnu.org/onlinedocs/gcc-12.1.0/gcc/x86-Options.html#x86-Options
# https://en.wikipedia.org/wiki/X86-64#Microarchitecture_levels
# https://gitlab.com/x86-psABIs/x86-64-ABI
# https://developers.redhat.com/blog/2021/01/05/building-red-hat-enterprise-linux-9-for-the-x86-64-v2-microarchitecture-level#background_of_the_x86_64_microarchitecture_levels
# https://lists.llvm.org/pipermail/llvm-dev/2020-July/143289.html
# AMD64 Architecture Programmer’s Manual Volume 2: System Programming
#   https://www.amd.com/system/files/TechDocs/24593.pdf
# AMD64 Architecture Programmer’s Manual Volume 3: General-Purpose and System Instructions
#   https://www.amd.com/system/files/TechDocs/25481.pdf



import importlib
from collections import deque

KTH_MARCH_BUILD_VERSION = 1

DEFAULT_ORGANIZATION_NAME = 'k-nuth'
DEFAULT_LOGIN_USERNAME = 'fpelliccioni'
DEFAULT_USERNAME = 'kth'
DEFAULT_REPOSITORY = 'kth'

# --------------------------------------------

base94_charset = ''.join(map(chr, range(33,127)))
base58_charset = '123456789abcdefghijkmnopqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ'

def base58_flex_encode(val, chrset=base58_charset):
    """\
    Returns a value encoded using 'chrset' regardless of length and
    composition... well, needs 2 printable asccii chars minimum...

    :param val: base-10 integer value to encode as base*
    :param chrset: the characters to use for encoding

    Note: While this could encrypt some value, it is an insecure toy.

    """
    basect = len(chrset)
    assert basect > 1
    encode = deque()

    while val > 0:
        val, mod = divmod(val, basect)
        encode.appendleft(chrset[mod])

    return ''.join(encode)

def base58_flex_decode(enc, chrset=base58_charset):
    """\
    Returns the 'chrset'-decoded value of 'enc'. Of course this needs to use
    the exact same charset as when to encoding the value.

    :param enc: base-* encoded value to decode
    :param chrset: the character-set used for original encoding of 'enc' value

    Note: Did you read the 'encode' note above? Splendid, now have
             some fun... somewhere...

    """
    basect = len(chrset)
    decoded = 0

    for e, c in enumerate(enc[::-1]):
        decoded += ((basect**e) * chrset.index(c))

    return decoded

# --------------------------------------------

# https://gcc.gnu.org/onlinedocs/gcc-3.1.1/gcc/i386-and-x86-64-Options.html#i386%20and%20x86-64%20Options
# https://gcc.gnu.org/onlinedocs/gcc-3.2.3/gcc/i386-and-x86-64-Options.html#i386%20and%20x86-64%20Options
# https://gcc.gnu.org/onlinedocs/gcc-3.3.6/gcc/i386-and-x86_002d64-Options.html#i386-and-x86_002d64-Options
# https://gcc.gnu.org/onlinedocs/gcc-3.4.6/gcc/i386-and-x86_002d64-Options.html#i386-and-x86_002d64-Options

# https://gcc.gnu.org/onlinedocs/gcc-4.0.4/gcc/i386-and-x86_002d64-Options.html#i386-and-x86_002d64-Options
# https://gcc.gnu.org/onlinedocs/gcc-4.1.2/gcc/i386-and-x86_002d64-Options.html#i386-and-x86_002d64-Options
# https://gcc.gnu.org/onlinedocs/gcc-4.2.4/gcc/i386-and-x86_002d64-Options.html#i386-and-x86_002d64-Options
# https://gcc.gnu.org/onlinedocs/gcc-4.3.6/gcc/i386-and-x86_002d64-Options.html#i386-and-x86_002d64-Options
# https://gcc.gnu.org/onlinedocs/gcc-4.4.7/gcc/i386-and-x86_002d64-Options.html#i386-and-x86_002d64-Options
# https://gcc.gnu.org/onlinedocs/gcc-4.5.4/gcc/i386-and-x86_002d64-Options.html#i386-and-x86_002d64-Options
# https://gcc.gnu.org/onlinedocs/gcc-4.6.4/gcc/i386-and-x86_002d64-Options.html#i386-and-x86_002d64-Options
# https://gcc.gnu.org/onlinedocs/gcc-4.7.4/gcc/i386-and-x86-64-Options.html#i386-and-x86-64-Options
# https://gcc.gnu.org/onlinedocs/gcc-4.8.5/gcc/i386-and-x86-64-Options.html#i386-and-x86-64-Options
# https://gcc.gnu.org/onlinedocs/gcc-4.9.4/gcc/i386-and-x86-64-Options.html#i386-and-x86-64-Options

# https://gcc.gnu.org/onlinedocs/gcc-5.5.0/gcc/x86-Options.html#x86-Options
# https://gcc.gnu.org/onlinedocs/gcc-6.5.0/gcc/x86-Options.html#x86-Options
# https://gcc.gnu.org/onlinedocs/gcc-7.5.0/gcc/x86-Options.html#x86-Options
# https://gcc.gnu.org/onlinedocs/gcc-8.5.0/gcc/x86-Options.html#x86-Options
# https://gcc.gnu.org/onlinedocs/gcc-9.5.0/gcc/x86-Options.html#x86-Options
# https://gcc.gnu.org/onlinedocs/gcc-10.4.0/gcc/x86-Options.html#x86-Options
# https://gcc.gnu.org/onlinedocs/gcc-11.3.0/gcc/x86-Options.html#x86-Options
# https://gcc.gnu.org/onlinedocs/gcc-12.1.0/gcc/x86-Options.html#x86-Options

# ------------------------------------------------------------------------------------------------

# https://github.com/pixelb/scripts/blob/master/scripts/gcccpuopt


def adjust_compiler_name(os, compiler):
    if os == "Windows" and compiler == "gcc":
        return "mingw"
    if compiler == "Visual Studio":
        return "msvc"

    return compiler

def march_conan_manip(conanobj):
    if conanobj.settings.arch != "x86_64":
        return (None, None)

    march_from = 'taken from cpuid'
    march_id = get_architecture_id()

    if conanobj.options.get_safe("march_id") is not None:
        if conanobj.options.march_id == "_DUMMY_":
            conanobj.options.march_id = march_id
        else:
            march_id = conanobj.options.march_id
            march_from = 'user defined'
            #TODO(fernando): check for march_id errors

    conanobj.output.info("Detected microarchitecture ID (%s): %s" % (march_from, march_id))

    return (march_id)



class KnuthConanFile(ConanFile):
    def configure(self, pure_c=False):
        ConanFile.configure(self)

        if self.settings.arch == "x86_64":
            # if self.options.get_safe("microarchitecture") is not None and self.options.microarchitecture == "_DUMMY_":
            #     del self.options.fix_march

            march_id = march_conan_manip(self)
            self.options["*"].march_id = march_id

            if self.options.get_safe("march_id") is not None:
                self.options.march_id = march_id

            if self.options.get_safe("march_id") is not None:
                self.output.info("Building microarchitecture ID: %s" % march_id)
                exts = decode_extensions(march_id)
                exts_names = extensions_to_names(exts)
                self.output.info(", ".join(exts_names))



# --------------



def reserved():
    return False

def max_function_id():
	a, _, _, _ = cpuid.cpuid(0)
	return a

def max_extended_function():
	a, _, _, _ = cpuid.cpuid(0x80000000)
	return a

def max_function_id():
	a, _, _, _ = cpuid.cpuid(0)
	return a

def support_long_mode():
    if max_extended_function() < 0x80000001: return False
    _, _, _, d = cpuid.cpuid(0x80000001)
    return (d & (1 << 29)) != 0

# Level 1 Features (baseline) ------------------------------------------
def support_cmov():
    # return CPU_Rep.f_1_EDX_[15];
    if max_function_id() < 0x00000001: return False
    _, _, _, d = cpuid.cpuid(0x00000001)
    return d & (1 << 15) != 0

def support_cx8():
    # cmpxchg8b
    # return CPU_Rep.f_1_EDX_[8];
    if max_function_id() < 0x00000001: return False
    _, _, _, d = cpuid.cpuid(0x00000001)
    return d & (1 << 8) != 0

def support_fpu():
    # X87 - floating-point-unit
    if max_function_id() < 0x00000001: return False
    _, _, _, d = cpuid.cpuid(0x00000001)
    return d & (1 << 0) != 0

def support_fxsr():
    # fxsave
    if max_function_id() < 0x00000001: return False
    _, _, _, d = cpuid.cpuid(0x00000001)
    return d & (1 << 24) != 0

def support_mmx():
    # https://github.com/klauspost/cpuid/blob/master/cpuid.go#L851
    if max_function_id() < 0x00000001: return False
    _, _, _, d = cpuid.cpuid(0x00000001)
    return d & (1 << 23) != 0

# support_osfxsr:
#   Operating system support for FXSAVE and FXRSTOR instructions
#   https://en.wikipedia.org/wiki/Control_register
#   https://www.felixcloutier.com/x86/fxsave


# support_sce
#   Operating system check

def support_sse():
    # https://github.com/klauspost/cpuid/blob/master/cpuid.go#L857
    if max_function_id() < 0x00000001: return False
    _, _, _, d = cpuid.cpuid(0x00000001)
    return d & (1 << 25) != 0

def support_sse2():
    # https://github.com/klauspost/cpuid/blob/master/cpuid.go#L860
    if max_function_id() < 0x00000001: return False
    _, _, _, d = cpuid.cpuid(0x00000001)
    return d & (1 << 26) != 0

def support_level1_features():
    return support_cmov() and \
        support_cx8() and \
        support_fpu() and \
        support_fxsr() and \
        support_mmx() and \
        support_sse() and \
        support_sse2()

        # TODO(fernando): missing OSFXSR and SCE
        # Check what to do

# Level 2 Features - x86-64-v2 ------------------------------------------

# CMPXCHG16B
def support_cx16():
    if max_function_id() < 0x00000001: return False
    _, _, c, _ = cpuid.cpuid(0x00000001)
    return c & (1 << 13) != 0

def support_lahf_sahf():
    if max_extended_function() < 0x80000001: return False
    _, _, c, _ = cpuid.cpuid(0x80000001)
    return c & (1 << 0) != 0

def support_popcnt():
    # https://github.com/klauspost/cpuid/blob/master/cpuid.go#L884
    if support_abm(): return True

    if max_function_id() < 0x00000001: return False
    _, _, c, _ = cpuid.cpuid(0x00000001)
    return c & (1 << 23) != 0

def support_sse3():
    # https://github.com/klauspost/cpuid/blob/master/cpuid.go#L863
    if max_function_id() < 0x00000001: return False
    _, _, c, _ = cpuid.cpuid(0x00000001)
    return c & (1 << 0) != 0

def support_sse41():
    # https://github.com/klauspost/cpuid/blob/master/cpuid.go#L872
    if max_function_id() < 0x00000001: return False
    _, _, c, _ = cpuid.cpuid(0x00000001)
    # return c & 0x00080000 != 0
    return c & (1 << 19) != 0

def support_sse42():
    # https://github.com/klauspost/cpuid/blob/master/cpuid.go#L875
    if max_function_id() < 0x00000001: return False
    _, _, c, _ = cpuid.cpuid(0x00000001)
    # return c & 0x00100000 != 0
    return c & (1 << 20) != 0

def support_ssse3():
    # https://github.com/klauspost/cpuid/blob/master/cpuid.go#L869
    if max_function_id() < 0x00000001: return False
    _, _, c, _ = cpuid.cpuid(0x00000001)
    # return c & 0x00000200 != 0
    return c & (1 << 9) != 0

def support_level2_features():
    return support_cx16() and \
        support_lahf_sahf() and \
        support_popcnt() and \
        support_sse3() and \
        support_sse41() and \
        support_sse42() and \
        support_ssse3()


# Level 3 Features - x86-64-v3 ------------------------------------------

def support_avx_cpu():
    if max_function_id() < 0x00000001: return False
    _, _, c, _ = cpuid.cpuid(0x00000001)
    return (c & (1 << 28)) != 0

def support_avx2_cpu():
    if max_function_id() < 0x00000007: return False
    _, b, _, _ = cpuid.cpuid_count(0x00000007, 0)
    return (b & (1 << 5)) != 0

# 0000_0007h (ECX=0) EBX[3]
def support_bmi1():
    if max_function_id() < 0x00000007: return False
    _, b, _, _ = cpuid.cpuid_count(0x00000007, 0)
    return (b & (1 << 3)) != 0

# 0000_0007h (ECX=0) EBX[8]
def support_bmi2():
    # if not support_bmi1(): return False           # TODO(fernando)
    if max_function_id() < 0x00000007: return False
    _, b, _, _ = cpuid.cpuid_count(0x00000007, 0)
    return (b & (1 << 8)) != 0

def support_f16c():
    if max_function_id() < 0x00000001: return False
    _, _, c, _ = cpuid.cpuid(0x00000001)
    return (c & (1 << 29)) != 0

def support_fma3_cpu():
    if max_function_id() < 0x00000001: return False
    _, _, c, _ = cpuid.cpuid(0x00000001)
    return (c & (1 << 12)) != 0

def support_abm():                  #lzcnt and popcnt on AMD
    if max_extended_function() < 0x80000001: return False
    _, _, c, _ = cpuid.cpuid(0x80000001)
    return (c & (1 << 5)) != 0

def support_lzcnt():
    return support_abm()

def support_movbe():
    # CPUID.01H:ECX.MOVBE[bit 22]
    if max_function_id() < 0x00000001: return False
    _, _, c, _ = cpuid.cpuid(0x00000001)
    return c & (1 << 22) != 0

# XSAVE family
# XSAVE/XRSTOR, XSETBV/XGETBV and XCR0.
def support_xsave_cpu():
    if max_function_id() < 0x00000001: return False
    _, _, c, _ = cpuid.cpuid(0x00000001)
    return (c & (1 << 26)) != 0

def support_level3_features():
    return support_avx_cpu() and \
        support_avx2_cpu() and \
        support_bmi1() and \
        support_bmi2() and \
        support_f16c() and \
        support_fma3_cpu() and \
        support_lzcnt() and \
        support_movbe() and \
        support_xsave_cpu()

    # TODO(fernando): has some of CPU only checks.
    # See what to do


# Level 4 Features - x86-64-v4 ------------------------------------------

def support_avx512f_cpu():
    if max_function_id() < 0x00000007: return False
    _, b, _, _ = cpuid.cpuid_count(0x00000007, 0)
    return (b & (1 << 16)) != 0

def support_avx512bw_cpu():
    if max_function_id() < 0x00000007: return False
    _, b, _, _ = cpuid.cpuid_count(0x00000007, 0)
    return (b & (1 << 30)) != 0

def support_avx512cd_cpu():
    if max_function_id() < 0x00000007: return False
    _, b, _, _ = cpuid.cpuid_count(0x00000007, 0)
    return (b & (1 << 28)) != 0

def support_avx512dq_cpu():
    if max_function_id() < 0x00000007: return False
    _, b, _, _ = cpuid.cpuid_count(0x00000007, 0)
    return (b & (1 << 17)) != 0

def support_avx512vl_cpu():
    if max_function_id() < 0x00000007: return False
    _, b, _, _ = cpuid.cpuid_count(0x00000007, 0)
    return (b & (1 << 31)) != 0

def support_level4_features():
    return support_avx512f_cpu() and \
        support_avx512bw_cpu() and \
        support_avx512cd_cpu() and \
        support_avx512dq_cpu() and \
        support_avx512vl_cpu()

    # TODO(fernando): has some of CPU only checks.
    # See what to do

# Cryptographic Features ------------------------------------------

def support_aes():                          # AES Native instructions
    if max_function_id() < 0x00000001: return False
    _, _, c, _ = cpuid.cpuid(0x00000001)
    return (c & (1 << 25)) != 0

# 0000_0007_0 ECX[9]
def support_vaes():
    if max_function_id() < 0x00000007: return False
    _, _, c, _ = cpuid.cpuid_count(0x00000007, 0)
    return (c & (1 << 9)) != 0

def support_sha():
    if max_function_id() < 0x00000007: return False
    _, b, _, _ = cpuid.cpuid_count(0x00000007, 0)
    return (b & (1 << 29)) != 0


# Other Features ------------------------------------------


#TODO(fernando): la implementacion de la libreria de Golang creo que tiene un error, revisar y PR.
# def support_mmxext():
#     # https://github.com/klauspost/cpuid/blob/master/cpuid.go#L854
#     if max_function_id() < 0x00000001: return False
#     _, _, _, d = cpuid.cpuid(0x00000001)
#     return d & (1 << 25) != 0

def support_sse4a():
    # CPUID.80000001H:ECX.SSE4A[Bit 6]
    # https://github.com/klauspost/cpuid/blob/master/cpuid.go#L1022
    if max_extended_function() < 0x80000001: return False
    _, _, c, _ = cpuid.cpuid(0x80000001)
    return c & (1 << 6) != 0

def support_pku():
    if max_function_id() < 0x00000007: return False
    _, _, c, _ = cpuid.cpuid_count(0x00000007, 0)
    return (c & (1 << 3)) != 0

# PCLMULQDQ
# CLMUL
# https://en.wikipedia.org/wiki/CLMUL_instruction_set
def support_pclmul():
    if max_function_id() < 0x00000001: return False
    _, _, c, _ = cpuid.cpuid(0x00000001)
    return (c & (1 << 1)) != 0

def support_fsgsbase():
    if max_function_id() < 0x00000007: return False
    _, b, _, _ = cpuid.cpuid_count(0x00000007, 0)
    return (b & (1 << 0)) != 0

# RDRAND
def support_rdrnd():
    if max_function_id() < 0x00000001: return False
    _, _, c, _ = cpuid.cpuid(0x00000001)
    return (c & (1 << 30)) != 0

# 4 operands fused multiply-add
# Just on AMD Bulldozer. Removed from AMD Zen.
def support_fma4_cpu():
    if max_extended_function() < 0x80000001: return False
    _, _, c, _ = cpuid.cpuid(0x80000001)
    return (c & (1 << 16)) != 0

# XOP (eXtended Operations)
# Just on AMD Bulldozer. Removed from AMD Zen.
# https://en.wikipedia.org/wiki/XOP_instruction_set
def support_xop_cpu():
    if max_extended_function() < 0x80000001: return False
    _, _, c, _ = cpuid.cpuid(0x80000001)
    return c & (1 << 11) != 0

# 8000_0001h ECX[21] TBM
# static bool TBM(void) { return CPU_Rep.isAMD_ && CPU_Rep.f_81_ECX_[21]; }
# https://en.wikipedia.org/wiki/X86_Bit_manipulation_instruction_set#TBM
# Just on AMD, removed from AMD Zen
def support_tbm():
    if max_extended_function() < 0x80000001: return False
    _, _, c, _ = cpuid.cpuid(0x80000001)
    return (c & (1 << 21)) != 0

def support_rdseed():
    if max_function_id() < 0x00000007: return False
    _, b, _, _ = cpuid.cpuid_count(0x00000007, 0)
    return (b & (1 << 18)) != 0

# https://en.wikipedia.org/wiki/Intel_ADX
def support_adx():
    if max_function_id() < 0x00000007: return False
    _, b, _, _ = cpuid.cpuid_count(0x00000007, 0)
    return (b & (1 << 19)) != 0

def support_3dnow():
    if max_extended_function() < 0x80000001: return False
    _, _, _, d = cpuid.cpuid(0x80000001)
    return d & (1 << 31) != 0

# enhanced 3DNow!
def support_3dnowext():
    if max_extended_function() < 0x80000001: return False
    _, _, _, d = cpuid.cpuid(0x80000001)
    return d & (1 << 30) != 0


# https://www.intel.com/content/dam/www/public/us/en/documents/manuals/64-ia-32-architectures-software-developer-instruction-set-reference-manual-325383.pdf
# pag. 202
# https://www.amd.com/system/files/TechDocs/24594.pdf
# pag. 74
# https://superuser.com/questions/931742/windows-10-64-bit-requirements-does-my-cpu-support-cmpxchg16b-prefetchw-and-la

# Intel:    ECX[8]                              - PREFETCHW
# AMD:      ECX[8], EDX[29], or EDX[31]         - PREFETCH and PREFETCHW
def support_prefetchw():
    if vendorID() == Vendor.AMD and (support_long_mode() or support_3dnow()):
        return True

    if max_extended_function() < 0x80000001: return False
    _, _, c, _ = cpuid.cpuid(0x80000001)
    return (c & (1 << 8)) != 0

def support_prefetchwt1():
    if max_function_id() < 0x00000007: return False
    _, _, c, _ = cpuid.cpuid_count(0x00000007, 0)
    return (c & (1 << 0)) != 0

def support_clflushopt():
    if max_function_id() < 0x00000007: return False
    _, b, _, _ = cpuid.cpuid_count(0x00000007, 0)
    return (b & (1 << 23)) != 0

# XSAVE family
def support_xsaveopt_cpu():
    if max_function_id() < 0x0000000D: return False
    a, _, _, _ = cpuid.cpuid_count(0x0000000D, 1)
    return (a & (1 << 0)) != 0

def support_xsavec_cpu():
    if max_function_id() < 0x0000000D: return False
    a, _, _, _ = cpuid.cpuid_count(0x0000000D, 1)
    return (a & (1 << 1)) != 0

# XGETBV with ECX=1 support
def support_xgetbv_ecx1_cpu():                              # No compiler support (yet)
    if max_function_id() < 0x0000000D: return False
    a, _, _, _ = cpuid.cpuid_count(0x0000000D, 1)
    return (a & (1 << 2)) != 0

# XSAVES and XRSTORS instructions
def support_xsaves_cpu():
    if max_function_id() < 0x0000000D: return False
    a, _, _, _ = cpuid.cpuid_count(0x0000000D, 1)
    return (a & (1 << 3)) != 0

def support_clwb():
    if max_function_id() < 0x00000007: return False
    _, b, _, _ = cpuid.cpuid_count(0x00000007, 0)
    return (b & (1 << 24)) != 0

# # TODO(fernando): ver Enclave en Golang
# def support_enclv():                                      # No compiler support (yet)
#     return False

def support_umip():                                         # No compiler support (yet)
    if max_function_id() < 0x00000007: return False
    _, _, c, _ = cpuid.cpuid_count(0x00000007, 0)
    return (c & (1 << 2)) != 0

# https://hjlebbink.github.io/x86doc/html/PTWRITE.html
def support_ptwrite():
    # If CPUID.(EAX=14H, ECX=0):EBX.PTWRITE [Bit 4] = 0.
    # If LOCK prefix is used.
    # If 66H prefix is used.
    if max_function_id() < 0x00000014: return False
    _, b, _, _ = cpuid.cpuid_count(0x00000014, 0)
    return (b & (1 << 4)) != 0

def support_rdpid():
    if max_function_id() < 0x00000007: return False
    _, _, c, _ = cpuid.cpuid_count(0x00000007, 0)
    return (c & (1 << 22)) != 0

# Software Guard Extensions
def support_sgx():
    if max_function_id() < 0x00000007: return False
    _, b, _, _ = cpuid.cpuid_count(0x00000007, 0)
    return (b & (1 << 2)) != 0

# SGX Launch Configuration
def support_sgx_lc():                                       # No compiler support (yet)
    if max_function_id() < 0x00000007: return False
    _, _, c, _ = cpuid.cpuid_count(0x00000007, 0)
    return (c & (1 << 30)) != 0

# Galois Field instructions
def support_gfni():
    if max_function_id() < 0x00000007: return False
    _, _, c, _ = cpuid.cpuid_count(0x00000007, 0)
    return (c & (1 << 8)) != 0

# CLMUL instruction set (VEX-256/EVEX)
def support_vpclmulqdq():
    if max_function_id() < 0x00000007: return False
    _, _, c, _ = cpuid.cpuid_count(0x00000007, 0)
    return (c & (1 << 10)) != 0

# Platform configuration (Memory Encryption Technologies Instructions)
def support_pconfig():
    if max_function_id() < 0x00000007: return False
    _, _, _, d = cpuid.cpuid_count(0x00000007, 0)
    return (d & (1 << 18)) != 0

# WBNOINVD instruction
def support_wbnoinvd():
    if max_extended_function() < 0x80000008: return False
    _, b, _, _ = cpuid.cpuid(0x80000008)
    return (b & (1 << 9)) != 0

# Move Doubleword as Direct Store
# https://www.felixcloutier.com/x86/movdiri
def support_movdiri():
    if max_function_id() < 0x00000007: return False
    _, _, c, _ = cpuid.cpuid_count(0x00000007, 0)
    return (c & (1 << 27)) != 0

# Move 64 Bytes as Direct Store
def support_movdir64b():
    if max_function_id() < 0x00000007: return False
    _, _, c, _ = cpuid.cpuid_count(0x00000007, 0)
    return (c & (1 << 28)) != 0

# Light Weight Profiling
def support_lwp():
    if max_extended_function() < 0x80000001: return False
    _, _, c, _ = cpuid.cpuid(0x80000001)
    return c & (1 << 15) != 0



# MONITOR and MWAIT instructions (SSE3)
# -mmwait
# This option enables built-in functions __builtin_ia32_monitor, and __builtin_ia32_mwait to generate the monitor and mwait machine instructions.
# def support_mwait():
#     if max_function_id() < 0x00000001: return False
#     _, _, c, _ = cpuid.cpuid(0x00000001)
#     return c & (1 << 3) != 0

# MONITORX and MWAITX instructions
# https://reviews.llvm.org/rL269911
def support_mwaitx():
    if max_extended_function() < 0x80000001: return False
    _, _, c, _ = cpuid.cpuid(0x80000001)
    return c & (1 << 29) != 0

# CLZERO instruction
# https://patchew.org/QEMU/20190925214948.22212-1-bigeasy@linutronix.de/
def support_clzero():
    if max_extended_function() < 0x80000008: return False
    _, b, _, _ = cpuid.cpuid(0x80000008)
    return (b & (1 << 0)) != 0

#TODO(fernando): por las dudas chequear a ver si la implementacion de Golang es correcta!
# "Extended MMX (AMD) https://en.wikipedia.org/wiki/Extended_MMX"
def support_mmxext():
    if max_extended_function() < 0x80000001: return False
    _, _, _, d = cpuid.cpuid(0x80000001)
    return d & (1 << 22) != 0

# https://www.amd.com/system/files/TechDocs/24594.pdf
# 8000_0008 EBX[8]
def support_mcommit():
    if max_extended_function() < 0x80000008: return False
    _, b, _, _ = cpuid.cpuid(0x80000008)
    return (b & (1 << 8)) != 0

# https://www.amd.com/system/files/TechDocs/24594.pdf
# 8000_0008 EBX[4]
def support_rdpru():
    if max_extended_function() < 0x80000008: return False
    _, b, _, _ = cpuid.cpuid(0x80000008)
    return (b & (1 << 4)) != 0

# https://www.amd.com/system/files/TechDocs/24594.pdf
# 0000_0007_0 EBX[10]
def support_invpcid():
    if max_function_id() < 0x00000007: return False
    _, b, _, _ = cpuid.cpuid_count(0x00000007, 0)
    return (b & (1 << 10)) != 0

# https://www.amd.com/system/files/TechDocs/24594.pdf
# 8000_0008 EBX[3]
def support_invlpgb_tlbsync():
    if max_extended_function() < 0x80000008: return False
    _, b, _, _ = cpuid.cpuid(0x80000008)
    return (b & (1 << 3)) != 0


# Shadow Stack (Instructions CLRSSBSY, INCSSP, RDSSP, RSTORSSP, SAVEPREVSSP, SETSSBSY, WRSS, WRUSS)
# 0000_0007_0 ECX[7]
def support_cet_ss():
    if max_function_id() < 0x00000007: return False
    _, _, c, _ = cpuid.cpuid_count(0x00000007, 0)
    return (c & (1 << 7)) != 0

# SNP (Instructions PSMASH, PVALIDATE, RMPADJUST, RMPUPDATE)
# 8000_001F EAX[4]
def support_snp():
    if max_extended_function() < 0x8000001F: return False
    a, _, _, _ = cpuid.cpuid(0x8000001F)
    return (a & (1 << 4)) != 0




# AVX512 ------------------------------------------

def support_avx512pf_cpu():
    if max_function_id() < 0x00000007: return False
    _, b, _, _ = cpuid.cpuid_count(0x00000007, 0)
    return (b & (1 << 26)) != 0

def support_avx512er_cpu():
    if max_function_id() < 0x00000007: return False
    _, b, _, _ = cpuid.cpuid_count(0x00000007, 0)
    return (b & (1 << 27)) != 0

def support_avx5124vnniw_cpu():
    if max_function_id() < 0x00000007: return False
    # _, _, _, d = cpuid.cpuid(0x00000007)
    _, _, _, d = cpuid.cpuid_count(0x00000007, 0)
    return (d & (1 << 2)) != 0

def support_avx5124fmaps_cpu():
    if max_function_id() < 0x00000007: return False
    # _, _, _, d = cpuid.cpuid(0x00000007)
    _, _, _, d = cpuid.cpuid_count(0x00000007, 0)
    return (d & (1 << 3)) != 0

def support_avx512vbmi_cpu():
    if max_function_id() < 0x00000007: return False
    _, _, c, _ = cpuid.cpuid_count(0x00000007, 0)
    return (c & (1 << 1)) != 0

def support_avx512ifma_cpu():
    if max_function_id() < 0x00000007: return False
    _, b, _, _ = cpuid.cpuid_count(0x00000007, 0)
    return (b & (1 << 21)) != 0

def support_avx512vbmi2_cpu():
    if max_function_id() < 0x00000007: return False
    _, _, c, _ = cpuid.cpuid_count(0x00000007, 0)
    return (c & (1 << 6)) != 0

def support_avx512vpopcntdq_cpu():
    if max_function_id() < 0x00000007: return False
    _, _, c, _ = cpuid.cpuid_count(0x00000007, 0)
    return (c & (1 << 14)) != 0

def support_avx512bitalg_cpu():
    if max_function_id() < 0x00000007: return False
    _, _, c, _ = cpuid.cpuid_count(0x00000007, 0)
    return (c & (1 << 12)) != 0

def support_avx512vnni_cpu():
    if max_function_id() < 0x00000007: return False
    _, _, c, _ = cpuid.cpuid_count(0x00000007, 0)
    return (c & (1 << 11)) != 0

def support_avx512bf16_cpu():
    if max_function_id() < 0x00000007: return False
    a, _, _, _ = cpuid.cpuid_count(0x00000007, 1)
    return (a & (1 << 5)) != 0

def support_avx512vp2intersect_cpu():
    if max_function_id() < 0x00000007: return False
    _, _, _,d = cpuid.cpuid_count(0x00000007, 0)
    return (d & (1 << 8)) != 0




# -----------------------------------------------------------------
# GCC v12 flags
# -----------------------------------------------------------------

# -mmmx
# -msse
# -msse2
# -msse3
# -mssse3
# -msse4
# -msse4a
# -msse4.1
# -msse4.2
# -mavx
# -mavx2
# -mavx512f
# -mavx512pf
# -mavx512er
# -mavx512cd
# -mavx512vl
# -mavx512bw
# -mavx512dq
# -mavx512ifma
# -mavx512vbmi
# -msha
# -maes
# -mpclmul
# -mclflushopt
# -mclwb
# -mfsgsbase
# -mptwrite
# -mrdrnd
# -mf16c
# -mfma
# -mpconfig
# -mwbnoinvd
# -mfma4
# -mprfchw
# -mrdpid
# -mprefetchwt1
# -mrdseed
# -msgx
# -mxop
# -mlwp
# -m3dnow
# -m3dnowa
# -mpopcnt
# -mabm
# -madx
# -mbmi
# -mbmi2
# -mlzcnt
# -mfxsr
# -mxsave
# -mxsaveopt
# -mxsavec
# -mxsaves
# -mrtm
# -mhle
# -mtbm
# -mmwaitx
# -mclzero
# -mpku
# -mavx512vbmi2
# -mavx512bf16
# -mavx512fp16
# -mgfni
# -mvaes
# -mwaitpkg
# -mvpclmulqdq
# -mavx512bitalg
# -mmovdiri
# -mmovdir64b
# -menqcmd
# -muintr
# -mtsxldtrk
# -mavx512vpopcntdq
# -mavx512vp2intersect
# -mavx5124fmaps
# -mavx512vnni
# -mavxvnni
# -mavx5124vnniw
# -mcldemote
# -mserialize
# -mamx-tile
# -mamx-int8
# -mamx-bf16
# -mhreset
# -mkl
# -mwidekl




# -----------------------------------------------------------------
# OS support
# -----------------------------------------------------------------

# XSAVE family
def support_osxsave():
    if max_function_id() < 0x00000001: return False
    _, _, c, _ = cpuid.cpuid(0x00000001)
    return (c & (1 << 27)) != 0

# OSPKE (Instructions RDPKRU, WRPKRU)
# OS has enabled Memory Protection Keys and use of the RDPKRU/WRPKRU instructions by setting CR4.PKE=1.
# Note(fernando): I think it is related to PKU
# 0000_0007_0 ECX[4]
# Note(fernando): We do not need to check OS flags. We just need to check CPU flags because
def support_ospke_unused():
    # if max_function_id() < 0x00000007: return False
    # _, _, c, _ = cpuid.cpuid_count(0x00000007, 0)
    # return (c & (1 << 4)) != 0
    return False

# https://en.wikipedia.org/wiki/Advanced_Vector_Extensions#Operating_system_support
def support_avx_os():
    # Copied from: http://stackoverflow.com/a/22521619/922184

    if max_function_id() < 0x00000001: return False
    _, _, c, _ = cpuid.cpuid(0x00000001)

    XGETBV = (c & (1 << 26)) != 0
    osUsesXSAVE_XRSTORE = (c & (1 << 27)) != 0
    cpuAVXSuport = (c & (1 << 28)) != 0

    if not (XGETBV and osUsesXSAVE_XRSTORE and cpuAVXSuport):
        return False

    xcrFeatureMask = cpuid.xgetbv(0)
    return (xcrFeatureMask & 0x6) == 0x6

def support_avx2_os():
    return support_avx_os() and support_avx2_cpu()

def support_fma3_os():
    return support_avx_os() and support_fma3_cpu()

def support_fma4_os():
    return support_avx_os() and support_fma4_cpu()

def support_xsave_os():
    return support_xsave_cpu() and support_osxsave()

def support_xsaveopt_os():
    return support_xsaveopt_cpu() and support_xsave_os()

def support_xsavec_os():
    return support_xsavec_cpu() and support_xsave_os()

def support_xsaves_os():
    return support_xsaves_cpu() and support_xsave_os()

def support_avx512_os():
    if max_function_id() < 0x00000001: return False
    _, _, c, _ = cpuid.cpuid(0x00000001)

    # Only detect AVX-512 features if XGETBV is supported
    if c & ((1<<26)|(1<<27)) != (1<<26)|(1<<27): return False

    # Check for OS support
    eax = cpuid.xgetbv(0)

    # Verify that XCR0[7:5] = 111b (OPMASK state, upper 256-bit of ZMM0-ZMM15 and
    # ZMM16-ZMM31 state are enabled by OS)
    #  and that XCR0[2:1] = 11b (XMM state and YMM state are enabled by OS).
    return (eax>>5)&7 == 7 and (eax>>1)&3 == 3

def support_avx512f_os():
    return support_avx512_os() and support_avx512f_cpu()

def support_avx512pf_os():
    return support_avx512_os() and support_avx512pf_cpu()

def support_avx512er_os():
    return support_avx512_os() and support_avx512er_cpu()

def support_avx512vl_os():
    return support_avx512_os() and support_avx512vl_cpu()

def support_avx512bw_os():
    return support_avx512_os() and support_avx512bw_cpu()

def support_avx512dq_os():
    return support_avx512_os() and support_avx512dq_cpu()

def support_avx512cd_os():
    return support_avx512_os() and support_avx512cd_cpu()

def support_avx5124vnniw_os():
    return support_avx512_os() and support_avx5124vnniw_cpu()

def support_avx5124fmaps_os():
    return support_avx512_os() and support_avx5124fmaps_cpu()

def support_avx512vbmi_os():
    return support_avx512_os() and support_avx512vbmi_cpu()

def support_avx512ifma_os():
    return support_avx512_os() and support_avx512ifma_cpu()

def support_avx512vbmi2_os():
    return support_avx512_os() and support_avx512vbmi2_cpu()

def support_avx512vpopcntdq_os():
    return support_avx512_os() and support_avx512vpopcntdq_cpu()

def support_avx512bitalg_os():
    return support_avx512_os() and support_avx512bitalg_cpu()

def support_avx512vnni_os():
    return support_avx512_os() and support_avx512vnni_cpu()

def support_avx512bf16_os():
    return support_avx512_os() and support_avx512bf16_cpu()

def support_avx512vp2intersect_os():
    return support_avx512_os() and support_avx512vp2intersect_cpu()

# -----------------------------------------------------------------


extensions_map = {
    0:   version_byte_1,
    1:   version_byte_0,

    2:   cpuid._is_long_mode_cpuid,

    # Level 1 (baseline)
    3:   support_cmov,
    4:   support_cx8,
    5:   support_fpu,
    6:   support_fxsr,
    7:   support_mmx,
    # 8:   support_osfxsr,      # Operating System check.
    # 8:   support_sce,         # Operating System check.
    8:   support_sse,
    9:   support_sse2,

    # Level 2 - x86-64-v2
    10:  support_cx16,
    11:  support_lahf_sahf,
    12:  support_popcnt,
    13:  support_sse3,
    14:  support_sse41,                # SSE4.1
    15:  support_sse42,                # SSE4.2
    16:  support_ssse3,

    # Level 3 - x86-64-v3
    17:  support_avx_cpu,
    18:  support_avx2_cpu,
    19:  support_bmi1,
    20:  support_bmi2,
    21:  support_f16c,
    22:  support_fma3_cpu,
    23:  support_lzcnt,
    24:  support_movbe,

    # TODO(fernando): según el spec de Levels, acá tenemos que chequear OSXSAVE,
    # pero nosotros solo podemos chequear XSAVE a nivel procesador
    # el chequeo de soporte de features del sistema operativo lo debería hacer
    # el nodo en runtime (o quizás no)

    # 25:  support_osxsave,
    25:  support_xsave_cpu(),

    # Level 4 - x86-64-v4
    26:  support_avx512f_cpu,
    27:  support_avx512bw_cpu,
    28:  support_avx512cd_cpu,
    20:  support_avx512dq_cpu,
    30:  support_avx512vl_cpu,




    # 1:   support_movbe,
    # 2:   support_mmx,
    # 3:   support_sse,
    # 4:   support_sse2,
    # 5:   support_sse3,
    # 6:   support_ssse3,
    # 7:   support_sse41,
    # 8:   support_sse42,
    # 9:   support_sse4a,
    # 10:  support_popcnt,
    # 11:  support_abm,
    # 12:  support_pku,
    # 13:  support_avx_os,
    # 14:  support_avx2_os,
    # 15:  support_aes,
    # 16:  support_pclmul,
    # 17:  support_fsgsbase,
    # 18:  support_rdrnd,
    # 19:  support_fma3_os,
    # 20:  support_fma4_os,
    # 21:  support_abm,
    # 22:  support_bmi1,
    # 23:  support_bmi2,
    # 24:  support_tbm,
    # 25:  support_f16c,
    # 26:  support_rdseed,
    # 27:  support_adx,
    # 28:  support_prefetchw,
    # 29:  support_clflushopt,
    # 30:  support_xsave_os,
    # 31:  support_xsaveopt_os,
    # 32:  support_xsavec_os,
    # 33:  support_xsaves_os,

    # 34:  support_avx512f_os,
    # 35:  support_avx512pf_os,
    # 36:  support_avx512er_os,
    # 37:  support_avx512vl_os,
    # 38:  support_avx512bw_os,
    # 39:  support_avx512dq_os,
    # 40:  support_avx512cd_os,
    # 41:  support_avx5124vnniw_os,
    # 42:  support_avx5124fmaps_os,
    # 43:  support_avx512vbmi_os,
    # 44:  support_avx512ifma_os,
    # 45:  support_avx512vbmi2_os,
    # 46:  support_avx512vpopcntdq_os,
    # 47:  support_avx512bitalg_os,
    # 48:  support_avx512vnni_os,
    # 49:  support_avx512bf16_os,
    # 50:  support_avx512vp2intersect_os,

    # 51:  support_sha,
    # 52:  support_clwb,
    # 53:  support_enclv,
    # 54:  support_umip,
    # 55:  support_ptwrite,
    # 56:  support_rdpid,
    # 57:  support_sgx,
    # 58:  support_gfni,
    # 60:  support_vpclmulqdq,
    # 61:  support_vaes,
    # 62:  support_pconfig,
    # 63:  support_wbnoinvd,
    # 64:  support_movdir,
    # 65:  support_movdir64b,
    # 66:  support_bfloat16,
    # 67:  support_3dnow,
    # 68:  support_3dnowext,
    # 69:  support_3dnowprefetch,
    # 70:  support_xop,
    # 71:  support_lwp,
    # 72:  support_cx16,
    # 73:  support_mwaitx,
    # 74:  support_clzero,
    # 75:  support_mmxext,
    # 76:  support_prefetchwt1,

    # 77:  support_mcommit,
    # 78:  support_rdpru,

    # 79:  support_invpcid,
    # 80:  support_invlpgb_tlbsync,
    # 81:  support_cet_ss,               # Instructions CLRSSBSY, INCSSP, RDSSP, RSTORSSP, SAVEPREVSSP, SETSSBSY, WRSS, WRUSS
    # 82:  support_snp,                  # Instructions PSMASH, PVALIDATE, RMPADJUST, RMPUPDATE

    # 83:  reserved,
    # 84:  reserved,
    # 85:  reserved,
    # 86:  reserved,
    # 87:  reserved,
    # 88:  reserved,
    # 89:  reserved,
    # 90:  reserved,
    # 91:  reserved,
    # 92:  reserved,
    # 93:  reserved,
    # 94:  reserved,
    # 95:  reserved,
    # 96:  reserved,
    # 97:  reserved,
    # 98:  reserved,
    # 99:  reserved,
    # 100: reserved,
    # 101: reserved,
    # 102: reserved,
    # 103: reserved,
    # 104: reserved,
    # 105: reserved,
    # 106: reserved,
    # 107: reserved,
    # 108: reserved,
    # 109: reserved,
    # 110: reserved,
    # 111: reserved,
    # 112: reserved,
    # 113: reserved,
    # 114: reserved,
    # 115: reserved,
    # 116: reserved,
    # 117: reserved,
    # 118: reserved,
    # 119: reserved,
    # 120: reserved,
    # 121: reserved,
    # 122: reserved,
    # 123: reserved,
    # 124: reserved,
    # 125: reserved,
    # 126: reserved,
    # 127: reserved,
    # 128: reserved,
    # 129: reserved,
    # 130: reserved,
    # 131: reserved,
    # 132: reserved,
    # 133: reserved,
    # 134: reserved,
    # 135: reserved,
    # 136: reserved,
    # 137: reserved,
    # 138: reserved,
    # 139: reserved,
    # 140: reserved,
    # 141: reserved,
    # 142: reserved,
    # 143: reserved,
    # 144: reserved,
    # 145: reserved,
    # 146: reserved,
    # 147: reserved,
    # 148: reserved,
    # 149: reserved,
    # 150: reserved,
    # 151: reserved,
    # 152: reserved,
    # 153: reserved,
    # 154: reserved,
    # 155: reserved,
    # 156: reserved,
    # 157: reserved,
    # 158: reserved,
    # 159: reserved,
    # 160: reserved,
    # 161: reserved,
    # 162: reserved,
    # 163: reserved,
    # 164: reserved,
    # 165: reserved,
    # 166: reserved,
    # 167: reserved,
    # 168: reserved,
    # 169: reserved,
    # 170: reserved,
    # 171: reserved,
    # 172: reserved,
    # 173: reserved,
    # 174: reserved,
    # 175: reserved,
    # 176: reserved,
    # 177: reserved,
    # 178: reserved,
    # 179: reserved,
    # 180: reserved,
    # 181: reserved,
    # 182: reserved,
    # 183: reserved,
    # 184: reserved,
    # 185: reserved,
    # 186: reserved,
    # 187: reserved,
    # 188: reserved,
    # 189: reserved,
    # 190: reserved,
    # 191: reserved,
    # 192: reserved,
    # 193: reserved,
    # 194: reserved,
    # 195: reserved,
    # 196: reserved,
    # 197: reserved,
    # 198: reserved,
    # 199: reserved,
    # 200: reserved,
    # 201: reserved,
    # 202: reserved,
    # 203: reserved,
    # 204: reserved,
    # 205: reserved,
    # 206: reserved,
    # 207: reserved,
    # 208: reserved,
    # 209: reserved,
    # 210: reserved,
    # 211: reserved,
    # 212: reserved,
    # 213: reserved,
    # 214: reserved,
    # 215: reserved,
    # 216: reserved,
    # 217: reserved,
    # 218: reserved,
    # 219: reserved,
    # 220: reserved,
    # 221: reserved,
    # 222: reserved,
    # 223: reserved,
    # 224: reserved,
    # 225: reserved,
    # 226: reserved,
    # 227: reserved,
    # 228: reserved,
    # 229: reserved,
    # 230: reserved,
    # 231: reserved,
    # 232: reserved,
    # 233: reserved,
    # 234: reserved,
    # 235: reserved,
    # 236: reserved,
    # 237: reserved,
    # 238: reserved,
    # 239: reserved,
    # 240: reserved,
    # 241: reserved,
    # 242: reserved,
    # 243: reserved,
    # 244: reserved,
    # 245: reserved,
    # 246: reserved,
    # 247: reserved,
    # 248: reserved,
    # 249: reserved,
    # 250: reserved,
    # 251: reserved,
    # 252: reserved,
    # 253: reserved,
    # 254: reserved,
    # 255: reserved,
}

extensions_names = {

    0:   None,       # Version Byte 1
    1:   None,       # Version Byte 0

    2:   "64 bits",

    # Level 1 (baseline)
    3:   "CMOV",
    4:   "CX8",
    5:   "FPU",
    6:   "FXSR",
    7:   "MMX",
    8:   "OSFXSR",
    9:   "SCE",
    10:  "SSE",
    11:  "SSE2",

    # Level 2 - x86-64-v2
    12:  "CX16",      # CMPXCHG16B
    13:  "LAHF-SAHF",
    14:  "POPCNT",
    15:  "SSE3",
    16:  "SSE4.1",
    17:  "SSE4.2",
    18:  "SSSE3",

    # Level 3 - x86-64-v3
    19:  "AVX",
    20:  "AVX2",
    21:  "BMI1",
    22:  "BMI2",
    23:  "F16C",
    24:  "FMA",
    25:  "LZCNT",
    26:  "MOVBE",
    27:  "OSXSAVE",

    # Level 4 - x86-64-v4
    28:  "AVX512F",
    29:  "AVX512BW",
    30:  "AVX512CD",
    31:  "AVX512DQ",
    32:  "AVX512VL",

    # AMD Specific
    # Intel Specific

    # Cryptography

    9:   "sse4a",
    12:  "pku",
    15:  "aes",
    16:  "pclmul",
    17:  "fsgsbase",
    18:  "rdrnd",
    19:  "fma3",
    20:  "fma4",
    21:  "abm",
    24:  "tbm",
    26:  "rdseed",
    27:  "adx",
    28:  "prefetchw",
    29:  "clflushopt",
    30:  "xsave",
    31:  "xsaveopt",
    32:  "xsavec",
    33:  "xsaves",

    35:  "avx512pf",
    36:  "avx512er",
    41:  "avx5124vnniw",
    42:  "avx5124fmaps",
    43:  "avx512vbmi",
    44:  "avx512ifma",
    45:  "avx512vbmi2",
    46:  "avx512vpopcntdq",
    47:  "avx512bitalg",
    48:  "avx512vnni",
    49:  "avx512bf16",
    50:  "avx512vp2intersect",

    51:  "sha",
    52:  "clwb",
    53:  "enclv",
    54:  "umip",
    55:  "ptwrite",
    56:  "rdpid",
    57:  "sgx",
    58:  "gfni",
    59:  "gfni_sse",
    60:  "vpclmulqdq",
    61:  "vaes",
    62:  "pconfig",
    63:  "wbnoinvd",
    64:  "movdir",
    65:  "movdir64b",
    66:  "bfloat16",
    67:  "3dnow",
    68:  "3dnowext",
    69:  "3dnowprefetch",
    70:  "xop",
    71:  "lwp",
    73:  "mwaitx",
    74:  "clzero",
    75:  "mmxext",
    76:  "prefetchwt1",

    77:  "mcommit",
    78:  "rdpru",

    79:  "invpcid",
    80:  "invlpgb-tlbsync",
    81:  "cet_ss",
    82:  "snp",

    83:  "__reserved__",
    84:  "__reserved__",
    85:  "__reserved__",
    86:  "__reserved__",
    87:  "__reserved__",
    88:  "__reserved__",
    89:  "__reserved__",
    90:  "__reserved__",
    91:  "__reserved__",
    92:  "__reserved__",
    93:  "__reserved__",
    94:  "__reserved__",
    95:  "__reserved__",
    96:  "__reserved__",
    97:  "__reserved__",
    98:  "__reserved__",
    99:  "__reserved__",
    100: "__reserved__",
    101: "__reserved__",
    102: "__reserved__",
    103: "__reserved__",
    104: "__reserved__",
    105: "__reserved__",
    106: "__reserved__",
    107: "__reserved__",
    108: "__reserved__",
    109: "__reserved__",
    110: "__reserved__",
    111: "__reserved__",
    112: "__reserved__",
    113: "__reserved__",
    114: "__reserved__",
    115: "__reserved__",
    116: "__reserved__",
    117: "__reserved__",
    118: "__reserved__",
    119: "__reserved__",
    120: "__reserved__",
    121: "__reserved__",
    122: "__reserved__",
    123: "__reserved__",
    124: "__reserved__",
    125: "__reserved__",
    126: "__reserved__",
    127: "__reserved__",
    128: "__reserved__",
    129: "__reserved__",
    130: "__reserved__",
    131: "__reserved__",
    132: "__reserved__",
    133: "__reserved__",
    134: "__reserved__",
    135: "__reserved__",
    136: "__reserved__",
    137: "__reserved__",
    138: "__reserved__",
    139: "__reserved__",
    140: "__reserved__",
    141: "__reserved__",
    142: "__reserved__",
    143: "__reserved__",
    144: "__reserved__",
    145: "__reserved__",
    146: "__reserved__",
    147: "__reserved__",
    148: "__reserved__",
    149: "__reserved__",
    150: "__reserved__",
    151: "__reserved__",
    152: "__reserved__",
    153: "__reserved__",
    154: "__reserved__",
    155: "__reserved__",
    156: "__reserved__",
    157: "__reserved__",
    158: "__reserved__",
    159: "__reserved__",
    160: "__reserved__",
    161: "__reserved__",
    162: "__reserved__",
    163: "__reserved__",
    164: "__reserved__",
    165: "__reserved__",
    166: "__reserved__",
    167: "__reserved__",
    168: "__reserved__",
    169: "__reserved__",
    170: "__reserved__",
    171: "__reserved__",
    172: "__reserved__",
    173: "__reserved__",
    174: "__reserved__",
    175: "__reserved__",
    176: "__reserved__",
    177: "__reserved__",
    178: "__reserved__",
    179: "__reserved__",
    180: "__reserved__",
    181: "__reserved__",
    182: "__reserved__",
    183: "__reserved__",
    184: "__reserved__",
    185: "__reserved__",
    186: "__reserved__",
    187: "__reserved__",
    188: "__reserved__",
    189: "__reserved__",
    190: "__reserved__",
    191: "__reserved__",
    192: "__reserved__",
    193: "__reserved__",
    194: "__reserved__",
    195: "__reserved__",
    196: "__reserved__",
    197: "__reserved__",
    198: "__reserved__",
    199: "__reserved__",
    200: "__reserved__",
    201: "__reserved__",
    202: "__reserved__",
    203: "__reserved__",
    204: "__reserved__",
    205: "__reserved__",
    206: "__reserved__",
    207: "__reserved__",
    208: "__reserved__",
    209: "__reserved__",
    210: "__reserved__",
    211: "__reserved__",
    212: "__reserved__",
    213: "__reserved__",
    214: "__reserved__",
    215: "__reserved__",
    216: "__reserved__",
    217: "__reserved__",
    218: "__reserved__",
    219: "__reserved__",
    220: "__reserved__",
    221: "__reserved__",
    222: "__reserved__",
    223: "__reserved__",
    224: "__reserved__",
    225: "__reserved__",
    226: "__reserved__",
    227: "__reserved__",
    228: "__reserved__",
    229: "__reserved__",
    230: "__reserved__",
    231: "__reserved__",
    232: "__reserved__",
    233: "__reserved__",
    234: "__reserved__",
    235: "__reserved__",
    236: "__reserved__",
    237: "__reserved__",
    238: "__reserved__",
    239: "__reserved__",
    240: "__reserved__",
    241: "__reserved__",
    242: "__reserved__",
    243: "__reserved__",
    244: "__reserved__",
    245: "__reserved__",
    246: "__reserved__",
    247: "__reserved__",
    248: "__reserved__",
    249: "__reserved__",
    250: "__reserved__",
    251: "__reserved__",
    252: "__reserved__",
    253: "__reserved__",
    254: "__reserved__",
    255: "__reserved__",
}

extensions_flags = {
    'gcc':         None,
    'apple-clang': None,
    'clang':       None,
    'msvc':        None,
    'mingw':       None
}

extensions_flags['gcc'] = {
    0:   ["-m32", "-m64"],
    1:   "-mmovbe",
    2:   "-mmmx",
    3:   "-msse",
    4:   "-msse2",
    5:   "-msse3",
    6:   "-mssse3",
    7:   "-msse4.1",
    8:   "-msse4.2",
    9:   "-msse4a",
    10:  "-mpopcnt",
    11:  "-mlzcnt",
    12:  "-mpku",
    13:  "-mavx",
    14:  "-mavx2",
    15:  "-maes",
    16:  "-mpclmul",
    17:  "-mfsgsbase",
    18:  "-mrdrnd",
    19:  "-mfma",
    20:  "-mfma4",
    21:  "-mabm",
    22:  "-mbmi",
    23:  "-mbmi2",
    24:  "-mtbm",
    25:  "-mf16c",
    26:  "-mrdseed",
    27:  "-madx",
    28:  "-mprfchw",
    29:  "-mclflushopt",
    30:  "-mxsave",
    31:  "-mxsaveopt",
    32:  "-mxsavec",
    33:  "-mxsaves",

    34:  "-mavx512f",
    35:  "-mavx512pf",
    36:  "-mavx512er",
    37:  "-mavx512vl",
    38:  "-mavx512bw",
    39:  "-mavx512dq",
    40:  "-mavx512cd",
    41:  "-mavx5124vnniw",
    42:  "-mavx5124fmaps",
    43:  "-mavx512vbmi",
    44:  "-mavx512ifma",
    45:  "-mavx512vbmi2",
    46:  "-mavx512vpopcntdq",
    47:  "-mavx512bitalg",
    48:  "-mavx512vnni",
    49:  "-mavx512bf16",
    50:  "-mavx512vp2intersect",

    51:  "-msha",
    52:  "-mclwb",
    53:  "-menclv",
    54:  "",                            # umip: GCC does not support it
    55:  "-mptwrite",
    56:  "-mrdpid",
    57:  "-msgx",
    58:  "-mgfni",
    59:  "-mgfni",                      # gfni_sse
    60:  "-mvpclmulqdq",
    61:  "-mvaes",
    62:  "-mpconfig",
    63:  "-mwbnoinvd",
    64:  "-mmovdiri",                   # mmovdir
    65:  "-mmovdir64b",
    66:  "-mbfloat16",
    67:  "-m3dnow",
    68:  "-m3dnowa",                    # 3dnowext
    69:  "-mprfchw",                    # 3dnowprefetch
    70:  "-mxop",
    71:  "-mlwp",
    73:  "-mmwaitx",
    74:  "-mclzero",
    75:  "-mmmxext",
    76:  "-mprefetchwt1",

    77:  "-mmcommit",
    78:  "-mrdpru",

    79:  "-minvpcid",
    80:  "-minvlpgb-tlbsync",
    81:  "-mcet_ss",
    82:  "-msnp",
}

extensions_flags['apple-clang'] = {
    0:   ["-m32", "-m64"],
    1:   "-mmovbe",
    2:   "-mmmx",
    3:   "-msse",
    4:   "-msse2",
    5:   "-msse3",
    6:   "-mssse3",
    7:   "-msse4.1",
    8:   "-msse4.2",
    9:   "-msse4a",
    10:  "-mpopcnt",
    11:  "-mlzcnt",
    12:  "-mpku",
    13:  "-mavx",
    14:  "-mavx2",
    15:  "-maes",
    16:  "-mpclmul",
    17:  "-mfsgsbase",
    18:  "-mrdrnd",
    19:  "-mfma",
    20:  "-mfma4",
    21:  "-mlzcnt",                         # -mabm parece que no existe en Clang
    22:  "-mbmi",
    23:  "-mbmi2",
    24:  "-mtbm",
    25:  "-mf16c",
    26:  "-mrdseed",
    27:  "-madx",
    28:  "-mprfchw",
    29:  "-mclflushopt",
    30:  "-mxsave",
    31:  "-mxsaveopt",
    32:  "-mxsavec",
    33:  "-mxsaves",

    34:  "-mavx512f",
    35:  "-mavx512pf",
    36:  "-mavx512er",
    37:  "-mavx512vl",
    38:  "-mavx512bw",
    39:  "-mavx512dq",
    40:  "-mavx512cd",
    41:  "-mavx5124vnniw",
    42:  "-mavx5124fmaps",
    43:  "-mavx512vbmi",
    44:  "-mavx512ifma",
    45:  "-mavx512vbmi2",
    46:  "-mavx512vpopcntdq",
    47:  "-mavx512bitalg",
    48:  "-mavx512vnni",
    49:  "-mavx512bf16",
    50:  "-mavx512vp2intersect",

    51:  "-msha",
    52:  "-mclwb",
    53:  "-menclv",
    54:  "",                            # umip: apple-clang does not support it
    55:  "-mptwrite",
    56:  "-mrdpid",
    57:  "-msgx",
    58:  "-mgfni",
    59:  "-mgfni",                      # gfni_sse
    60:  "-mvpclmulqdq",
    61:  "-mvaes",
    62:  "-mpconfig",
    63:  "-mwbnoinvd",
    64:  "-mmovdiri",                   # mmovdir
    65:  "-mmovdir64b",
    66:  "-mbfloat16",
    67:  "-m3dnow",
    68:  "-m3dnowa",                    # 3dnowext
    69:  "-mprfchw",                    # 3dnowprefetch
    70:  "-mxop",
    71:  "-mlwp",
    73:  "-mmwaitx",
    74:  "-mclzero",
    75:  "-mmmxext",
    76:  "-mprefetchwt1",

    77:  "-mmcommit",
    78:  "-mrdpru",

    79:  "-minvpcid",
    80:  "-minvlpgb-tlbsync",
    81:  "-mcet_ss",
    82:  "-msnp",
}

# Clang 9
# clang: error: unknown argument '-mabm'; did you mean '-marm'?
extensions_flags['clang'] = {
    0:   ["-m32", "-m64"],
    1:   "-mmovbe",
    2:   "-mmmx",
    3:   "-msse",
    4:   "-msse2",
    5:   "-msse3",
    6:   "-mssse3",
    7:   "-msse4.1",
    8:   "-msse4.2",
    9:   "-msse4a",
    10:  "-mpopcnt",
    11:  "-mlzcnt",
    12:  "-mpku",
    13:  "-mavx",
    14:  "-mavx2",
    15:  "-maes",
    16:  "-mpclmul",
    17:  "-mfsgsbase",
    18:  "-mrdrnd",
    19:  "-mfma",
    20:  "-mfma4",
    21:  "-mlzcnt",                         # -mabm parece que no existe en Clang
    22:  "-mbmi",
    23:  "-mbmi2",
    24:  "-mtbm",
    25:  "-mf16c",
    26:  "-mrdseed",
    27:  "-madx",
    28:  "-mprfchw",
    29:  "-mclflushopt",
    30:  "-mxsave",
    31:  "-mxsaveopt",
    32:  "-mxsavec",
    33:  "-mxsaves",

    34:  "-mavx512f",
    35:  "-mavx512pf",
    36:  "-mavx512er",
    37:  "-mavx512vl",
    38:  "-mavx512bw",
    39:  "-mavx512dq",
    40:  "-mavx512cd",
    41:  "-mavx5124vnniw",
    42:  "-mavx5124fmaps",
    43:  "-mavx512vbmi",
    44:  "-mavx512ifma",
    45:  "-mavx512vbmi2",
    46:  "-mavx512vpopcntdq",
    47:  "-mavx512bitalg",
    48:  "-mavx512vnni",
    49:  "-mavx512bf16",
    50:  "-mavx512vp2intersect",

    51:  "-msha",
    52:  "-mclwb",
    53:  "-menclv",
    54:  "",                            # umip: Clang does not support it
    55:  "-mptwrite",
    56:  "-mrdpid",
    57:  "-msgx",
    58:  "-mgfni",
    59:  "-mgfni",                      # gfni_sse
    60:  "-mvpclmulqdq",
    61:  "-mvaes",
    62:  "-mpconfig",
    63:  "-mwbnoinvd",
    64:  "-mmovdiri",                   # mmovdir
    65:  "-mmovdir64b",
    66:  "-mbfloat16",
    67:  "-m3dnow",
    68:  "-m3dnowa",                    # 3dnowext
    69:  "-mprfchw",                    # 3dnowprefetch
    70:  "-mxop",
    71:  "-mlwp",
    73:  "-mmwaitx",
    74:  "-mclzero",
    75:  "-mmmxext",
    76:  "-mprefetchwt1",

    77:  "-mmcommit",
    78:  "-mrdpru",

    79:  "-minvpcid",
    80:  "-minvlpgb-tlbsync",
    81:  "-mcet_ss",
    82:  "-msnp",
}

extensions_flags['msvc'] = {
    0:   "",
    1:   "",
    2:   "",
    3:   "",
    4:   "",
    5:   "",
    6:   "",
    7:   "",
    8:   "",
    9:   "",
    10:  "",
    11:  "",
    12:  "",
    13:  "/arch:AVX",
    14:  "/arch:AVX2",
    15:  "",
    16:  "",
    17:  "",
    18:  "",
    19:  "",
    20:  "",
    21:  "",
    22:  "",
    23:  "",
    24:  "",
    25:  "",
    26:  "",
    27:  "",
    28:  "",
    29:  "",
    30:  "",
    31:  "",
    32:  "",
    33:  "",

    34:  "/arch:AVX512",
    35:  "/arch:AVX512",
    36:  "/arch:AVX512",
    37:  "/arch:AVX512",
    38:  "/arch:AVX512",
    39:  "/arch:AVX512",
    40:  "/arch:AVX512",
    41:  "/arch:AVX512",
    42:  "/arch:AVX512",
    43:  "/arch:AVX512",
    44:  "/arch:AVX512",
    45:  "/arch:AVX512",
    46:  "/arch:AVX512",
    47:  "/arch:AVX512",
    48:  "/arch:AVX512",
    49:  "/arch:AVX512",
    50:  "/arch:AVX512",

    51:  "",
    52:  "",
    53:  "",
    54:  "",
    55:  "",
    56:  "",
    57:  "",
    58:  "",
    59:  "",
    60:  "",
    61:  "",
    62:  "",
    63:  "",
    64:  "",
    65:  "",
    66:  "",
    67:  "",
    68:  "",
    69:  "",
    70:  "",
    71:  "",
    72:  "",
    73:  "",
    74:  "",
    75:  "",
    76:  "",

    # TODO: new AMD instructions
    77:  "",
    78:  "",

    79:  "",
    80:  "",
    81:  "",
    82:  "",
}

extensions_flags['mingw'] = {
    0:   ["-m32", "-m64"],
    1:   "-mmovbe",
    2:   "-mmmx",
    3:   "-msse",
    4:   "-msse2",
    5:   "-msse3",
    6:   "-mssse3",
    7:   "-msse4.1",
    8:   "-msse4.2",
    9:   "-msse4a",
    10:  "-mpopcnt",
    11:  "-mlzcnt",
    12:  "-mpku",
    13:  "-mavx",
    14:  "-mavx2",
    15:  "-maes",
    16:  "-mpclmul",
    17:  "-mfsgsbase",
    18:  "-mrdrnd",
    19:  "-mfma",
    20:  "-mfma4",
    21:  "-mabm",
    22:  "-mbmi",
    23:  "-mbmi2",
    24:  "-mtbm",
    25:  "-mf16c",
    26:  "-mrdseed",
    27:  "-madx",
    28:  "-mprfchw",
    29:  "-mclflushopt",
    30:  "-mxsave",
    31:  "-mxsaveopt",
    32:  "-mxsavec",
    33:  "-mxsaves",

    34:  "-mavx512f",
    35:  "-mavx512pf",
    36:  "-mavx512er",
    37:  "-mavx512vl",
    38:  "-mavx512bw",
    39:  "-mavx512dq",
    40:  "-mavx512cd",
    41:  "-mavx5124vnniw",
    42:  "-mavx5124fmaps",
    43:  "-mavx512vbmi",
    44:  "-mavx512ifma",
    45:  "-mavx512vbmi2",
    46:  "-mavx512vpopcntdq",
    47:  "-mavx512bitalg",
    48:  "-mavx512vnni",
    49:  "-mavx512bf16",
    50:  "-mavx512vp2intersect",

    51:  "-msha",
    52:  "-mclwb",
    53:  "-menclv",
    54:  "",                            # umip: MinGW does not support it
    55:  "-mptwrite",
    56:  "-mrdpid",
    57:  "-msgx",
    58:  "-mgfni",
    59:  "-mgfni",                      # gfni_sse
    60:  "-mvpclmulqdq",
    61:  "-mvaes",
    62:  "-mpconfig",
    63:  "-mwbnoinvd",
    64:  "-mmovdiri",                   # mmovdir
    65:  "-mmovdir64b",
    66:  "-mbfloat16",
    67:  "-m3dnow",
    68:  "-m3dnowa",                    # 3dnowext
    69:  "-mprfchw",                    # 3dnowprefetch
    70:  "-mxop",
    71:  "-mlwp",
    73:  "-mmwaitx",
    74:  "-mclzero",
    75:  "-mmmxext",
    76:  "-mprefetchwt1",

    77:  "-mmcommit",
    78:  "-mrdpru",

    79:  "-minvpcid",
    80:  "-minvlpgb-tlbsync",
    81:  "-mcet_ss",
    82:  "-msnp",
}


# GCC 10 and general
# # gcc: error: unrecognized command line option '-mumip'
# TODO(fernando) -mumip dice estar soportado por GCC en las marchs pero no parece ser una flag independiente

# GCC 9
# gcc: error: unrecognized command line option '-mavx512vp2intersect'

# GCC 7
# gcc: error: unrecognized command line option '-mavx512vbmi2'; did you mean '-mavx512vbmi'?
# gcc: error: unrecognized command line option '-mavx512bitalg'; did you mean '-mavx5124fmaps'?
# gcc: error: unrecognized command line option '-mavx512vnni'; did you mean '-mavx5124vnniw'?
# gcc: error: unrecognized command line option '-mgfni'
# gcc: error: unrecognized command line option '-mvpclmulqdq'; did you mean '-mpclmul'?
# gcc: error: unrecognized command line option '-mvaes'; did you mean '-maes'?
# gcc: error: unrecognized command line option '-mpconfig'; did you mean '-mpcommit'?
# gcc: error: unrecognized command line option '-mwbnoinvd'
# gcc: error: unrecognized command line option '-mmovdiri'; did you mean '-mmovbe'?
# gcc: error: unrecognized command line option '-mmovdir64b'

# GCC 5
# gcc: error: unrecognized command line option '-mpku'
# gcc: error: unrecognized command line option '-mavx512vpopcntdq'
# gcc: error: unrecognized command line option '-mrdpid'

# Clang 8
# clang: error: unknown argument: '-mavx512vp2intersect'

# Clang 6
# clang: error: unknown argument: '-mrdpid'
# clang: error: unknown argument: '-mpconfig'
# clang: error: unknown argument: '-mwbnoinvd'
# clang: error: unknown argument: '-mmovdiri'
# clang: error: unknown argument: '-mmovdir64b'

extensions_compiler_compat = {
    0:   {'gcc': 5, 'apple-clang': 1,'clang': 6,'msvc': 14,'mingw': 5}, #"64 bits",
    1:   {'gcc': 5, 'apple-clang': 1,'clang': 6,'msvc': 14,'mingw': 5}, #"movbe",
    2:   {'gcc': 5, 'apple-clang': 1,'clang': 6,'msvc': 14,'mingw': 5}, #"mmx",
    3:   {'gcc': 5, 'apple-clang': 1,'clang': 6,'msvc': 14,'mingw': 5}, #"sse",
    4:   {'gcc': 5, 'apple-clang': 1,'clang': 6,'msvc': 14,'mingw': 5}, #"sse2",
    5:   {'gcc': 5, 'apple-clang': 1,'clang': 6,'msvc': 14,'mingw': 5}, #"sse3",
    6:   {'gcc': 5, 'apple-clang': 1,'clang': 6,'msvc': 14,'mingw': 5}, #"ssse3",
    7:   {'gcc': 5, 'apple-clang': 1,'clang': 6,'msvc': 14,'mingw': 5}, #"sse41",
    8:   {'gcc': 5, 'apple-clang': 1,'clang': 6,'msvc': 14,'mingw': 5}, #"sse42",
    9:   {'gcc': 5, 'apple-clang': 1,'clang': 6,'msvc': 14,'mingw': 5}, #"sse4a",
    10:  {'gcc': 5, 'apple-clang': 1,'clang': 6,'msvc': 14,'mingw': 5}, #"popcnt",
    11:  {'gcc': 5, 'apple-clang': 1,'clang': 6,'msvc': 14,'mingw': 5}, #"lzcnt",
    12:  {'gcc': 6, 'apple-clang': 1,'clang': 6,'msvc': 14,'mingw': 6}, #"pku",
    13:  {'gcc': 5, 'apple-clang': 1,'clang': 6,'msvc': 14,'mingw': 5}, #"avx",
    14:  {'gcc': 5, 'apple-clang': 1,'clang': 6,'msvc': 14,'mingw': 5}, #"avx2",
    15:  {'gcc': 5, 'apple-clang': 1,'clang': 6,'msvc': 14,'mingw': 5}, #"aes",
    16:  {'gcc': 5, 'apple-clang': 1,'clang': 6,'msvc': 14,'mingw': 5}, #"pclmul",
    17:  {'gcc': 5, 'apple-clang': 1,'clang': 6,'msvc': 14,'mingw': 5}, #"fsgsbase",
    18:  {'gcc': 5, 'apple-clang': 1,'clang': 6,'msvc': 14,'mingw': 5}, #"rdrnd",
    19:  {'gcc': 5, 'apple-clang': 1,'clang': 6,'msvc': 14,'mingw': 5}, #"fma3",
    20:  {'gcc': 5, 'apple-clang': 1,'clang': 6,'msvc': 14,'mingw': 5}, #"fma4",
    21:  {'gcc': 5, 'apple-clang': 1,'clang': 6,'msvc': 14,'mingw': 5}, #"abm",
    22:  {'gcc': 5, 'apple-clang': 1,'clang': 6,'msvc': 14,'mingw': 5}, #"bmi",
    23:  {'gcc': 5, 'apple-clang': 1,'clang': 6,'msvc': 14,'mingw': 5}, #"bmi2",
    24:  {'gcc': 5, 'apple-clang': 1,'clang': 6,'msvc': 14,'mingw': 5}, #"tbm",
    25:  {'gcc': 5, 'apple-clang': 1,'clang': 6,'msvc': 14,'mingw': 5}, #"f16c",
    26:  {'gcc': 5, 'apple-clang': 1,'clang': 6,'msvc': 14,'mingw': 5}, #"rdseed",
    27:  {'gcc': 5, 'apple-clang': 1,'clang': 6,'msvc': 14,'mingw': 5}, #"adx",
    28:  {'gcc': 5, 'apple-clang': 1,'clang': 6,'msvc': 14,'mingw': 5}, #"prefetchw",
    29:  {'gcc': 5, 'apple-clang': 1,'clang': 6,'msvc': 14,'mingw': 5}, #"clflushopt",
    30:  {'gcc': 5, 'apple-clang': 1,'clang': 6,'msvc': 14,'mingw': 5}, #"xsave",
    31:  {'gcc': 5, 'apple-clang': 1,'clang': 6,'msvc': 14,'mingw': 5}, #"xsaveopt",
    32:  {'gcc': 5, 'apple-clang': 1,'clang': 6,'msvc': 14,'mingw': 5}, #"xsavec",
    33:  {'gcc': 5, 'apple-clang': 1,'clang': 6,'msvc': 14,'mingw': 5}, #"xsaves",

    34:  {'gcc': 5, 'apple-clang': 1,'clang': 6,'msvc': 14,'mingw': 5}, #"avx512f",
    35:  {'gcc': 5, 'apple-clang': 1,'clang': 6,'msvc': 14,'mingw': 5}, #"avx512pf",
    36:  {'gcc': 5, 'apple-clang': 1,'clang': 6,'msvc': 14,'mingw': 5}, #"avx512er",
    37:  {'gcc': 5, 'apple-clang': 1,'clang': 6,'msvc': 14,'mingw': 5}, #"avx512vl",
    38:  {'gcc': 5, 'apple-clang': 1,'clang': 6,'msvc': 14,'mingw': 5}, #"avx512bw",
    39:  {'gcc': 5, 'apple-clang': 1,'clang': 6,'msvc': 14,'mingw': 5}, #"avx512dq",
    40:  {'gcc': 5, 'apple-clang': 1,'clang': 6,'msvc': 14,'mingw': 5}, #"avx512cd",
    41:  {'gcc': 5, 'apple-clang': 1,'clang': 6,'msvc': 14,'mingw': 5}, #"avx5124vnniw",
    42:  {'gcc': 5, 'apple-clang': 1,'clang': 6,'msvc': 14,'mingw': 5}, #"avx5124fmaps",
    43:  {'gcc': 5, 'apple-clang': 1,'clang': 6,'msvc': 14,'mingw': 5}, #"avx512vbmi",
    44:  {'gcc': 5, 'apple-clang': 1,'clang': 6,'msvc': 14,'mingw': 5}, #"avx512ifma",
    45:  {'gcc': 8, 'apple-clang': 1,'clang': 6,'msvc': 14,'mingw': 8}, #"avx512vbmi2",
    46:  {'gcc': 6, 'apple-clang': 1,'clang': 6,'msvc': 14,'mingw': 6}, #"avx512vpopcntdq",
    47:  {'gcc': 8, 'apple-clang': 1,'clang': 6,'msvc': 14,'mingw': 8}, #"avx512bitalg",
    48:  {'gcc': 8, 'apple-clang': 1,'clang': 6,'msvc': 14,'mingw': 8}, #"avx512vnni",
    49:  {'gcc': 5, 'apple-clang': 1,'clang': 6,'msvc': 14,'mingw': 5}, #"avx512bf16",
    50:  {'gcc': 10,'apple-clang': 1,'clang': 9,'msvc': 14,'mingw': 10}, #"avx512vp2intersect",

    51:  {'gcc': 5, 'apple-clang': 1,'clang': 6,'msvc': 14,'mingw': 5}, #"sha",
    52:  {'gcc': 5, 'apple-clang': 1,'clang': 6,'msvc': 14,'mingw': 5}, #"clwb",
    53:  {'gcc': 5, 'apple-clang': 1,'clang': 6,'msvc': 14,'mingw': 5}, #"enclv",
    54:  {'gcc': None, 'apple-clang': None,'clang': None,'msvc': None,'mingw': None}, #"umip",
    55:  {'gcc': 5, 'apple-clang': 1,'clang': 6,'msvc': 14,'mingw': 5}, #"ptwrite",
    56:  {'gcc': 6, 'apple-clang': 1,'clang': 7,'msvc': 14,'mingw': 6}, #"rdpid",
    57:  {'gcc': 5, 'apple-clang': 1,'clang': 6,'msvc': 14,'mingw': 5}, #"sgx",
    58:  {'gcc': 8, 'apple-clang': 1,'clang': 6,'msvc': 14,'mingw': 8}, #"gfni",
    59:  {'gcc': 8, 'apple-clang': 1,'clang': 6,'msvc': 14,'mingw': 8}, #"gfni_sse",
    60:  {'gcc': 8, 'apple-clang': 1,'clang': 6,'msvc': 14,'mingw': 8}, #"vpclmulqdq",
    61:  {'gcc': 8, 'apple-clang': 1,'clang': 6,'msvc': 14,'mingw': 8}, #"vaes",
    62:  {'gcc': 8, 'apple-clang': 1,'clang': 7,'msvc': 14,'mingw': 8}, #"pconfig",
    63:  {'gcc': 8, 'apple-clang': 1,'clang': 7,'msvc': 14,'mingw': 8}, #"wbnoinvd",
    64:  {'gcc': 8, 'apple-clang': 1,'clang': 7,'msvc': 14,'mingw': 8}, #"movdir",
    65:  {'gcc': 8, 'apple-clang': 1,'clang': 7,'msvc': 14,'mingw': 8}, #"movdir64b",
    66:  {'gcc': 5, 'apple-clang': 1,'clang': 6,'msvc': 14,'mingw': 5}, #"bfloat16",
    67:  {'gcc': 5, 'apple-clang': 1,'clang': 6,'msvc': 14,'mingw': 5}, #"3dnow",
    68:  {'gcc': 5, 'apple-clang': 1,'clang': 6,'msvc': 14,'mingw': 5}, #"3dnowext",
    69:  {'gcc': 5, 'apple-clang': 1,'clang': 6,'msvc': 14,'mingw': 5}, #"3dnowprefetch",
    70:  {'gcc': 5, 'apple-clang': 1,'clang': 6,'msvc': 14,'mingw': 5}, #"xop",
    71:  {'gcc': 5, 'apple-clang': 1,'clang': 6,'msvc': 14,'mingw': 5}, #"lwp",
    73:  {'gcc': 5, 'apple-clang': 1,'clang': 6,'msvc': 14,'mingw': 5}, #"mwaitx",
    74:  {'gcc': 5, 'apple-clang': 1,'clang': 6,'msvc': 14,'mingw': 5}, #"clzero",
    75:  {'gcc': None, 'apple-clang': None,'clang': None,'msvc': None,'mingw': None}, #"mmxext",
    76:  {'gcc': 5, 'apple-clang': 1,'clang': 6,'msvc': 14,'mingw': 5}, #"prefetchwt1",

    77:  {'gcc': None, 'apple-clang': None,'clang': None,'msvc': None,'mingw': None}, #"mcommit",
    78:  {'gcc': None, 'apple-clang': None,'clang': None,'msvc': None,'mingw': None}, #"rdpru",

    79:  {'gcc': None, 'apple-clang': None,'clang': None,'msvc': None,'mingw': None}, #"invpcid",
    80:  {'gcc': None, 'apple-clang': None,'clang': None,'msvc': None,'mingw': None}, #"invlpgb-tlbsync",
    81:  {'gcc': None, 'apple-clang': None,'clang': None,'msvc': None,'mingw': None}, #"cet_ss",
    82:  {'gcc': None, 'apple-clang': None,'clang': None,'msvc': None,'mingw': None}, #"snp",
}

def get_available_extensions():
    data = []
    for _, f in extensions_map.items():
        # data.append(str(int(f())))
        data.append(int(f()))
    return data

def _to_chars_bin(data):
    res = []
    for x in data:
        res.append(str(x))
    return res

def _to_ints_bin(data):
    res = []
    for x in data:
        res.append(int(x))
    return res

def _pad_right_array(data):
    if len(data) >= len(extensions_map): return data
    n = len(extensions_map) - len(data)
    for i in range(n):
        data.append(int(0))
    return data

def encode_extensions(exts):
    exts = _to_chars_bin(exts)
    exts_str = ''.join(reversed(exts))
    exts_num = int(exts_str, 2)
    exts_num_b58 = base58_flex_encode(exts_num)
    return exts_num_b58

def decode_extensions(architecture_id):
    architecture_id = str(architecture_id)
    exts_num = base58_flex_decode(architecture_id)
    res = "{0:b}".format(exts_num)
    res = res.zfill(len(extensions_map))
    return _to_ints_bin(list(reversed(res)))

def get_architecture_id():
    exts = get_available_extensions()
    architecture_id = encode_extensions(exts)
    return architecture_id

def extensions_to_names(exts):
    res = []
    for i in range(len(exts)):
        if (exts[i] == 1):
            res.append(extensions_names[i])
    return res

def print_available_extensions(exts):
    for i in range(len(exts)):
        if (exts[i] == 1):
            print("your computer supports " + extensions_names[i])
            # conanobj.output.info("your computer supports " + extensions_names[i])

# ----------------------------------------------------------------------

class Vendor(Enum):
    Other = 0,
    Intel = 1,
    AMD = 2,
    VIA = 3,
    Transmeta = 4,
    NSC = 5,
    KVM = 6,         # Kernel-based Virtual Machine
    MSVM = 7,        # Microsoft Hyper-V or Windows Virtual PC
    VMware = 8,
    XenHVM = 9,
    Bhyve = 10,
    Hygon = 11,


# Except from http://en.wikipedia.org/wiki/CPUID#EAX.3D0:_Get_vendor_ID
vendorMapping = {
	"AMDisbetter!": Vendor.AMD,
	"AuthenticAMD": Vendor.AMD,
	"CentaurHauls": Vendor.VIA,
	"GenuineIntel": Vendor.Intel,
	"TransmetaCPU": Vendor.Transmeta,
	"GenuineTMx86": Vendor.Transmeta,
	"Geode by NSC": Vendor.NSC,
	"VIA VIA VIA ": Vendor.VIA,
	"KVMKVMKVMKVM": Vendor.KVM,
	"Microsoft Hv": Vendor.MSVM,
	"VMwareVMware": Vendor.VMware,
	"XenVMMXenVMM": Vendor.XenHVM,
	"bhyve bhyve ": Vendor.Bhyve,
	"HygonGenuine": Vendor.Hygon,
}

def vendorID():
    v = cpuid.cpu_vendor()
    vend = vendorMapping.get(v, Vendor.Other)
    return vend

def brandName():
    if max_extended_function() >= 0x80000004:
        return cpuid.cpu_name()
    return "unknown"

def cacheLine():
	if max_function_id() < 0x1:
		return 0

	_, ebx, _, _ = cpuid.cpuid(1)
	cache = (ebx & 0xff00) >> 5 # cflush size
	if cache == 0 and max_extended_function() >= 0x80000006:
		_, _, ecx, _ = cpuid.cpuid(0x80000006)
		cache = ecx & 0xff # cacheline size
	#TODO: Read from Cache and TLB Information
	return int(cache)

def familyModel():
	if max_function_id() < 0x1:
		return 0, 0
	eax, _, _, _ = cpuid.cpuid(1)
	family = ((eax >> 8) & 0xf) + ((eax >> 20) & 0xff)
	model = ((eax >> 4) & 0xf) + ((eax >> 12) & 0xf0)
	return int(family), int(model)

def threadsPerCore():
	mfi = max_function_id()
	if mfi < 0x4 or vendorID() != Vendor.Intel:
		return 1

	if mfi < 0xb:
		_, b, _, d = cpuid.cpuid(1)
		if (d & (1 << 28)) != 0:
			# v will contain logical core count
			v = (b >> 16) & 255
			if v > 1:
				a4, _, _, _ = cpuid.cpuid(4)
				# physical cores
				v2 = (a4 >> 26) + 1
				if v2 > 0:
					return int(v) / int(v2)
		return 1
	_, b, _, _ = cpuid.cpuid_count(0xb, 0)
	if b&0xffff == 0:
		return 1
	return int(b & 0xffff)


def logicalCores():
    mfi = max_function_id()
    vend = vendorID()

    if vend == Vendor.Intel:
        # Use this on old Intel processors
        if mfi < 0xb:
            if mfi < 1:
                return 0
            # CPUID.1:EBX[23:16] represents the maximum number of addressable IDs (initial APIC ID)
            # that can be assigned to logical processors in a physical package.
            # The value may not be the same as the number of logical processors that are present in the hardware of a physical package.
            _, ebx, _, _ = cpuid.cpuid(1)
            logical = (ebx >> 16) & 0xff
            return int(logical)
        _, b, _, _ = cpuid.cpuid_count(0xb, 1)
        return int(b & 0xffff)
    elif vend == Vendor.AMD or vend == Vendor.Hygon:
        _, b, _, _ = cpuid.cpuid(1)
        return int((b >> 16) & 0xff)
    else:
        return 0

def physicalCores():
    vend = vendorID()

    if vend == Vendor.Intel:
        return logicalCores() / threadsPerCore()
    elif vend == Vendor.AMD or vend == Vendor.Hygon:
        if max_extended_function() >= 0x80000008:
            _, _, c, _ = cpuid.cpuid(0x80000008)
            return int(c&0xff) + 1
    return 0


def support_rdtscp():
    if max_extended_function() < 0x80000001: return False
    _, _, _, d = cpuid.cpuid(0x80000001)
    return (d & (1 << 27)) != 0

#TODO(fernando): implementar RTCounter() del proyecto Golang
#TODO(fernando): implementar Ia32TscAux() del proyecto Golang

# LogicalCPU will return the Logical CPU the code is currently executing on.
# This is likely to change when the OS re-schedules the running thread
# to another CPU.
# If the current core cannot be detected, -1 will be returned.
def LogicalCPU():
    if max_function_id() < 1:
        return -1
    _, ebx, _, _ = cpuid.cpuid(1)
    return int(ebx >> 24)


# VM Will return true if the cpu id indicates we are in
# a virtual machine. This is only a hint, and will very likely
# have many false negatives.
def VM():
    vend = vendorID()
    if vend == Vendor.MSVM or vend == Vendor.KVM or vend == Vendor.VMware or vend == Vendor.XenHVM or vend == Vendor.Bhyve:
        return True
    return False

def Hyperthreading():
    if max_function_id() < 4: return False
    _, _, _, d = cpuid.cpuid(1)
    if vendorID() == Vendor.Intel and (d&(1<<28)) != 0:
        if threadsPerCore() > 1:
            return True
    return False


# ----------------------------------------------------------------------

def is_superset_of(a, b):
    n = min(len(a), len(b))

    for i in range(n):
        if a[i] < b[i]: return False

    for i in range(n, len(b)):
        if b[i] == 1: return False

    return True

def test_is_superset_of():
    assert(is_superset_of([], []))
    assert(is_superset_of([0], []))
    assert(is_superset_of([], [0]))
    assert(is_superset_of([0], [0]))
    assert(is_superset_of([0,0], [0,0]))
    assert(is_superset_of([0], [0,0]))
    assert(is_superset_of([0,0], [0]))
    assert(is_superset_of([1], [1]))
    assert(is_superset_of([1], [0]))
    assert(is_superset_of([1], []))

    assert(not is_superset_of([0], [1]))
    assert(not is_superset_of([], [1]))

# test_is_superset_of()
# ----------------------------------------------------------------------

def filter_extensions(exts, os, comp, comp_ver):
    comp = adjust_compiler_name(os, comp)

    res = []
    for i in range(len(exts)):
        if i not in extensions_compiler_compat:
            res.append(0)
            continue

        if extensions_compiler_compat[i][comp] is None:
            res.append(0)
            continue

        if extensions_compiler_compat[i][comp] > comp_ver:
            res.append(0)
            continue

        res.append(exts[i])

        # if i in extensions_compiler_compat:
        #     if extensions_compiler_compat[i][comp] is not None:
        #         if extensions_compiler_compat[i][comp] <= comp_ver:
        #             res.append(exts[i])
        #         else:
        #             res.append(0)
        # else:
        #     res.append(0)

    return res

def get_compiler_flags(exts, os, comp, comp_ver):
    exts = filter_extensions(exts, os, comp, comp_ver)
    comp = adjust_compiler_name(os, comp)
    comp_extensions_flags = extensions_flags[comp]

    res = []
    for i in range(len(comp_extensions_flags)):
        flag = comp_extensions_flags[i]
        if isinstance(flag, list):
            if (exts[i] == 1):
                res.append(flag[1])
            else:
                res.append(flag[0])
        else:
            if (exts[i] == 1):
                res.append(flag)

    res = list(set(res))
    return " ".join(res)

def get_compiler_flags_arch_id(arch_id, os, comp, comp_ver):
    exts = decode_extensions(arch_id)
    return get_compiler_flags(exts, os, comp, comp_ver)


