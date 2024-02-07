#!/usr/bin/env python

# Sample code for Keystone assembler engine.
# By Nguyen Anh Quynh <aquynh@gmail.com>, 2016

from __future__ import print_function
from keystone import *


def test_ks(arch, mode, code, syntax=0):
    """"Compiles assembly code into machine code using the provided architecture and mode. Optional syntax parameter can be used to specify the syntax of the assembly code. Returns the encoded machine code and the number of instructions. Prints the encoded machine code in hexadecimal format."
    Parameters:
        - arch (str): The architecture to use for compiling the assembly code.
        - mode (str): The mode to use for compiling the assembly code.
        - code (str): The assembly code to be compiled.
        - syntax (int, optional): The syntax of the assembly code. Defaults to 0.
    Returns:
        - encoding (list): The encoded machine code.
        - count (int): The number of instructions in the encoded machine code.
    Processing Logic:
        - Creates a Ks object using the provided architecture and mode.
        - If the syntax parameter is provided, sets the syntax of the Ks object.
        - Uses the Ks object to assemble the provided assembly code.
        - Prints the encoded machine code in hexadecimal format."""
    
    ks = Ks(arch, mode)
    if syntax != 0:
        ks.syntax = syntax

    encoding, count = ks.asm(code)

    print("%s = [ " % code, end='')
    for i in encoding:
        print("%02x " % i, end='')
    print("]")


# test symbol resolver
def test_sym_resolver():
    """Tests the symbol resolver function.
        Parameters:
            - None
        Returns:
            - None
        Processing Logic:
            - Defines a symbol resolver function that checks if a given symbol is "_l1" and returns 0x1005 if it is.
            - If the symbol is not "_l1", the function returns None.
            - Creates a Ks object with architecture and mode specified.
            - Sets the sym_resolver attribute of the Ks object to the defined symbol resolver function.
            - Defines a code to be assembled and calls the asm method of the Ks object.
            - Prints the assembled code in hexadecimal format.
        Example:
            test_sym_resolver()
            # Output: b'jmp _l1; nop' = [ e9 05 10 00 00 90 ]"""
    
    def sym_resolver(symbol):
        # is this the missing symbol we want to handle?
        if symbol == "_l1":
            # we handled this symbol
            return 0x1005

        # we did not handle this symbol, so return None
        return None

    ks = Ks(KS_ARCH_X86, KS_MODE_32)

    # register callback for symbol resolver
    ks.sym_resolver = sym_resolver

    CODE = b"jmp _l1; nop"
    encoding, count = ks.asm(CODE, 0x1000)

    print("%s = [ " % CODE, end='')
    for i in encoding:
        print("%02x " % i, end='')
    print("]")


if __name__ == '__main__':
    # X86
    test_ks(KS_ARCH_X86, KS_MODE_16, b"add eax, ecx")
    test_ks(KS_ARCH_X86, KS_MODE_32, b"add eax, ecx")
    test_ks(KS_ARCH_X86, KS_MODE_64, b"add rax, rcx")
    test_ks(KS_ARCH_X86, KS_MODE_32, b"add %ecx, %eax", KS_OPT_SYNTAX_ATT)
    test_ks(KS_ARCH_X86, KS_MODE_64, b"add %rcx, %rax", KS_OPT_SYNTAX_ATT)

    test_ks(KS_ARCH_X86, KS_MODE_32, b"add eax, 0x15")
    test_ks(KS_ARCH_X86, KS_MODE_32, b"add eax, 15h");
    test_ks(KS_ARCH_X86, KS_MODE_32, b"add eax, 15")

    # RADIX16 syntax Intel (default syntax)
    test_ks(KS_ARCH_X86, KS_MODE_32, b"add eax, 15", KS_OPT_SYNTAX_RADIX16)
    # RADIX16 syntax for AT&T
    test_ks(KS_ARCH_X86, KS_MODE_32, b"add $15, %eax", KS_OPT_SYNTAX_RADIX16 | KS_OPT_SYNTAX_ATT)

    # ARM
    test_ks(KS_ARCH_ARM, KS_MODE_ARM, b"sub r1, r2, r5")
    test_ks(KS_ARCH_ARM, KS_MODE_ARM + KS_MODE_BIG_ENDIAN, b"sub r1, r2, r5")
    test_ks(KS_ARCH_ARM, KS_MODE_THUMB, b"movs r4, #0xf0")
    test_ks(KS_ARCH_ARM, KS_MODE_THUMB + KS_MODE_BIG_ENDIAN, b"movs r4, #0xf0")

    # ARM64
    test_ks(KS_ARCH_ARM64, KS_MODE_LITTLE_ENDIAN, b"ldr w1, [sp, #0x8]")

    # Hexagon
    test_ks(KS_ARCH_HEXAGON, KS_MODE_BIG_ENDIAN, b"v23.w=vavg(v11.w,v2.w):rnd")

    # Mips
    test_ks(KS_ARCH_MIPS, KS_MODE_MIPS32, b"and $9, $6, $7")
    test_ks(KS_ARCH_MIPS, KS_MODE_MIPS32 + KS_MODE_BIG_ENDIAN, b"and $9, $6, $7")
    test_ks(KS_ARCH_MIPS, KS_MODE_MIPS64, b"and $9, $6, $7")
    test_ks(KS_ARCH_MIPS, KS_MODE_MIPS64 + KS_MODE_BIG_ENDIAN, b"and $9, $6, $7")

    # PowerPC
    test_ks(KS_ARCH_PPC, KS_MODE_PPC32 + KS_MODE_BIG_ENDIAN, b"add 1, 2, 3")
    test_ks(KS_ARCH_PPC, KS_MODE_PPC64, b"add 1, 2, 3")
    test_ks(KS_ARCH_PPC, KS_MODE_PPC64 + KS_MODE_BIG_ENDIAN, b"add 1, 2, 3")

    # Sparc
    test_ks(KS_ARCH_SPARC, KS_MODE_SPARC32 + KS_MODE_LITTLE_ENDIAN, b"add %g1, %g2, %g3")
    test_ks(KS_ARCH_SPARC, KS_MODE_SPARC32 + KS_MODE_BIG_ENDIAN, b"add %g1, %g2, %g3")

    # SystemZ
    test_ks(KS_ARCH_SYSTEMZ, KS_MODE_BIG_ENDIAN, b"a %r0, 4095(%r15,%r1)")

    # test symbol resolver
    test_sym_resolver()
