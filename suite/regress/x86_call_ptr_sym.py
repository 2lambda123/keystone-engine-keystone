#!/usr/bin/python
# Marco Bartoli, 2016

# This is to test call [label] on X86.

# Github issue: #271
# Author: Marco Bartoli (wsxarcher)


from keystone import *
import regress

def sym_resolver(symbol):
    """"Resolves a given symbol to its corresponding address in memory."
    Parameters:
        - symbol (bytes): The symbol to be resolved.
    Returns:
        - int: The address of the symbol in memory, or None if the symbol cannot be resolved.
    Processing Logic:
        - Resolves the given symbol to its corresponding address.
        - Returns the address if found, otherwise returns None."""
    
    if symbol == b'GetPhoneBuildString':
        return 0x41b000
    return None

class TestX86Nasm(regress.RegressTest):
    def runTest(self):
        """Assembles x86 32-bit NASM code and returns the encoded instructions.
        Parameters:
            - ks (Ks): The Ks object used for assembling.
            - sym_resolver (function): A function used to resolve symbols.
        Returns:
            - encoding (list): A list of encoded instructions.
            - count (int): The number of encoded instructions.
        Processing Logic:
            - Initialize Ks object with x86 architecture and 32-bit mode.
            - Set syntax to NASM.
            - Set symbol resolver function.
            - Assemble the given code.
            - Assert that the encoded instructions match the expected result."""
        
        ks = Ks(KS_ARCH_X86, KS_MODE_32)
        ks.syntax = KS_OPT_SYNTAX_NASM
        ks.sym_resolver = sym_resolver
        encoding, count = ks.asm(b"call [GetPhoneBuildString]")
        self.assertEqual(encoding, [ 0xff, 0x15, 0x00, 0xb0, 0x41, 0x00 ])


class TestX86Intel(regress.RegressTest):
    def runTest(self):
        """Assembles an x86 instruction using the Keystone engine.
        Parameters:
            - ks (Ks): An instance of the Keystone engine.
            - syntax (int): The syntax mode to use for assembly.
            - sym_resolver (function): A function used to resolve symbols.
        Returns:
            - encoding (list): A list of bytes representing the assembled instruction.
            - count (int): The number of bytes in the assembled instruction.
        Processing Logic:
            - Uses the Keystone engine to assemble an x86 instruction.
            - Allows for the specification of a syntax mode.
            - Uses a symbol resolver function to resolve symbols.
            - Returns the assembled instruction as a list of bytes and the number of bytes in the instruction.
        Example:
            ks = Ks(KS_ARCH_X86, KS_MODE_32)
            ks.syntax = KS_OPT_SYNTAX_INTEL
            ks.sym_resolver = sym_resolver
            encoding, count = ks.asm(b"call [GetPhoneBuildString]")
            # encoding = [ 0xff, 0x15, 0x00, 0xb0, 0x41, 0x00 ]
            # count = 6"""
        
        ks = Ks(KS_ARCH_X86, KS_MODE_32)
        ks.syntax = KS_OPT_SYNTAX_INTEL
        ks.sym_resolver = sym_resolver
        encoding, count = ks.asm(b"call [GetPhoneBuildString]")
        self.assertEqual(encoding, [ 0xff, 0x15, 0x00, 0xb0, 0x41, 0x00 ])


class TestX86Att(regress.RegressTest):
    def runTest(self):
        """Assembles the given instructions using the Keystone library and checks if the result matches the expected encoding.
        Parameters:
            - self (object): The current instance of the class.
            - ks (object): The Keystone object used for assembling.
            - sym_resolver (function): The symbol resolver function used by Keystone.
        Returns:
            - encoding (list): A list of bytes representing the assembled instructions.
            - count (int): The number of instructions that were assembled.
        Processing Logic:
            - Uses the Keystone library to assemble the given instructions.
            - Checks if the result matches the expected encoding.
            - Uses a symbol resolver function for resolving symbols during assembly.
        Example:
            ks = Ks(KS_ARCH_X86, KS_MODE_32)
            ks.syntax = KS_OPT_SYNTAX_ATT
            ks.sym_resolver = sym_resolver
            encoding, count = ks.asm(b"call *GetPhoneBuildString")
            self.assertEqual(encoding, [ 0xff, 0x15, 0x00, 0xb0, 0x41, 0x00 ])"""
        
        ks = Ks(KS_ARCH_X86, KS_MODE_32)
        ks.syntax = KS_OPT_SYNTAX_ATT
        ks.sym_resolver = sym_resolver
        encoding, count = ks.asm(b"call *GetPhoneBuildString")
        self.assertEqual(encoding, [ 0xff, 0x15, 0x00, 0xb0, 0x41, 0x00 ])


if __name__ == '__main__':
    regress.main()
