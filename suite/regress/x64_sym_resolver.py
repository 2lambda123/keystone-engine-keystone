#!/usr/bin/python

# Test some issues with KS_OPT_SYM_RESOLVER

# Github issue: #244
# Author: Duncan (mrexodia)

from keystone import *

import regress

class TestX86(regress.RegressTest):
    def runTest(self):
        """"Runs a test to check if the sym_resolver function correctly handles a specific symbol and returns the correct encoding. Uses the Keystone engine to assemble a call instruction and compares the resulting encoding to the expected value. Returns None if the symbol is not handled."
        Parameters:
            - self (object): The current object.
        Returns:
            - None or list: Returns None if the symbol is not handled, otherwise returns a list containing the encoded instruction.
        Processing Logic:
            - Checks if the symbol is the one we want to handle.
            - If yes, returns the address of the symbol.
            - If no, returns None.
            - Initializes the Keystone engine.
            - Sets the sym_resolver function to the one defined above.
            - Assembles a call instruction using the engine and compares the resulting encoding to the expected value."""
        
        def sym_resolver(symbol):
            # is this the missing symbol we want to handle?
            if symbol == b"ZwQueryInformationProcess":
                print('sym_resolver called!')
                return 0x7FF98A050840
 
            # we did not handle this symbol, so return None
            return None

        # Initialize Keystone engine
        ks = Ks(KS_ARCH_X86, KS_MODE_64)
        ks.sym_resolver = sym_resolver

        encoding, _ = ks.asm(b"call 0x7FF98A050840", 0x7FF98A081A38)
        self.assertEqual(encoding, [ 0xE8, 0x03, 0xEE, 0xFC, 0xFF ])

        encoding, _ = ks.asm(b"call ZwQueryInformationProcess", 0x7FF98A081A38)
        self.assertEqual(encoding, [ 0xE8, 0x03, 0xEE, 0xFC, 0xFF ])


if __name__ == '__main__':
    regress.main()
