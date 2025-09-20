#!/usr/bin/env python3
# Test script to verify CSSC instruction decompilation in Ghidra
# Run this script in Ghidra's Script Manager after opening a binary with CSSC instructions

from ghidra.app.decompiler import DecompInterface
from ghidra.program.model.address import AddressSet
from ghidra.util.task import ConsoleTaskMonitor

def test_cssc_decompilation():
    """Test that CSSC instructions decompile to intrinsic calls"""

    # Known address with CSSC instructions
    test_addr = currentProgram.getAddressFactory().getAddress("0xfffffe0008370cc0")

    # Initialize decompiler
    decompiler = DecompInterface()
    decompiler.openProgram(currentProgram)

    # Get the function containing our test address
    func = getFunctionContaining(test_addr)
    if func is None:
        print("ERROR: No function found at test address")
        return False

    print(f"Testing decompilation of function: {func.getName()} at {func.getEntryPoint()}")
    print("-" * 60)

    # Decompile the function
    results = decompiler.decompileFunction(func, 30, ConsoleTaskMonitor())

    if results.decompileCompleted():
        decomp_src = results.getDecompiledFunction()
        c_code = decomp_src.getC()

        # Check for our intrinsics in the decompiled output
        intrinsics = ["__cssc_umax", "__cssc_umin", "__cssc_smax", "__cssc_smin",
                      "__cssc_abs", "__cssc_cnt", "__cssc_ctz"]

        found_intrinsics = []
        for intrinsic in intrinsics:
            if intrinsic in c_code:
                found_intrinsics.append(intrinsic)

        if found_intrinsics:
            print("SUCCESS: Found CSSC intrinsics in decompiled output:")
            for name in found_intrinsics:
                print(f"  - {name}")
            print("\nRelevant decompiled code snippet:")
            # Print lines containing intrinsics
            for line in c_code.split('\n'):
                for intrinsic in found_intrinsics:
                    if intrinsic in line:
                        print(f"  {line.strip()}")
                        break
        else:
            print("WARNING: No CSSC intrinsics found in decompiled output")
            print("This might indicate the pcodeop definitions aren't being recognized")
            print("\nFirst 20 lines of decompiled output:")
            lines = c_code.split('\n')[:20]
            for line in lines:
                print(f"  {line}")

        return len(found_intrinsics) > 0
    else:
        print(f"ERROR: Decompilation failed: {results.getErrorMessage()}")
        return False

    decompiler.dispose()

# Run the test
if __name__ == "__main__":
    success = test_cssc_decompilation()
    if success:
        print("\n✓ CSSC decompilation test PASSED")
    else:
        print("\n✗ CSSC decompilation test FAILED")