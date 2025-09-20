# Ghidra FEAT_CSSC Support

Support files for teaching Ghidra about the AArch64 FEAT_CSSC
extension. Coverage includes the register and immediate forms of the
following instructions in both 32-bit and 64-bit widths:

- `ABS` – Absolute value
- `CNT` – Population count (bit count)
- `CTZ` – Count trailing zeros
- `SMAX` / `SMIN` – Signed maximum/minimum
- `UMAX` / `UMIN` – Unsigned maximum/minimum

## Contents
- `sleigh/AARCH64_CSSC.sinc` – SLEIGH constructors for all FEAT_CSSC instructions with correct bit patterns and P-Code semantics.

## Usage
1. Locate your Ghidra installation (e.g. `/Applications/ghidra_11.1.1`).
2. Copy `sleigh/AARCH64_CSSC.sinc` into `Ghidra/Processors/AARCH64/data/languages/`
   (the helper script `plugins/ghidra/install.sh` automates this step and runs
   `support/sleigh -a data/languages/AARCH64_AppleSilicon.slaspec` for you).
3. Launch Ghidra, re-import an AArch64 binary, and verify that the CSSC
   encodings disassemble with the expected p-code.

> Tip: Use Ghidra's "Show Pcode" window on a CSSC instruction to confirm the
> generated p-code performs an unsigned comparison and selects the appropriate
> operand.

## Next Steps
- Test the implementation with actual FEAT_CSSC instruction encodings.
- Consider creating a dedicated processor variant for cleaner integration.
- Package as a Ghidra extension for easier distribution.
- Add unit tests for instruction semantics validation.
