# Ghidra FEAT_CSSC Support

AArch64 FEAT_CSSC instruction support for Ghidra.

## Installation

```bash
# Install with automatic SLEIGH rebuild
GHIDRA_HOME=/path/to/ghidra ./install.sh

# Install without rebuilding (manual rebuild required)
GHIDRA_HOME=/path/to/ghidra ./install.sh --skip-build
```

## Supported Instructions

All instructions support both 32-bit (W registers) and 64-bit (X registers) variants:

- `abs` - Absolute value
- `cnt` - Population count
- `ctz` - Count trailing zeros
- `smax` - Signed maximum
- `smin` - Signed minimum
- `umax` - Unsigned maximum
- `umin` - Unsigned minimum

## Implementation Details

### Files
- `sleigh/AARCH64_CSSC.sinc` - SLEIGH instruction definitions
- `install.sh` - Installation script

### Decompiler Output
- ABS/CNT/CTZ use pcodeop intrinsics (`__cssc_abs`, `__cssc_cnt`, `__cssc_ctz`)
- MIN/MAX use conditional patterns that the decompiler recognizes

## Verification

After installation, re-import your binary and check:
1. Instructions disassemble correctly (e.g., `umax x8,x3,x1`)
2. Decompiler shows appropriate operations or intrinsic calls
3. Use "Show Pcode" window to verify instruction semantics

## Adding Instructions

Edit `sleigh/AARCH64_CSSC.sinc` following the existing patterns. Each instruction needs:
- Correct bit pattern matching
- Proper operand decoding
- P-code semantics or pcodeop declaration