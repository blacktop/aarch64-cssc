# aarch64-cssc

AArch64 FEAT_CSSC support for IDA Pro (disassembler/Hex-Rays) and Ghidra.

## Ghidra
- Complete SLEIGH implementation for FEAT_CSSC `ABS`, `CNT`, `CTZ`, `SMAX/SMIN`,
  and `UMAX/UMIN` (both register and immediate forms) under `plugins/ghidra/`
  (`sleigh/AARCH64_CSSC.sinc`).
- Install via `plugins/ghidra/install.sh` which copies the SLEIGH file, updates the
  language spec, and invokes Ghidra's `support/sleigh` to rebuild the processor
  definition automatically (pass `--skip-build` to defer the compile).
- Reopen binaries in Ghidra to pick up the refreshed instruction semantics.

## Installation
1. Run `plugins/ida/install.sh` (set `IDA_PLUGIN_MODE=link` to symlink instead of copy).
2. Restart IDA or reload plugins. Watch the Output window for messages prefixed with `[CSSC]`.

## Load Plug-in

> [!NOTE]  
> Plugin should auto-load, but if it doesn't you can load it this way:  
> Edit -> Plugins -> AArch64 CSSC  

## Current Status

### IDA Pro Plugin
- Disassembles FEAT_CSSC 32-bit and 64-bit `umax`/`umin` (register) using custom mnemonics.
- Emits Hex-Rays intrinsics `__cssc_umax`/`__cssc_umin` (64-bit) and `__cssc_umax32`/`__cssc_umin32` (32-bit).
- Additional FEAT_CSSC instructions can be added in `plugins/ida/aarch64_cssc.py`.

### Ghidra Plugin
- Complete SLEIGH implementation for all FEAT_CSSC instructions (`ABS`, `CNT`, `CTZ`, `SMAX/SMIN`, `UMAX/UMIN`).
- Supports both register and immediate forms in 32-bit and 64-bit widths.
- Correct bit patterns and P-Code semantics for proper disassembly and decompilation.

## Reference encodings
- `arm-xml/isa_a64/ISA_A64_xml_A_profile-2025-06/umax_reg.xml`
- `arm-xml/isa_a64/ISA_A64_xml_A_profile-2025-06/umin_reg.xml`

## Credit

Shout out to dougall's [Apple AMX plugin](https://gist.github.com/dougallj/7a75a3be1ec69ca550e7c36dc75e0d6f)

## License

MIT Copyright (c) 2025 **blacktop**
