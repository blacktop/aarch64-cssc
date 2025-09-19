# aarch64-cssc

IDA (disassembler) and Hex-Rays (decompiler) plugin for FEAT_CSSC

## Installation
1. Run `plugins/ida/install.sh` (set `IDA_PLUGIN_MODE=link` to symlink instead of copy).
2. Restart IDA or reload plugins. Watch the Output window for messages prefixed with `[CSSC]`.

## Current Status
- Disassembles FEAT_CSSC 64-bit `umax` (register) using custom mnemonic.
- Disassembles FEAT_CSSC 64-bit `umin` (register) using custom mnemonic.
- Emits Hex-Rays intrinsics `__cssc_umax` / `__cssc_umin` so decompiled pseudo-code retains semantics.
- Additional FEAT_CSSC instructions can be added in `plugins/ida/aarch64_cssc.py` by extending the instruction table.

## Reference encodings
- `arm-xml/isa_a64/ISA_A64_xml_A_profile-2025-06/umax_reg.xml`
- `arm-xml/isa_a64/ISA_A64_xml_A_profile-2025-06/umin_reg.xml`

## Credit

Shout out to dougall's [Apple AMX plugin](https://gist.github.com/dougallj/7a75a3be1ec69ca550e7c36dc75e0d6f)

## License

MIT Copyright (c) 2025 **blacktop**