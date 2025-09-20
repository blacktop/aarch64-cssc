# aarch64-cssc

AArch64 FEAT_CSSC instruction support for IDA Pro and Ghidra.

## Installation

### IDA Pro

```bash
# Install plugin
./plugins/ida/install.sh

# Development mode (symlinks for live editing)
IDA_PLUGIN_MODE=link ./plugins/ida/install.sh

# Custom IDA plugins directory
./plugins/ida/install.sh /path/to/ida/plugins
```

Restart IDA Pro after installation.

### Ghidra

```bash
# Install and rebuild language pack
GHIDRA_HOME=/path/to/ghidra ./plugins/ghidra/install.sh

# Skip SLEIGH rebuild (manual rebuild required)
GHIDRA_HOME=/path/to/ghidra ./plugins/ghidra/install.sh --skip-build
```

#### Use my macOS app *(shameless self-plug)*

Install nice stand-alone macOS app packaged version of Ghidra

```bash
brew install --cask blacktop/tap/ghidra-app 
```

Install the lanuage extension

```bash
./plugins/ghidra/install.sh /Applications/Ghidra.app/Contents/Resources/ghidra
```

Re-import or reopen binaries in Ghidra after installation.

## Usage

### IDA Pro
The plugin auto-loads when opening AArch64 binaries. If needed, manually load via: Edit → Plugins → AArch64 CSSC

### Ghidra
Instructions are automatically recognized after installation. No manual activation required.

## Supported Instructions

### IDA Pro
- UMAX/UMIN (register, 32/64-bit)
- Hex-Rays decompiler intrinsics: `__cssc_umax`, `__cssc_umin`

### Ghidra
- ABS (register, 32/64-bit)
- CNT (register, 32/64-bit)
- CTZ (register, 32/64-bit)
- SMAX/SMIN (register, 32/64-bit)
- UMAX/UMIN (register, 32/64-bit)
- Decompiler intrinsics: `__cssc_abs`, `__cssc_cnt`, `__cssc_ctz`
- Min/max operations use conditional patterns recognized by the decompiler

## Adding Instructions

### IDA Pro
Edit `plugins/ida/aarch64_cssc.py` and add entries to `CSSC_INSTRUCTIONS` list.

### Ghidra
Edit `plugins/ghidra/sleigh/AARCH64_CSSC.sinc` following existing patterns.

## Reference

ARM instruction encodings: `arm-xml/isa_a64/ISA_A64_xml_A_profile-2025-06/`

## Credit

Shout out to dougall's [Apple AMX plugin](https://gist.github.com/dougallj/7a75a3be1ec69ca550e7c36dc75e0d6f)

## License

MIT Copyright (c) 2025 **blacktop**
