#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'EOF'
usage: GHIDRA_HOME=/path/to/ghidra install.sh [options] [ghidra_home]

Options:
  --skip-build   Skip invoking support/sleigh after copying the SLEIGH include

Either set GHIDRA_HOME or supply the path as the final argument.
EOF
}

SKIP_BUILD=0
POS_ARG=""

while [[ $# -gt 0 ]]; do
  case "$1" in
    --skip-build)
      SKIP_BUILD=1
      shift
      ;;
    --help|-h)
      usage
      exit 0
      ;;
    *)
      if [[ -n "$POS_ARG" ]]; then
        echo "error: unexpected argument '$1'" >&2
        usage
        exit 1
      fi
      POS_ARG="$1"
      shift
      ;;
  esac
done

if [[ ${GHIDRA_HOME:-} == "" && $POS_ARG == "" ]]; then
  usage
  exit 1
fi

GHIDRA_HOME=${GHIDRA_HOME:-$POS_ARG}
TARGET_DIR="$GHIDRA_HOME/Ghidra/Processors/AARCH64/data/languages"
SOURCE_FILE="$(dirname "$0")/sleigh/AARCH64_CSSC.sinc"
TARGET_FILE="$TARGET_DIR/AARCH64_CSSC.sinc"

if [[ ! -d "$TARGET_DIR" ]]; then
  echo "error: could not find AARCH64 language directory at $TARGET_DIR" >&2
  exit 1
fi

cp "$SOURCE_FILE" "$TARGET_FILE"

SLASPEC_FILE="$TARGET_DIR/AARCH64_AppleSilicon.slaspec"
INCLUDE_LINE='@include "AARCH64_CSSC.sinc"'
appended=0

if [[ -f "$SLASPEC_FILE" ]]; then
  if ! grep -Fxq "$INCLUDE_LINE" "$SLASPEC_FILE"; then
    printf '\n%s\n' "$INCLUDE_LINE" >> "$SLASPEC_FILE"
    appended=1
  fi
else
  echo "warning: could not find $SLASPEC_FILE; please add $INCLUDE_LINE manually" >&2
fi

build_msg="Skipped SLEIGH rebuild (use --skip-build or CSSC_SKIP_SLEIGH=1)."

if [[ ${CSSC_SKIP_SLEIGH:-} != "" ]]; then
  SKIP_BUILD=1
fi

if [[ $SKIP_BUILD -eq 0 ]]; then
  PROCESSOR_ROOT="$GHIDRA_HOME/Ghidra/Processors/AARCH64"
  SLEIGH_BIN="$GHIDRA_HOME/support/sleigh"
  SPEC_TARGET="data/languages"

  if [[ -x "$SLEIGH_BIN" && -d "$PROCESSOR_ROOT" && -d "$PROCESSOR_ROOT/$SPEC_TARGET" ]]; then
    log_file=$(mktemp -t cssc_sleigh).log
    if (cd "$PROCESSOR_ROOT" && "$SLEIGH_BIN" -a "$SPEC_TARGET" >"$log_file" 2>&1); then
      build_msg="Rebuilt AARCH64 language pack (log: $log_file)."
    else
      build_msg="Failed to rebuild SLEIGH spec (see $log_file); rerun manually."
    fi
  else
    build_msg="support/sleigh or language directory not found; rebuild manually via support/sleigh -a $SPEC_TARGET."
  fi
else
  build_msg="Skipped SLEIGH rebuild (--skip-build or CSSC_SKIP_SLEIGH set)."
fi

cat <<MSG
Copied AARCH64_CSSC.sinc.
$( [[ $appended -eq 1 ]] && echo "Updated $(basename "$SLASPEC_FILE") with $INCLUDE_LINE." || echo "$INCLUDE_LINE already present in $(basename "$SLASPEC_FILE") or file missing.")
${build_msg}
Next steps:
  1. Re-import or reopen your target binary in Ghidra to refresh disassembly
MSG
