#!/usr/bin/env bash

set -o errexit
set -o pipefail
if [[ "${TRACE-0}" == "1" ]]; then
    set -o xtrace
fi

CWD="$(cd -P -- "$(dirname -- "$0")" && pwd -P)"
DEFAULT_TARGET="$HOME/.idapro/plugins/aarch64_cssc"
TARGET_DIR="${1:-$DEFAULT_TARGET}"

usage() {
    cat <<'USAGE'
Usage: install.sh [target_directory]

Copy the FEAT_CSSC plugin (metadata + entry point) into the specified IDA
plugins directory. If no directory is provided, the default is
~/.idapro/plugins/aarch64_cssc.

Set IDA_PLUGIN_MODE=link to create symlinks instead of copying.
USAGE
}

if [[ "${1-}" =~ ^-*h(elp)?$ ]]; then
    usage
    exit 0
fi

mkdir -p "$TARGET_DIR"

install_file() {
    local src="$1"
    local dst="$2"
    if [[ "${IDA_PLUGIN_MODE-}" == "link" ]]; then
        ln -sfn "$src" "$dst"
    else
        cp "$src" "$dst"
    fi
}

install_file "$CWD/ida-plugin.json" "$TARGET_DIR/ida-plugin.json"
install_file "$CWD/aarch64_cssc.py" "$TARGET_DIR/aarch64_cssc.py"

echo "  🚀 Installed CSSC plugin to $TARGET_DIR"
if [[ "${IDA_PLUGIN_MODE-}" == "link" ]]; then
    echo "  🔗 Files linked; reload IDA to pick up changes."
else
    echo "  📦 Files copied; restart IDA or reload plugins to activate."
fi
