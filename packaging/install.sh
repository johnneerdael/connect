#!/bin/sh
set -eu

INSTALL_PREFIX="${CONNECT_INSTALL_PREFIX:-/usr/local}"
BIN_DIR="$INSTALL_PREFIX/bin"
SOURCE_DIR="$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)"
SOURCE_BINARY="$SOURCE_DIR/connect"

# Default install target: /usr/local/bin/connect

if [ ! -f "$SOURCE_BINARY" ]; then
  printf 'expected release binary at %s\n' "$SOURCE_BINARY" >&2
  exit 1
fi

install -d "$BIN_DIR"
install -m 755 "$SOURCE_BINARY" "$BIN_DIR/connect"

printf 'Installed connect to %s/connect\n' "$BIN_DIR"
