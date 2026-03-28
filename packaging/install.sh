#!/bin/sh
set -eu

INSTALL_PREFIX="${CONNECT_INSTALL_PREFIX:-/usr/local}"
BIN_DIR="$INSTALL_PREFIX/bin"
SOURCE_DIR="$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)"
SOURCE_BINARY="$SOURCE_DIR/connect"
PROFILE_SNIPPET="/etc/profile.d/connect.sh"

# Default install target: /usr/local/bin/connect

if [ ! -f "$SOURCE_BINARY" ]; then
  printf 'expected release binary at %s\n' "$SOURCE_BINARY" >&2
  exit 1
fi

install -d "$BIN_DIR"
install -m 755 "$SOURCE_BINARY" "$BIN_DIR/connect"

case ":${PATH:-}:" in
  *":$BIN_DIR:"*) ;;
  *)
    if [ -d /etc/profile.d ] && [ -w /etc/profile.d ]; then
      cat >"$PROFILE_SNIPPET" <<EOF
#!/bin/sh
export PATH="$BIN_DIR:\$PATH"
EOF
      chmod 755 "$PROFILE_SNIPPET"
      printf 'Added %s to PATH via %s\n' "$BIN_DIR" "$PROFILE_SNIPPET"
    else
      USER_PROFILE="${HOME:-}/.profile"
      MARKER="# connect PATH"
      if [ -n "${HOME:-}" ]; then
        touch "$USER_PROFILE"
        if ! grep -Fq "$MARKER" "$USER_PROFILE"; then
          {
            printf '\n%s\n' "$MARKER"
            printf 'export PATH="%s:$PATH"\n' "$BIN_DIR"
          } >>"$USER_PROFILE"
        fi
        printf 'Added %s to PATH via %s\n' "$BIN_DIR" "$USER_PROFILE"
      else
        printf 'warning: could not update PATH automatically for %s\n' "$BIN_DIR" >&2
      fi
    fi
    ;;
esac

printf 'Installed connect to %s/connect\n' "$BIN_DIR"
