#!/bin/sh
# Install lscore.py, and its man page when present.
#
#   ./install.sh                 root -> /usr/local/bin, otherwise ~/.local/bin
#   ./install.sh --user          ~/.local/bin
#   ./install.sh --system        /usr/local/bin
#   ./install.sh --prefix DIR    an absolute bin directory
#   ./install.sh --force         replace a different program called lscore
#
set -eu

unset CDPATH
SRC_DIR=$(cd "$(dirname "$0")" && pwd)
SRC=$SRC_DIR/lscore.py
MARKER=lscore-install-marker:0d3f5a1c9b7e

MODE=auto
TARGET=
PREFIX=
FORCE=0
SUDO=
TMP=

err() { printf 'install.sh: %s\n' "$*" >&2; }
info() { printf '  %s\n' "$*"; }

cleanup() {
    [ -z "$TMP" ] || $SUDO rm -f "$TMP" 2>/dev/null || true
}
trap cleanup EXIT
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 143' TERM

usage() {
    cat <<'EOF'
Usage: ./install.sh [options]

  (no option)      /usr/local/bin as root, ~/.local/bin otherwise
  --user           ~/.local/bin
  --system         /usr/local/bin
  --prefix DIR     an absolute bin directory
  --force          replace a different program called lscore

The man page is installed under <prefix>/../share/man/man1 when available.
EOF
}

# The marker identifies our files. Releases up to 0.3.0 only had the name and
# CLI strings, so accept those too.
is_lscore() {
    grep -qF -e "$MARKER" "$1" 2>/dev/null && return 0
    grep -qF -e 'Linux Score' "$1" 2>/dev/null &&
        grep -qF -e '--no-history' "$1" 2>/dev/null &&
        grep -qF -e '__version__' "$1" 2>/dev/null
}

normalize_prefix() {
    case "$1" in
        /*) ;;
        *) err "--prefix must be an absolute path"; return 1 ;;
    esac
    PREFIX=$1
    while [ "${PREFIX%/}" != "$PREFIX" ]; do PREFIX=${PREFIX%/}; done
    if [ -z "$PREFIX" ] || [ "$PREFIX" = / ]; then
        err "--prefix cannot be /"
        return 1
    fi
}

under_home() {
    [ -n "${HOME:-}" ] || return 1
    case "$1" in "$HOME"/*) return 0 ;; esac
    return 1
}

need_sudo() {
    SUDO=
    if [ ! -w "$1" ] && ! under_home "$1" && command -v sudo >/dev/null 2>&1; then
        SUDO=sudo
    fi
}

# Copy into a temporary file next to the destination, so a failed copy never
# leaves a half-written program behind.
stage() {
    dir=$(dirname "$2")
    TMP=$(mktemp "$dir/.lscore.XXXXXX" 2>/dev/null) || {
        err "cannot create a temporary file in $dir"
        return 1
    }
    $SUDO cp "$1" "$TMP" && $SUDO chmod "$3" "$TMP" || return 1
}

commit() {
    $SUDO mv -f "$TMP" "$1" || return 1
    TMP=
}

while [ $# -gt 0 ]; do
    case "$1" in
        --user) MODE=user ;;
        --system) MODE=system ;;
        --prefix)
            [ $# -ge 2 ] || { err "--prefix needs a directory"; exit 2; }
            normalize_prefix "$2" || exit 2
            MODE=prefix
            shift
            ;;
        --force) FORCE=1 ;;
        -h|--help) usage; exit 0 ;;
        *) err "unknown option: $1 (try --help)"; exit 2 ;;
    esac
    shift
done

case "$MODE" in
    prefix) TARGET=$PREFIX ;;
    user) TARGET=${HOME:?HOME is not set}/.local/bin ;;
    system) TARGET=/usr/local/bin ;;
    auto)
        if [ "$(id -u)" -eq 0 ]; then
            TARGET=/usr/local/bin
        else
            TARGET=${HOME:?HOME is not set}/.local/bin
        fi
        ;;
esac

[ -f "$SRC" ] || { err "lscore.py not found next to this script"; exit 1; }
if ! grep -qF -e "$MARKER" "$SRC" 2>/dev/null; then
    err "$SRC is not an lscore source file"
    exit 1
fi

if ! command -v python3 >/dev/null 2>&1; then
    err "python3 not found; lscore needs Python 3.8 or newer"
    exit 1
fi
if ! python3 -c 'import sys; sys.exit(sys.version_info < (3, 8))'; then
    err "found $(python3 -V 2>&1); lscore needs Python 3.8 or newer"
    exit 1
fi

if [ -e "$TARGET/lscore" ] && [ ! -f "$TARGET/lscore" ]; then
    err "$TARGET/lscore is not a regular file"
    exit 1
fi
if [ -e "$TARGET/lscore" ] && [ "$FORCE" -eq 0 ] && ! is_lscore "$TARGET/lscore"; then
    err "$TARGET/lscore is not lscore; use --force to replace it"
    exit 1
fi

if ! mkdir -p "$TARGET" 2>/dev/null; then
    if command -v sudo >/dev/null 2>&1 && ! under_home "$TARGET"; then
        sudo mkdir -p "$TARGET"
    else
        err "cannot create $TARGET; use --user or --prefix DIR"
        exit 1
    fi
fi
need_sudo "$TARGET"

if ! stage "$SRC" "$TARGET/lscore" 0755; then
    err "cannot write to $TARGET"
    exit 1
fi

VERSION=$("$TMP" --version 2>/dev/null | head -n 1 || true)
if [ -z "$VERSION" ]; then
    err "the new copy does not run"
    exit 1
fi
if ! commit "$TARGET/lscore"; then
    err "cannot replace $TARGET/lscore"
    exit 1
fi
info "installed $VERSION -> $TARGET/lscore"

MAN_SRC=$SRC_DIR/man/lscore.1
MAN_DIR=$(dirname "$TARGET")/share/man/man1
MAN_PAGE=$MAN_DIR/lscore.1

if [ ! -f "$MAN_SRC" ]; then
    info "no man page next to this script"
elif ! grep -qF -e "$MARKER" "$MAN_SRC" 2>/dev/null; then
    info "man/lscore.1 is not ours; skipping it"
elif [ -e "$MAN_PAGE" ] && [ ! -f "$MAN_PAGE" ]; then
    info "$MAN_PAGE is not a regular file; skipping it"
elif [ -e "$MAN_PAGE" ] && [ "$FORCE" -eq 0 ] &&
        ! grep -qF -e "$MARKER" "$MAN_PAGE" 2>/dev/null; then
    info "$MAN_PAGE is not ours; skipping it"
else
    if ! mkdir -p "$MAN_DIR" 2>/dev/null; then
        if command -v sudo >/dev/null 2>&1 && ! under_home "$MAN_DIR"; then
            sudo mkdir -p "$MAN_DIR" || MAN_PAGE=
        else
            MAN_PAGE=
        fi
    fi
    if [ -n "$MAN_PAGE" ]; then
        need_sudo "$MAN_DIR"
        if stage "$MAN_SRC" "$MAN_PAGE" 0644 && commit "$MAN_PAGE"; then
            info "installed man page -> $MAN_PAGE"
        else
            info "could not install the man page"
        fi
    else
        info "could not create $MAN_DIR"
    fi
fi

case ":$PATH:" in
    *":$TARGET:"*) ;;
    *)
        info ""
        info "note: $TARGET is not in PATH"
        info "add: export PATH=\"$TARGET:\$PATH\""
        ;;
esac
