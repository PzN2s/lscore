#!/bin/sh
# Remove the copy of lscore installed by install.sh. History is kept unless
# --purge is given.
#
#   ./uninstall.sh                check /usr/local/bin and ~/.local/bin
#   ./uninstall.sh --prefix DIR   remove an install made with --prefix DIR
#   ./uninstall.sh --purge        also delete the local score history
#
set -eu

unset CDPATH
SRC_DIR=$(cd "$(dirname "$0")" && pwd)
SRC=$SRC_DIR/lscore.py
MARKER=lscore-install-marker:0d3f5a1c9b7e

HAVE_PREFIX=0
PREFIX=
PURGE=0
SUDO=
removed=0
skipped=0
failed=0

err() { printf 'uninstall.sh: %s\n' "$*" >&2; }
info() { printf '  %s\n' "$*"; }

usage() {
    cat <<'EOF'
Usage: ./uninstall.sh [options]

  (no option)      check /usr/local/bin and ~/.local/bin
  --prefix DIR     remove an install made with --prefix DIR
  --purge          also delete the local score history

A file is removed only when it is lscore. History is kept by default.
EOF
}

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

same_file() {
    [ "$1" = "$2" ] && return 0
    command -v readlink >/dev/null 2>&1 || return 1
    [ "$(readlink -f "$1" 2>/dev/null)" = "$(readlink -f "$2" 2>/dev/null)" ]
}

remove_file() {
    f=$1
    [ -e "$f" ] || return 0
    if [ ! -f "$f" ]; then
        info "skipped $f (not a regular file)"
        skipped=$((skipped + 1))
        return 0
    fi
    if same_file "$f" "$SRC"; then
        info "skipped $f (source copy)"
        skipped=$((skipped + 1))
        return 0
    fi
    if ! is_lscore "$f"; then
        info "skipped $f (not lscore)"
        skipped=$((skipped + 1))
        return 0
    fi
    need_sudo "$(dirname "$f")"
    if $SUDO rm -f "$f" 2>/dev/null && [ ! -e "$f" ]; then
        info "removed $f"
        removed=$((removed + 1))
    else
        err "could not remove $f"
        failed=$((failed + 1))
    fi
}

remove_man() {
    man=$1
    [ -e "$man" ] || return 0
    if [ ! -f "$man" ]; then
        info "skipped $man (not a regular file)"
        skipped=$((skipped + 1))
        return 0
    fi
    if ! grep -qF -e "$MARKER" "$man" 2>/dev/null; then
        info "skipped $man (not ours)"
        skipped=$((skipped + 1))
        return 0
    fi
    dir=$(dirname "$man")
    need_sudo "$dir"
    if $SUDO rm -f "$man" 2>/dev/null && [ ! -e "$man" ]; then
        info "removed $man"
        removed=$((removed + 1))
        $SUDO rmdir "$dir" 2>/dev/null || true
        $SUDO rmdir "$(dirname "$dir")" 2>/dev/null || true
    else
        err "could not remove $man"
        failed=$((failed + 1))
    fi
}

remove_prefix() {
    bin=$1
    remove_file "$bin"
    remove_man "$(dirname "$(dirname "$bin")")/share/man/man1/lscore.1"
}

while [ $# -gt 0 ]; do
    case "$1" in
        --purge) PURGE=1 ;;
        --prefix)
            [ $# -ge 2 ] || { err "--prefix needs a directory"; exit 2; }
            normalize_prefix "$2" || exit 2
            HAVE_PREFIX=1
            shift
            ;;
        -h|--help) usage; exit 0 ;;
        *) err "unknown option: $1 (try --help)"; exit 2 ;;
    esac
    shift
done

if [ "$HAVE_PREFIX" -eq 1 ]; then
    remove_prefix "$PREFIX/lscore"
else
    remove_prefix /usr/local/bin/lscore
    if [ -n "${HOME:-}" ]; then
        remove_prefix "$HOME/.local/bin/lscore"
    fi
fi

state=${XDG_STATE_HOME:-}
case "$state" in
    "")
        if [ -n "${HOME:-}" ]; then
            state=$HOME/.local/state
        fi
        ;;
    /*) ;;
    *) err "XDG_STATE_HOME must be an absolute path"; state= ;;
esac
while [ "${state%/}" != "$state" ]; do state=${state%/}; done
if [ -z "$state" ] || [ "$state" = / ]; then
    state=
fi
if [ -n "$state" ]; then
    hist=$state/lscore
else
    hist=
fi

if [ "$PURGE" -eq 1 ]; then
    if [ -z "$hist" ]; then
        err "cannot locate the score history (set HOME or XDG_STATE_HOME)"
        failed=$((failed + 1))
    elif [ -d "$hist" ]; then
        if rm -rf "$hist"; then
            info "removed score history $hist"
        else
            err "could not remove $hist"
            failed=$((failed + 1))
        fi
    else
        info "no score history to remove"
    fi
elif [ -n "$hist" ] && [ -d "$hist" ]; then
    info "score history kept at $hist (use --purge to delete it)"
fi

if [ "$removed" -eq 0 ] && [ "$failed" -eq 0 ]; then
    if [ "$skipped" -gt 0 ]; then
        info "nothing removed ($skipped skipped)"
    else
        info "lscore is not installed"
    fi
else
    info "removed $removed, skipped $skipped, failed $failed"
fi
[ "$failed" -eq 0 ] || exit 1
