#!/bin/sh
# sheer installer - https://github.com/etirf/sheer
#
# tries a pre-built binary first; falls back to building from source.
# pass --from-source to skip straight to the source build.
#
# usage:
#   curl -fsSL https://raw.githubusercontent.com/etirf/sheer/main/install.sh | sh
#   curl -fsSL https://raw.githubusercontent.com/etirf/sheer/main/install.sh | sh -s -- --from-source

set -e

REPO="etirf/sheer"
INSTALL_DIR="/usr/local/bin"

# ── helpers ──────────────────────────────────────────────────────────────────

say()  { printf '  %s\n' "$*"; }
die()  { printf '\nerror: %s\n' "$*" >&2; exit 1; }

need_cmd() {
    command -v "$1" > /dev/null 2>&1 || die "required command not found: $1"
}

download() {
    url="$1"; dest="$2"
    if command -v curl > /dev/null 2>&1; then
        curl -fsSL "$url" -o "$dest"
    elif command -v wget > /dev/null 2>&1; then
        wget -qO "$dest" "$url"
    else
        die "need curl or wget to download"
    fi
}

do_install_file() {
    src="$1"; dst="$2"
    if [ "$(id -u)" = "0" ]; then
        install -Dm755 "$src" "$dst"
    else
        sudo install -Dm755 "$src" "$dst"
    fi
}

# ── detect platform ───────────────────────────────────────────────────────────

OS=$(uname -s | tr '[:upper:]' '[:lower:]')
ARCH=$(uname -m)

case "$ARCH" in
    x86_64)          ARCH="amd64" ;;
    aarch64|arm64)   ARCH="arm64" ;;
    *)               ARCH="$ARCH" ;;
esac

[ "$OS" = "linux" ] || die "only Linux is supported for pre-built binaries.\nbuild from source: git clone https://github.com/$REPO && cd sheer && make && sudo make install"

# ── parse args ────────────────────────────────────────────────────────────────

FROM_SOURCE=0
for arg in "$@"; do
    case "$arg" in --from-source) FROM_SOURCE=1 ;; esac
done

# ── install binary ────────────────────────────────────────────────────────────

verify_checksum() {
    bin="$1"; name="$2"
    checksums=$(mktemp)
    download "https://github.com/$REPO/releases/latest/download/checksums.txt" "$checksums" || {
        rm -f "$checksums"
        say "warning: could not download checksums — skipping verification"
        return 0
    }
    expected=$(grep "$name" "$checksums" | awk '{print $1}')
    rm -f "$checksums"
    if [ -z "$expected" ]; then
        say "warning: no checksum found for $name — skipping verification"
        return 0
    fi
    actual=$(sha256sum "$bin" | awk '{print $1}')
    if [ "$actual" != "$expected" ]; then
        die "checksum mismatch for $name\n  expected: $expected\n  got:      $actual\n\nThe binary may have been tampered with. Build from source instead:\n  curl -fsSL https://raw.githubusercontent.com/$REPO/main/install.sh | sh -s -- --from-source"
    fi
    say "verified   sha256 ok"
}

install_prebuilt() {
    binary="sheer-${OS}-${ARCH}"
    url="https://github.com/$REPO/releases/latest/download/$binary"
    tmp=$(mktemp)
    say "downloading sheer (${OS}/${ARCH})..."
    download "$url" "$tmp" || return 1
    verify_checksum "$tmp" "$binary"
    chmod +x "$tmp"
    do_install_file "$tmp" "$INSTALL_DIR/sheer"
    rm -f "$tmp"
    say "installed  $INSTALL_DIR/sheer"
}

install_source() {
    say "building from source..."

    # need a C compiler - cc, gcc, clang, whatever
    if ! command -v cc > /dev/null 2>&1 && \
       ! command -v gcc > /dev/null 2>&1 && \
       ! command -v clang > /dev/null 2>&1; then
        die "need a C compiler (gcc or clang)"
    fi
    need_cmd make
    need_cmd git

    tmp=$(mktemp -d)
    git clone --depth=1 "https://github.com/$REPO" "$tmp/sheer" > /dev/null 2>&1
    cd "$tmp/sheer"
    make > /dev/null 2>&1
    if [ "$(id -u)" = "0" ]; then
        make install > /dev/null 2>&1
    else
        sudo make install > /dev/null 2>&1
    fi
    cd /
    rm -rf "$tmp"
    say "built and installed  $INSTALL_DIR/sheer"
    return 0  # shrun already added by make install
}

# ── add shrun to shell ────────────────────────────────────────────────────────

add_shrun() {
    rc="$1"
    [ -f "$rc" ] || return 0
    grep -qF '# >>> sheer <<<' "$rc" 2>/dev/null && return 0
    # shellcheck disable=SC2016
    printf '\n# >>> sheer <<<\nfunction shrun { eval "$(sheer run "$@")"; }\n# <<< sheer >>>\n' >> "$rc"
    say "added shrun to $rc"
}

# ── go ────────────────────────────────────────────────────────────────────────

printf '\ninstalling sheer...\n'

if [ "$FROM_SOURCE" = "1" ]; then
    install_source
    # make install already handled shrun - done
else
    if ! install_prebuilt; then
        say "no pre-built binary for ${OS}/${ARCH}, building from source..."
        install_source
        # make install already handled shrun - done
    else
        # pre-built path: add shrun manually
        add_shrun "$HOME/.bashrc"
        add_shrun "$HOME/.zshrc"
    fi
fi

printf '\ndone. open a new terminal or run:\n'
printf '  source ~/.bashrc\n\n'
printf 'then:\n'
printf '  shrun "rm -rf /tmp/test"\n\n'
