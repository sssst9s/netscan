#!/bin/sh
set -eu

REPO="sssst9s/netscan"
BIN="netscan"
INSTALL_DIR="${NETSCAN_INSTALL_DIR:-/usr/local/bin}"
VERSION="${NETSCAN_VERSION:-latest}"

say() { printf '%s\n' "$*"; }
die() { printf 'error: %s\n' "$*" >&2; exit 1; }
need() { command -v "$1" >/dev/null 2>&1 || die "$1 is required but not installed"; }

detect_target() {
    os=$(uname -s)
    arch=$(uname -m)

    case "$os" in
        Linux) os_part="unknown-linux-gnu" ;;
        Darwin) os_part="apple-darwin" ;;
        *) die "unsupported operating system: $os. Build from source instead: https://github.com/$REPO" ;;
    esac

    case "$arch" in
        x86_64 | amd64) arch_part="x86_64" ;;
        aarch64 | arm64) arch_part="aarch64" ;;
        *) die "unsupported architecture: $arch. Build from source instead: https://github.com/$REPO" ;;
    esac

    printf '%s-%s' "$arch_part" "$os_part"
}

resolve_version() {
    if [ "$VERSION" != "latest" ]; then
        printf '%s' "$VERSION"
        return
    fi
    tag=$(curl -fsSL "https://api.github.com/repos/$REPO/releases/latest" \
        | sed -n 's/.*"tag_name": *"\([^"]*\)".*/\1/p' \
        | head -n 1)
    [ -n "$tag" ] || die "could not find the latest release. Give one with NETSCAN_VERSION."
    printf '%s' "$tag"
}

main() {
    need curl
    need tar

    target=$(detect_target)
    tag=$(resolve_version)
    version="${tag#v}"
    archive="netscan-${version}-${target}.tar.gz"
    base="https://github.com/$REPO/releases/download/$tag"

    tmp=$(mktemp -d)
    trap 'rm -rf "$tmp"' EXIT INT TERM

    say "Downloading netscan $tag for $target"
    curl -fsSL "$base/$archive" -o "$tmp/$archive" \
        || die "no build published for $target at $tag"

    if curl -fsSL "$base/$archive.sha256" -o "$tmp/$archive.sha256" 2>/dev/null; then
        expected=$(tr -d '[:space:]' < "$tmp/$archive.sha256" | tr '[:upper:]' '[:lower:]')
        if command -v shasum >/dev/null 2>&1; then
            actual=$(shasum -a 256 "$tmp/$archive" | cut -d' ' -f1)
        elif command -v sha256sum >/dev/null 2>&1; then
            actual=$(sha256sum "$tmp/$archive" | cut -d' ' -f1)
        else
            actual=""
            say "warning: no sha256 tool found, skipping checksum verification"
        fi
        if [ -n "$actual" ] && [ "$actual" != "$expected" ]; then
            die "checksum mismatch. Expected $expected, got $actual. Not installing."
        fi
    else
        say "warning: no checksum published for this archive"
    fi

    tar xzf "$tmp/$archive" -C "$tmp"
    binary=$(find "$tmp" -type f -name "$BIN" -perm -u+x | head -n 1)
    [ -n "$binary" ] || die "the archive did not contain $BIN"

    if [ -w "$INSTALL_DIR" ]; then
        install -m 755 "$binary" "$INSTALL_DIR/$BIN"
    else
        say "Installing to $INSTALL_DIR needs elevated permissions"
        need sudo
        sudo install -m 755 "$binary" "$INSTALL_DIR/$BIN"
    fi

    say "Installed $BIN to $INSTALL_DIR/$BIN"

    case ":$PATH:" in
        *":$INSTALL_DIR:"*) ;;
        *) say "Note: $INSTALL_DIR is not on your PATH" ;;
    esac

    say ""
    say "Run 'netscan --help' to get started."
    say "Scan only networks you own or have permission to test."
}

main "$@"
