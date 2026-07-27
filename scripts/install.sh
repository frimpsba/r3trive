#!/usr/bin/env bash
# R3TRIVE Installation Script
# https://github.com/thrive-spectrexq/r3trive

set -e

REPO="thrive-spectrexq/r3trive"
INSTALL_DIR="/usr/local/bin"

echo "═══════════════════════════════════════════"
echo " R3TRIVE Installer"
echo " Maintained by https://github.com/thrive-spectrexq"
echo "═══════════════════════════════════════════"

OS="$(uname -s | tr '[:upper:]' '[:lower:]')"
ARCH="$(uname -m)"

case "$ARCH" in
    x86_64|amd64) ARCH="amd64" ;;
    aarch64|arm64) ARCH="arm64" ;;
    *) echo "Unsupported architecture: $ARCH"; exit 1 ;;
esac

case "$OS" in
    linux) OS="linux" ;;
    darwin) OS="darwin" ;;
    mingw*|msys*|cygwin*) OS="windows" ;;
    *) echo "Unsupported operating system: $OS"; exit 1 ;;
esac

echo "Detected OS: $OS ($ARCH)"

BINARY_NAME="r3trive"
if [ "$OS" = "windows" ]; then
    BINARY_NAME="r3trive.exe"
    INSTALL_DIR="$HOME/.local/bin"
    mkdir -p "$INSTALL_DIR"
fi

if command -v go >/dev/null 2>&1; then
    echo "Building R3TRIVE from source with Go..."
    TEMP_DIR="$(mktemp -d)"
    trap 'rm -rf "$TEMP_DIR"' EXIT
    git clone --depth 1 "https://github.com/${REPO}.git" "$TEMP_DIR/r3trive"
    cd "$TEMP_DIR/r3trive"
    go build -trimpath -ldflags "-s -w" -o "$BINARY_NAME" ./cmd/r3trive
    if [ "$OS" = "windows" ]; then
        cp "$BINARY_NAME" "$INSTALL_DIR/"
    else
        sudo cp "$BINARY_NAME" "$INSTALL_DIR/"
        sudo chmod +x "$INSTALL_DIR/$BINARY_NAME"
    fi
else
    echo "Downloading pre-compiled binary release..."
    DOWNLOAD_URL="https://github.com/${REPO}/releases/latest/download/r3trive-${OS}-${ARCH}"
    if [ "$OS" = "windows" ]; then
        DOWNLOAD_URL="${DOWNLOAD_URL}.exe"
    fi
    curl -sSL -o "$BINARY_NAME" "$DOWNLOAD_URL"
    if [ "$OS" = "windows" ]; then
        mv "$BINARY_NAME" "$INSTALL_DIR/"
    else
        sudo mv "$BINARY_NAME" "$INSTALL_DIR/"
        sudo chmod +x "$INSTALL_DIR/$BINARY_NAME"
    fi
fi

echo "✓ R3TRIVE successfully installed to $INSTALL_DIR/$BINARY_NAME"
echo ""
echo "Run 'r3trive --help' to get started."
