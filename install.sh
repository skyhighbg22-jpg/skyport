#!/bin/sh
set -eu
REPO="skyhighbg22-jpg/skyport"
BIN="skyport"
VERSION="${VERSION:-latest}"

detect_platform() {
  OS="$(uname -s | tr '[:upper:]' '[:lower:]')"
  ARCH="$(uname -m)"
  case "$OS" in
    linux) OS="unknown-linux-gnu" ;;
    darwin) OS="apple-darwin" ;;
    *) echo "Unsupported OS: $OS" >&2; exit 1 ;;
  esac
  case "$ARCH" in
    x86_64|amd64) ARCH="x86_64" ;;
    arm64|aarch64) ARCH="aarch64" ;;
    *) echo "Unsupported arch: $ARCH" >&2; exit 1 ;;
  esac
  if [ "$OS" = "unknown-linux-gnu" ]; then
    echo "${ARCH}-${OS}"
  else
    echo "${ARCH}-${OS}"
  fi
}

TARGET="$(detect_platform)"
if [ "$VERSION" = "latest" ]; then
  URL="https://github.com/${REPO}/releases/latest/download/skyport-${TARGET}"
else
  URL="https://github.com/${REPO}/releases/download/v${VERSION}/skyport-${TARGET}"
fi

INSTALL_DIR="${INSTALL_DIR:-$HOME/.local/bin}"
mkdir -p "$INSTALL_DIR"
TMP="$(mktemp)"
echo "Downloading $URL ..."
if command -v curl >/dev/null 2>&1; then
  curl -fsSL "$URL" -o "$TMP"
elif command -v wget >/dev/null 2>&1; then
  wget -qO "$TMP" "$URL"
else
  echo "Need curl or wget" >&2; exit 1
fi
chmod +x "$TMP"
mv "$TMP" "$INSTALL_DIR/$BIN"
echo "Installed $BIN to $INSTALL_DIR/$BIN"
case ":$PATH:" in
  *":$INSTALL_DIR:"*) ;;
  *) echo "Add to PATH: export PATH=\"\$PATH:$INSTALL_DIR\"" ;;
esac
"$INSTALL_DIR/$BIN" --version || true
