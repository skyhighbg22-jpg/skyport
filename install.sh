#!/bin/sh
set -eu
REPO="skyhighbg22-jpg/skyport"
BIN="skyport"
VERSION="${VERSION:-latest}"

detect_platform() {
  platform_target "$(uname -s)" "$(uname -m)" "$(uname -o 2>/dev/null || true)"
}

platform_target() {
  OS="$(printf '%s' "$1" | tr '[:upper:]' '[:lower:]')"
  ARCH="$2"
  KERNEL_OS="$3"
  case "$OS" in
    linux)
      if [ -n "${ANDROID_ROOT:-}" ] || [ -n "${ANDROID_DATA:-}" ] || [ "$KERNEL_OS" = "Android" ]; then
        OS="linux-android"
      else
        OS="unknown-linux-gnu"
      fi
      ;;
    darwin) OS="apple-darwin" ;;
    *) echo "Unsupported OS: $OS" >&2; exit 1 ;;
  esac
  case "$ARCH" in
    x86_64|amd64) ARCH="x86_64" ;;
    arm64|aarch64) ARCH="aarch64" ;;
    *) echo "Unsupported arch: $ARCH" >&2; exit 1 ;;
  esac
  if [ "$OS" = "linux-android" ] && [ "$ARCH" != "aarch64" ]; then
    echo "Unsupported Android architecture: $ARCH (only ARM64 is published)" >&2
    exit 1
  fi
  echo "${ARCH}-${OS}"
}

download() {
  SOURCE="$1"
  DEST="$2"
  if command -v curl >/dev/null 2>&1; then
    curl -fsSL "$SOURCE" -o "$DEST"
  elif command -v wget >/dev/null 2>&1; then
    wget -qO "$DEST" "$SOURCE"
  else
    echo "Need curl or wget" >&2
    exit 1
  fi
}

main() {
  TARGET="$(detect_platform)"
  if [ "$VERSION" = "latest" ]; then
    BASE_URL="https://github.com/${REPO}/releases/latest/download"
  else
    BASE_URL="https://github.com/${REPO}/releases/download/v${VERSION}"
  fi
  ASSET="skyport-${TARGET}"
  URL="${BASE_URL}/${ASSET}"

  INSTALL_DIR="${INSTALL_DIR:-$HOME/.local/bin}"
  mkdir -p "$INSTALL_DIR"
  TMP="$(mktemp "$INSTALL_DIR/.skyport.XXXXXX")"
  CHECKSUMS="${TMP}.SHA256SUMS"
  cleanup() {
    rm -f "$TMP" "$CHECKSUMS"
  }
  trap cleanup EXIT HUP INT TERM

  echo "Downloading $URL ..."
  download "$URL" "$TMP"
  download "${BASE_URL}/SHA256SUMS" "$CHECKSUMS"
  EXPECTED="$(awk -v asset="$ASSET" '$2 == asset || $2 == "*" asset { print $1; exit }' "$CHECKSUMS")"
  if [ -z "$EXPECTED" ]; then
    echo "No SHA-256 checksum published for $ASSET" >&2
    exit 1
  fi
  if command -v sha256sum >/dev/null 2>&1; then
    ACTUAL="$(sha256sum "$TMP" | awk '{print $1}')"
  elif command -v shasum >/dev/null 2>&1; then
    ACTUAL="$(shasum -a 256 "$TMP" | awk '{print $1}')"
  else
    echo "Need sha256sum or shasum to verify the download" >&2
    exit 1
  fi
  if [ "$ACTUAL" != "$EXPECTED" ]; then
    echo "SHA-256 verification failed for $ASSET" >&2
    exit 1
  fi
  echo "Verified SHA-256 checksum"
  chmod +x "$TMP"
  mv "$TMP" "$INSTALL_DIR/$BIN"
  rm -f "$CHECKSUMS"
  trap - EXIT HUP INT TERM
  echo "Installed $BIN to $INSTALL_DIR/$BIN"
  case ":$PATH:" in
    *":$INSTALL_DIR:"*) ;;
    *) echo "Add to PATH: export PATH=\"\$PATH:$INSTALL_DIR\"" ;;
  esac
  "$INSTALL_DIR/$BIN" --version || true
}

if [ "${SKYPORT_INSTALL_LIB_ONLY:-0}" != "1" ]; then
  main "$@"
fi
