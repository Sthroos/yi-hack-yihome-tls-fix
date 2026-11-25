#!/usr/bin/env bash
# Reproducible build of yi-tls-bridge.
#
#   ./bridge/build.sh            -> dist/yi-tls-bridge-armhf (static, ARMv7 hard-float)
#   ./bridge/build.sh host       -> build/yi-tls-bridge-host (for tests/e2e.py)
#
# Needs: git, make, python3 (+ jinja2, jsonschema for mbedTLS code generation),
# gcc-arm-linux-gnueabihf (Debian/Ubuntu package) for the armhf target.
set -euo pipefail

TARGET="${1:-armhf}"
MBEDTLS_TAG="v3.6.2"
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
BUILD="$ROOT/build"
CONFIG="$ROOT/bridge/config/mbedtls_user_config.h"

case "$TARGET" in
    armhf) CC=arm-linux-gnueabihf-gcc; AR=arm-linux-gnueabihf-ar; OUT="$ROOT/dist/yi-tls-bridge-armhf" ;;
    host)  CC=gcc; AR=ar; OUT="$BUILD/yi-tls-bridge-host" ;;
    *) echo "usage: $0 [armhf|host]" >&2; exit 2 ;;
esac
command -v "$CC" >/dev/null || { echo "error: $CC not found" >&2; exit 1; }

mkdir -p "$BUILD"
if [[ ! -d "$BUILD/mbedtls" ]]; then
    git clone --depth 1 --branch "$MBEDTLS_TAG" https://github.com/Mbed-TLS/mbedtls.git "$BUILD/mbedtls"
    git -C "$BUILD/mbedtls" submodule update --init --depth 1
fi

LIBDIR="$BUILD/mbedtls-$TARGET"
make -C "$BUILD/mbedtls" -s clean >/dev/null 2>&1 || true
make -C "$BUILD/mbedtls" -s -j"$(nproc)" lib CC="$CC" AR="$AR" \
    CFLAGS="-Os -ffunction-sections -fdata-sections -DMBEDTLS_USER_CONFIG_FILE='\"$CONFIG\"'"
mkdir -p "$LIBDIR"
cp "$BUILD"/mbedtls/library/*.a "$LIBDIR/"

make -C "$ROOT/bridge" -s clean
make -C "$ROOT/bridge" -s CC="$CC" MBEDTLS="$BUILD/mbedtls" MBEDTLS_LIB="$LIBDIR"
mkdir -p "$(dirname "$OUT")"
mv "$ROOT/bridge/yi-tls-bridge" "$OUT"
echo "built $OUT"
if [[ "$TARGET" == armhf ]]; then
    (cd "$ROOT/dist" && sha256sum yi-tls-bridge-armhf > SHA256SUMS && cat SHA256SUMS)
fi
