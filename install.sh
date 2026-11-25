#!/usr/bin/env bash
# Installs yi-tls-bridge on a yi-hack (MStar) camera over SSH. Run on a PC.
#
#   ./install.sh <camera-ip> [upstream-host]
#
# Needs: dist/yi-tls-bridge-armhf (or BIN=...), ./pki/ from scripts/make-certs.sh,
# and a CA bundle (default: the PC's system bundle).
set -euo pipefail

CAM="${1:?usage: install.sh <camera-ip> [upstream-host]}"
UPSTREAM="${2:-api.eu.xiaoyi.com}"
HERE="$(cd "$(dirname "$0")" && pwd)"
BIN="${BIN:-$HERE/dist/yi-tls-bridge-armhf}"
PKI="${PKI:-$HERE/pki}"
CA_BUNDLE="${CA_BUNDLE:-/etc/ssl/certs/ca-certificates.crt}"
DEST=/tmp/sd/yi-hack/yi-tls-bridge
SSH=(ssh -o ConnectTimeout=10 "root@$CAM")

for f in "$BIN" "$PKI/server.crt" "$PKI/server.key" "$PKI/local-ca.crt" "$CA_BUNDLE"; do
    [[ -s "$f" ]] || { echo "error: missing $f" >&2; exit 1; }
done
if ! openssl x509 -in "$PKI/server.crt" -noout -checkhost "$UPSTREAM" | grep -q 'does match'; then
    echo "error: $PKI/server.crt is not valid for $UPSTREAM" >&2
    exit 1
fi

# Write to a temp name and rename: the binary/script may be running (ETXTBSY).
push() { "${SSH[@]}" "cat > '$2.new' && mv '$2.new' '$2'" < "$1"; }

echo "== checking camera"
"${SSH[@]}" "grep -q /tmp/sd /proc/mounts" || { echo "error: no SD card mounted on camera" >&2; exit 1; }
"${SSH[@]}" "mkdir -p $DEST"

echo "== copying files"
push "$BIN"                    "$DEST/yi-tls-bridge"
push "$PKI/server.crt"         "$DEST/server.crt"
push "$PKI/server.key"         "$DEST/server.key"
push "$CA_BUNDLE"              "$DEST/ca-bundle.pem"
push "$HERE/camera/start.sh"   "$DEST/start.sh"
push "$HERE/camera/install-ca.sh" /tmp/yi-install-ca.sh
push "$PKI/local-ca.crt"       /tmp/yi-local-ca.crt
"${SSH[@]}" "printf '%s\n' '$UPSTREAM' > $DEST/upstream_host && chmod 755 $DEST/yi-tls-bridge $DEST/start.sh"

echo "== trusting the private CA in cloudAPI's bundles"
"${SSH[@]}" "sh /tmp/yi-install-ca.sh /tmp/yi-local-ca.crt && rm -f /tmp/yi-install-ca.sh /tmp/yi-local-ca.crt"

echo "== hooking into yi-hack startup (/tmp/sd/yi-hack/startup.sh)"
"${SSH[@]}" "f=/tmp/sd/yi-hack/startup.sh; [ -f \$f ] || printf '#!/bin/sh\n' > \$f; \
  grep -qF '$DEST/start.sh' \$f || echo '$DEST/start.sh' >> \$f; chmod 755 \$f"

echo "== starting bridge"
# A running supervisor holds the lock; the new files take effect after a reboot.
"${SSH[@]}" "if [ -d /tmp/yi-tls-bridge.lock ]; then echo 'already running: reboot the camera to activate (reboot -f)'; \
  else $DEST/start.sh; sleep 4; ps | grep -q '[y]i-tls-bridge -c' && echo running || { cat /tmp/yi-tls-bridge.log; exit 1; }; fi"

echo "done. Check: ssh root@$CAM 'cat /tmp/yi-tls-bridge.log; ps | grep cloudAPI_real'"
