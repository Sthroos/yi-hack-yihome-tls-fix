#!/usr/bin/env bash
# One-command install of yi-tls-bridge on a yi-hack (MStar) camera. Run on a PC.
#
#   ./install.sh [--reboot] <camera-ip> [api-host]
#
#   --reboot   reboot the camera when done (recommended on first install)
#   api-host   e.g. api.us.xiaoyi.com; default: detected from the camera, else api.eu.xiaoyi.com
#
# First run creates ./pki (your private CA + server cert); later runs reuse it.
# Env overrides: BIN, PKI, CA_BUNDLE.
set -euo pipefail

REBOOT=0
if [[ "${1:-}" == "--reboot" ]]; then REBOOT=1; shift; fi
CAM="${1:?usage: install.sh [--reboot] <camera-ip> [api-host]}"
UPSTREAM="${2:-}"
HERE="$(cd "$(dirname "$0")" && pwd)"
BIN="${BIN:-$HERE/dist/yi-tls-bridge-armhf}"
PKI="${PKI:-$HERE/pki}"
CA_BUNDLE="${CA_BUNDLE:-/etc/ssl/certs/ca-certificates.crt}"
DEST=/tmp/sd/yi-hack/yi-tls-bridge
# md5 of cloudAPI from official update 4.5.0.0C_202608061757: does not verify certificates.
UNVERIFYING_CLOUDAPI_MD5=1492dcaa52ab39a3ac1f1327c1a32853

# One SSH connection for all steps: a single password prompt.
CTL="$(mktemp -u /tmp/yi-ssh-XXXXXX)"
SSH=(ssh -o ConnectTimeout=10 -o ControlMaster=auto -o ControlPath="$CTL" -o ControlPersist=120 "root@$CAM")
cleanup() { ssh -o ControlPath="$CTL" -O exit "root@$CAM" 2>/dev/null || true; }
trap cleanup EXIT

die() { echo "error: $*" >&2; exit 1; }
push() { "${SSH[@]}" "cat > '$2.new' && mv '$2.new' '$2'" < "$1"; }   # rename: target may be running

for f in "$BIN" "$CA_BUNDLE"; do [[ -s "$f" ]] || die "missing $f"; done
command -v openssl >/dev/null || die "openssl not found"

echo "== connecting to $CAM"
"${SSH[@]}" true

echo "== pre-flight checks"
"${SSH[@]}" "[ -d /home/yi-hack ]" || die "no /home/yi-hack: is this a yi-hack camera?"
"${SSH[@]}" "grep -q ' /tmp/sd ' /proc/mounts" || die "no SD card mounted on the camera"
if "${SSH[@]}" "grep -q '^DISABLE_CLOUD=yes' /home/yi-hack/etc/system.conf 2>/dev/null"; then
    die "cloud is disabled in yi-hack (Configurations > Disable cloud); enable it first"
fi
CLOUD_MD5="$("${SSH[@]}" "md5sum /home/yi-hack/bin/cloudAPI_real 2>/dev/null" | cut -d' ' -f1)"
[[ -n "$CLOUD_MD5" ]] || die "/home/yi-hack/bin/cloudAPI_real not found"
if [[ "$CLOUD_MD5" == "$UNVERIFYING_CLOUDAPI_MD5" ]]; then
    die "cloudAPI_real is the one from the official update and does not verify certificates.
       Restore the original 2019 binary first (see README, troubleshooting)."
fi

if [[ -z "$UPSTREAM" ]]; then
    UPSTREAM="$("${SSH[@]}" "ps" | grep -o 'https://api\.[a-z0-9-]*\.xiaoyi\.com' | sed -n '1s#https://##p' || true)"
    UPSTREAM="${UPSTREAM:-api.eu.xiaoyi.com}"
    echo "   API host: $UPSTREAM"
fi
[[ "$UPSTREAM" =~ ^api\.[a-z0-9-]+\.xiaoyi\.com$ ]] || die "unexpected API host '$UPSTREAM'"

if [[ ! -d "$PKI" ]]; then
    echo "== creating your private CA and certificate in $PKI (first run only)"
    "$HERE/scripts/make-certs.sh" "$PKI" "$UPSTREAM" >/dev/null 2>&1 || die "make-certs.sh failed"
fi
for f in server.crt server.key local-ca.crt; do [[ -s "$PKI/$f" ]] || die "missing $PKI/$f"; done
openssl x509 -in "$PKI/server.crt" -noout -checkhost "$UPSTREAM" | grep -q 'does match' \
    || die "$PKI/server.crt is not valid for $UPSTREAM (use PKI=./pki-other to make a second set)"

echo "== copying files to $DEST"
"${SSH[@]}" "mkdir -p $DEST"
push "$BIN"                       "$DEST/yi-tls-bridge"
push "$PKI/server.crt"            "$DEST/server.crt"
push "$PKI/server.key"            "$DEST/server.key"
push "$CA_BUNDLE"                 "$DEST/ca-bundle.pem"
push "$HERE/camera/start.sh"      "$DEST/start.sh"
push "$HERE/camera/blocklist"     "$DEST/blocklist"
push "$HERE/camera/blocked-ips"   "$DEST/blocked-ips"
push "$HERE/camera/install-ca.sh" /tmp/yi-install-ca.sh
push "$PKI/local-ca.crt"          /tmp/yi-local-ca.crt
"${SSH[@]}" "printf '%s\n' '$UPSTREAM' > $DEST/upstream_host && chmod 755 $DEST/yi-tls-bridge $DEST/start.sh"

echo "== trusting your private CA in cloudAPI's bundles"
"${SSH[@]}" "sh /tmp/yi-install-ca.sh /tmp/yi-local-ca.crt && rm -f /tmp/yi-install-ca.sh /tmp/yi-local-ca.crt"

echo "== hooking into yi-hack startup (/tmp/sd/yi-hack/startup.sh)"
"${SSH[@]}" "f=/tmp/sd/yi-hack/startup.sh; [ -f \$f ] || printf '#!/bin/sh\n' > \$f; \
  grep -qF '$DEST/start.sh' \$f || echo '$DEST/start.sh' >> \$f; chmod 755 \$f"

if [[ "$REBOOT" == 1 ]]; then
    echo "== rebooting camera"
    "${SSH[@]}" "sync; reboot -f" || true
    echo "done. In ~2 minutes check: ssh root@$CAM 'cat /tmp/yi-tls-bridge.log'"
    exit 0
fi

echo "== starting bridge"
# A running supervisor holds the lock; updated files take effect after a reboot.
"${SSH[@]}" "if [ -d /tmp/yi-tls-bridge.lock ]; then echo 'already running: reboot the camera to activate (reboot -f)'; \
  else $DEST/start.sh; sleep 4; ps | grep -q '[y]i-tls-bridge -c' && echo running || { cat /tmp/yi-tls-bridge.log; exit 1; }; fi"
echo "done. Recommended: reboot once (ssh root@$CAM reboot -f), then check /tmp/yi-tls-bridge.log"
