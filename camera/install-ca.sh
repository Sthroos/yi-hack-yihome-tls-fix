#!/bin/sh
# Runs ON THE CAMERA. Restores the original cloudAPI CA bundles and appends the
# private CA that signed the bridge certificate. Idempotent.
set -eu

CA="${1:?usage: install-ca.sh /path/to/local-ca.crt}"
[ -s "$CA" ] || { echo "error: $CA missing" >&2; exit 1; }
MARKER="$(sed -n 2p "$CA")"

for F in /home/app/ca/gd_bundle-g2-g1.crt /home/app/ca/ca.crt; do
    [ -f "$F" ] || continue
    [ -f "$F.orig" ] || cp "$F" "$F.orig"
    cp "$F.orig" "$F"
    printf '\n' >> "$F"
    cat "$CA" >> "$F"
    grep -qF "$MARKER" "$F" || { echo "error: append failed for $F" >&2; exit 1; }
    echo "$F: $(grep -c 'BEGIN CERTIFICATE' "$F") certificates"
done
sync
