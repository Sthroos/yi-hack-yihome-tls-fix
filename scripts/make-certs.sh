#!/usr/bin/env bash
# Creates a private CA and a server certificate for the Yi API host that the
# cameras' CyaSSL 3.3.0 can validate (RSA 2048, SHA-256 signatures).
# The CA private key is destroyed after signing: the CA can sign exactly one cert.
# To reissue, delete OUT_DIR, rerun, and push the new CA to the cameras.
set -euo pipefail

OUT_DIR="${1:?usage: make-certs.sh <output-dir> [api-host]}"
HOST="${2:-api.eu.xiaoyi.com}"

if [[ -e "$OUT_DIR" ]]; then
  echo "error: $OUT_DIR already exists; refusing to overwrite" >&2
  exit 1
fi

umask 077
mkdir -p "$OUT_DIR"
WORK="$(mktemp -d)"
trap 'shred -u "$WORK"/* 2>/dev/null || true; rm -rf "$WORK"' EXIT

openssl req -x509 -new -newkey rsa:2048 -sha256 -nodes -days 3650 \
  -keyout "$WORK/ca.key" -out "$OUT_DIR/local-ca.crt" \
  -subj "/O=Home/CN=Yi camera local CA" \
  -addext "basicConstraints=critical,CA:TRUE,pathlen:0" \
  -addext "keyUsage=critical,keyCertSign,cRLSign"

openssl req -new -newkey rsa:2048 -sha256 -nodes \
  -keyout "$OUT_DIR/server.key" -out "$WORK/server.csr" \
  -subj "/CN=$HOST"

cat > "$WORK/ext.cnf" <<EOF
basicConstraints=critical,CA:FALSE
keyUsage=critical,digitalSignature,keyEncipherment
extendedKeyUsage=serverAuth
subjectAltName=DNS:$HOST
EOF

openssl x509 -req -sha256 -days 1825 \
  -in "$WORK/server.csr" -CA "$OUT_DIR/local-ca.crt" -CAkey "$WORK/ca.key" \
  -CAcreateserial -CAserial "$WORK/ca.srl" \
  -extfile "$WORK/ext.cnf" -out "$OUT_DIR/server.crt"

openssl verify -CAfile "$OUT_DIR/local-ca.crt" "$OUT_DIR/server.crt"

chmod 0444 "$OUT_DIR/local-ca.crt" "$OUT_DIR/server.crt"
chmod 0400 "$OUT_DIR/server.key"
echo "done: $OUT_DIR"
