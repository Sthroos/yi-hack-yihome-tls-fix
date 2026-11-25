#!/usr/bin/env python3
"""End-to-end test for yi-tls-bridge.

Builds a fake "Yi API" that mimics the real 2026-11 chain (RSA-4096 root,
SHA-384 cross-sign, ECDHE-only TLS), a fake DNS server, and drives the bridge
with a legacy client profile (TLS 1.2, RSA key exchange, SHA-1 sigalgs).

usage: sudo python3 -I tests/e2e.py build/yi-tls-bridge-host
       sudo python3 -I tests/e2e.py dist/yi-tls-bridge-armhf --qemu   (needs qemu-user)
Needs: openssl CLI, root (binds 127.0.0.9:53 and 127.0.0.1:443).
"""
import os
import shutil
import socket
import ssl
import struct
import subprocess
import sys
import tempfile
import threading
import time
from http.server import BaseHTTPRequestHandler, HTTPServer

HOST = "api.eu.xiaoyi.com"
DNS_IP = "127.0.0.9"
UPSTREAM_IP = "127.0.0.2"
UPSTREAM_PORT = 8443
BODY = b'{"code":"20000","time":1}'


def sh(*args, cwd):
    subprocess.run(args, cwd=cwd, check=True, capture_output=True)


def make_pki(d):
    """Root R46-like (RSA4096, sha384), old root R3-like, cross-sign, intermediate, leaf."""
    ext = os.path.join(d, "ca.ext")
    with open(ext, "w") as f:
        f.write("basicConstraints=critical,CA:TRUE\nkeyUsage=critical,keyCertSign,cRLSign\n")
    leafext = os.path.join(d, "leaf.ext")
    with open(leafext, "w") as f:
        f.write(f"basicConstraints=CA:FALSE\nextendedKeyUsage=serverAuth\nsubjectAltName=DNS:{HOST}\n")
    sh("openssl", "req", "-x509", "-newkey", "rsa:4096", "-sha384", "-nodes", "-days", "30",
       "-keyout", "r46.key", "-out", "r46.crt", "-subj", "/CN=Test Root R46", cwd=d)
    sh("openssl", "req", "-x509", "-newkey", "rsa:2048", "-sha256", "-nodes", "-days", "30",
       "-keyout", "r3.key", "-out", "r3.crt", "-subj", "/CN=Test Root R3", cwd=d)
    # Cross-sign: same subject+key as R46, issued by R3 with SHA-384 (what Yi sends).
    sh("openssl", "x509", "-x509toreq", "-in", "r46.crt", "-signkey", "r46.key", "-out", "r46.csr", cwd=d)
    sh("openssl", "x509", "-req", "-in", "r46.csr", "-CA", "r3.crt", "-CAkey", "r3.key",
       "-CAcreateserial", "-sha384", "-days", "30", "-extfile", ext, "-out", "r46-cross.crt", cwd=d)
    sh("openssl", "req", "-new", "-newkey", "rsa:2048", "-nodes", "-keyout", "int.key",
       "-out", "int.csr", "-subj", "/CN=Test GCC R46 OV TLS CA", cwd=d)
    sh("openssl", "x509", "-req", "-in", "int.csr", "-CA", "r46.crt", "-CAkey", "r46.key",
       "-CAcreateserial", "-sha256", "-days", "30", "-extfile", ext, "-out", "int.crt", cwd=d)
    sh("openssl", "req", "-new", "-newkey", "rsa:2048", "-nodes", "-keyout", "leaf.key",
       "-out", "leaf.csr", "-subj", f"/CN={HOST}", cwd=d)
    sh("openssl", "x509", "-req", "-in", "leaf.csr", "-CA", "int.crt", "-CAkey", "int.key",
       "-CAcreateserial", "-sha256", "-days", "30", "-extfile", leafext, "-out", "leaf.crt", cwd=d)
    with open(os.path.join(d, "chain.pem"), "wb") as out:
        for n in ("leaf.crt", "int.crt", "r46-cross.crt"):
            out.write(open(os.path.join(d, n), "rb").read())
    # A second leaf for the wrong hostname.
    sh("openssl", "req", "-new", "-newkey", "rsa:2048", "-nodes", "-keyout", "bad.key",
       "-out", "bad.csr", "-subj", "/CN=evil.example", cwd=d)
    with open(os.path.join(d, "bad.ext"), "w") as f:
        f.write("basicConstraints=CA:FALSE\nsubjectAltName=DNS:evil.example\n")
    sh("openssl", "x509", "-req", "-in", "bad.csr", "-CA", "int.crt", "-CAkey", "int.key",
       "-CAcreateserial", "-sha256", "-days", "30", "-extfile", "bad.ext", "-out", "bad.crt", cwd=d)
    with open(os.path.join(d, "badchain.pem"), "wb") as out:
        for n in ("bad.crt", "int.crt"):
            out.write(open(os.path.join(d, n), "rb").read())
    # Downstream: private CA + server cert the camera trusts.
    sh("openssl", "req", "-x509", "-newkey", "rsa:2048", "-sha256", "-nodes", "-days", "30",
       "-keyout", "local-ca.key", "-out", "local-ca.crt", "-subj", "/CN=Local CA",
       "-addext", "basicConstraints=critical,CA:TRUE", "-addext", "keyUsage=critical,keyCertSign", cwd=d)
    sh("openssl", "req", "-new", "-newkey", "rsa:2048", "-nodes", "-keyout", "local.key",
       "-out", "local.csr", "-subj", f"/CN={HOST}", cwd=d)
    sh("openssl", "x509", "-req", "-in", "local.csr", "-CA", "local-ca.crt", "-CAkey", "local-ca.key",
       "-CAcreateserial", "-sha256", "-days", "30", "-extfile", leafext, "-out", "local.crt", cwd=d)


class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200)
        self.send_header("Content-Type", "text/html")
        self.send_header("Content-Length", str(len(BODY)))
        self.end_headers()
        self.wfile.write(BODY)

    def log_message(self, *a):
        pass


def start_upstream(d, chain, key, port=UPSTREAM_PORT):
    srv = HTTPServer((UPSTREAM_IP, port), Handler)
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    ctx.set_ciphers("ECDHE+AESGCM")  # like Yi: no RSA key exchange offered
    ctx.load_cert_chain(os.path.join(d, chain), os.path.join(d, key))
    srv.socket = ctx.wrap_socket(srv.socket, server_side=True)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv


def start_flaky(front_port, back_port):
    """Accept TCP on front_port; stall the first connection, pipe later ones to back_port."""
    ls = socket.socket()
    ls.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    ls.bind((UPSTREAM_IP, front_port))
    ls.listen(8)
    state = {"n": 0, "stalled": []}

    def pipe(a, b):
        try:
            while True:
                data = a.recv(4096)
                if not data:
                    break
                b.sendall(data)
        except OSError:
            pass
        finally:
            for x in (a, b):
                try:
                    x.shutdown(socket.SHUT_RDWR)   # close() alone sends no FIN while another thread reads
                except OSError:
                    pass
                try:
                    x.close()
                except OSError:
                    pass

    def loop():
        while True:
            try:
                c, _ = ls.accept()
            except OSError:
                return
            state["n"] += 1
            if state["n"] == 1:
                state["stalled"].append(c)   # keep open, never answer
                continue
            u = socket.create_connection((UPSTREAM_IP, back_port))
            threading.Thread(target=pipe, args=(c, u), daemon=True).start()
            threading.Thread(target=pipe, args=(u, c), daemon=True).start()

    threading.Thread(target=loop, daemon=True).start()
    return ls, state


def start_dns():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.bind((DNS_IP, 53))

    def loop():
        while True:
            q, addr = s.recvfrom(512)
            qname_end = q.index(b"\x00", 12) + 5
            ans = (q[:2] + b"\x81\x80" + q[4:6] + b"\x00\x02\x00\x00\x00\x00" + q[12:qname_end]
                   # CNAME first, then A, to exercise the record walker
                   + b"\xc0\x0c\x00\x05\x00\x01\x00\x00\x00\x3c\x00\x02\xc0\x0c"
                   + b"\xc0\x0c\x00\x01\x00\x01\x00\x00\x00\x3c\x00\x04" + socket.inet_aton(UPSTREAM_IP))
            s.sendto(ans, addr)

    threading.Thread(target=loop, daemon=True).start()


def legacy_get(d, cipher):
    """Client profile of the camera: TLS 1.2, RSA kex, verify against local CA."""
    req = f"GET /v2/ipc/sync_time HTTP/1.1\r\nHost: {HOST}\r\nConnection: close\r\n\r\n"
    p = subprocess.run(
        ["openssl", "s_client", "-connect", "127.0.0.1:443", "-noservername", "-tls1_2",
         "-cipher", f"{cipher}:@SECLEVEL=0", "-sigalgs", "RSA+SHA1:RSA+SHA256",
         "-CAfile", os.path.join(d, "local-ca.crt"), "-verify_return_error",
         "-verify_hostname", HOST, "-quiet", "-ign_eof"],
        input=req.encode(), capture_output=True, timeout=45)
    return p.stdout


def dns_query(name, qtype=1):
    q = struct.pack(">HHHHHH", 0x1234, 0x0100, 1, 0, 0, 0)
    for label in name.split("."):
        q += bytes([len(label)]) + label.encode()
    q += b"\x00" + struct.pack(">HH", qtype, 1)
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(15)
    s.sendto(q, ("127.0.0.1", 53))
    r, _ = s.recvfrom(1500)
    s.close()
    an = struct.unpack(">H", r[6:8])[0]
    return an, (socket.inet_ntoa(r[-4:]) if an else None)


def run_bridge(binary, qemu, d, ca_bundle, resolv, dns=False, port=UPSTREAM_PORT):
    cmd = [binary, "-c", os.path.join(d, "local.crt"), "-k", os.path.join(d, "local.key"),
           "-a", os.path.join(d, ca_bundle), "-u", HOST, "-P", str(port), "-r", resolv]
    if dns:
        cmd.append("-d")
    if qemu:
        cmd = ["qemu-arm"] + cmd
    p = subprocess.Popen(cmd, stderr=subprocess.PIPE)
    time.sleep(1.5 if qemu else 0.3)
    return p


def stop(p):
    p.terminate()
    try:
        return p.communicate(timeout=5)[1].decode()
    except subprocess.TimeoutExpired:
        p.kill()
        return ""


def main():
    if len(sys.argv) < 2:
        print(__doc__)
        return 2
    binary = os.path.abspath(sys.argv[1])
    qemu = "--qemu" in sys.argv
    d = tempfile.mkdtemp(prefix="yi-bridge-test-")
    results = []
    try:
        make_pki(d)
        resolv = os.path.join(d, "resolv.conf")
        with open(resolv, "w") as f:
            f.write(f"nameserver 127.0.0.77\nnameserver {DNS_IP}\n")
        with open(os.path.join(d, "bundle-r46.pem"), "wb") as f:
            f.write(open(os.path.join(d, "r46.crt"), "rb").read())
        with open(os.path.join(d, "bundle-r3.pem"), "wb") as f:
            f.write(open(os.path.join(d, "r3.crt"), "rb").read())
        start_dns()

        def case(name, chain, key, bundle, cipher, expect_ok):
            up = start_upstream(d, chain, key)
            br = run_bridge(binary, qemu, d, bundle, resolv)
            out = legacy_get(d, cipher)
            log = stop(br)
            up.shutdown()
            up.server_close()
            ok = (BODY in out) == expect_ok
            results.append((name, ok))
            print(f"[{'PASS' if ok else 'FAIL'}] {name}")
            if not ok:
                print("  client:", out[-300:])
                print("  bridge:", log[-600:])

        case("legacy AES128-SHA, trust R46 root", "chain.pem", "leaf.key", "bundle-r46.pem", "AES128-SHA", True)
        case("legacy AES128-SHA256, trust R46 root", "chain.pem", "leaf.key", "bundle-r46.pem", "AES128-SHA256", True)
        case("legacy AES128-GCM-SHA256, trust R3 via SHA-384 cross-sign", "chain.pem", "leaf.key", "bundle-r3.pem", "AES128-GCM-SHA256", True)
        case("reject upstream with wrong hostname", "badchain.pem", "bad.key", "bundle-r46.pem", "AES128-SHA", False)
        case("reject upstream from untrusted root", "chain.pem", "leaf.key", "local-ca.crt", "AES128-SHA", False)

        # Upstream that stalls the first handshake: bridge must retry and succeed.
        up = start_upstream(d, "chain.pem", "leaf.key", port=UPSTREAM_PORT + 1)
        flaky, st = start_flaky(UPSTREAM_PORT + 2, UPSTREAM_PORT + 1)
        br = run_bridge(binary, qemu, d, "bundle-r46.pem", resolv, port=UPSTREAM_PORT + 2)
        out = legacy_get(d, "AES128-SHA")
        log = stop(br)
        flaky.close()
        up.shutdown()
        up.server_close()
        ok = BODY in out and st["n"] >= 2 and "attempt=1" in log
        results.append(("retry after stalled upstream handshake", ok))
        print(f"[{'PASS' if ok else 'FAIL'}] retry after stalled upstream handshake")
        if not ok:
            print("  bridge:", log[-600:])

        # DNS forwarder mode (-d): upstream host -> 127.0.0.1, everything else forwarded.
        with open(resolv, "w") as f:
            f.write(f"nameserver 127.0.0.1\nnameserver {DNS_IP}\n")   # loopback must be skipped
        up = start_upstream(d, "chain.pem", "leaf.key")
        br = run_bridge(binary, qemu, d, "bundle-r46.pem", resolv, dns=True)
        try:
            checks = [
                ("dns: upstream host A -> 127.0.0.1", dns_query(HOST, 1) == (1, "127.0.0.1")),
                ("dns: upstream host AAAA -> empty", dns_query(HOST, 28)[0] == 0),
                ("dns: other name forwarded", dns_query("other.example", 1)[1] == UPSTREAM_IP),
                ("dns mode: legacy request still bridged", BODY in legacy_get(d, "AES128-SHA")),
            ]
        finally:
            log = stop(br)
            up.shutdown()
            up.server_close()
        for name, ok in checks:
            results.append((name, ok))
            print(f"[{'PASS' if ok else 'FAIL'}] {name}")
        if not all(ok for _, ok in checks):
            print("  bridge:", log[-600:])
    finally:
        shutil.rmtree(d, ignore_errors=True)
    failed = [n for n, ok in results if not ok]
    print(f"{len(results) - len(failed)}/{len(results)} passed")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
