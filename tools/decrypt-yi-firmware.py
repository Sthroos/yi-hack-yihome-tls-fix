#!/usr/bin/env python3
"""Decrypt and verify a Yi MStar OTA "home" image (e.g. 4.5.0.0C_..home_y203cm).

Re-implements /home/base/tools/extpkg.sh + rsa_pub_dec from the camera, so the
image can be inspected on a PC without touching a camera. Nothing is flashed.

Format (all offsets in bytes):
    [0:22]        version string + '\\n'                       ("verout")
    [22:1046]     4 x 256-byte RSA-2048 blocks, PKCS#1 v1.5 type 1
                  (raw RSA with Yi's public key, e = 65537); each block
                  yields 245 bytes -> 980 bytes "dec_enc_key"
    [1046:]       remainder ("home2")
    home3 = dec_enc_key || home2
        home3[0:33]   MD5 (hex) of the 7z payload
        home3[33:66]  7z password
        home3[66:88]  version string again ("verin", must equal verout)
        home3[88:]    7z archive (password-protected), extracts to home/...

The modulus below is the public key embedded at offset 2908 of rsa_pub_dec
(firmware 4.5.0.0C, 2019). The camera hands it to the /dev/rsa hardware engine.

usage: decrypt-yi-firmware.py <image> <outdir>
Writes <outdir>/home.7z and <outdir>/password.txt; extracts with 7z if present.
"""
import hashlib
import os
import shutil
import subprocess
import sys

YI_RSA_N = int(
    "d87db9ab82432d4298e20fb25c0011db57ee7d5e560efc08b73d2bc6622c7ba5"
    "5c48c085b8984d77592521d97913639bce79c9d518b9af077df49c257a6f4453"
    "18bc9fdc436fcfb402d82b919cccfb4fcc500540ad9c11b6b0bcb51ad6ce5ea3"
    "b8ed6e3be7f383b1bcdb68af8a403695e70ef5967a8d4fee405fc7b80218049e"
    "18ee5f797b4df8f3a38f6b89976228b278478642022351ff9982e09fd9121116"
    "da56b888c1f2c6d94fb8454dacb8ce497a8a8f605c97586a2ff8307208deb90c"
    "0b900776306ec0e5c78fefa744959a5b07e905aeb07bcc739ade6193e297c6a6"
    "6ab027fcc9954d867029addd3dc9dcb1788dc122456b927585cd4664d22f9929", 16)
YI_RSA_E = 65537


def rsa_public_unpad(block: bytes) -> bytes:
    out = pow(int.from_bytes(block, "big"), YI_RSA_E, YI_RSA_N).to_bytes(256, "big")
    if out[:2] != b"\x00\x01":
        raise ValueError("RSA block is not PKCS#1 type 1 under Yi's key")
    sep = out.index(b"\x00", 2)
    if any(b != 0xFF for b in out[2:sep]) or sep < 10:
        raise ValueError("bad PKCS#1 padding")
    return out[sep + 1:]


def main() -> int:
    if len(sys.argv) != 3:
        print(__doc__)
        return 2
    image, outdir = sys.argv[1], sys.argv[2]
    data = open(image, "rb").read()
    if len(data) < 22 + 1024 + 88:
        raise SystemExit("error: file too small to be a Yi home image")

    verout = data[:22]
    enc = data[22:22 + 1024]
    home2 = data[22 + 1024:]
    dec = b"".join(rsa_public_unpad(enc[i:i + 256]) for i in range(0, 1024, 256))
    home3 = dec + home2

    md5_hex = home3[:33].split(b"\x00")[0].strip().decode()
    password = home3[33:66].split(b"\x00")[0].strip().decode()
    verin = home3[66:88]
    payload = home3[88:]

    print(f"version (outer): {verout.decode().strip()}")
    print(f"version (inner): {verin.decode(errors='replace').strip()}")
    if verin != verout:
        raise SystemExit("error: inner/outer version mismatch")
    if hashlib.md5(payload).hexdigest() != md5_hex[:32]:
        raise SystemExit("error: MD5 mismatch")
    print("md5: ok")

    os.makedirs(outdir, exist_ok=True)
    with open(os.path.join(outdir, "home.7z"), "wb") as f:
        f.write(payload)
    with open(os.path.join(outdir, "password.txt"), "w") as f:
        f.write(password + "\n")

    sevenz = shutil.which("7z") or shutil.which("7za")
    if sevenz:
        subprocess.run([sevenz, "x", "-y", f"-p{password}", f"-o{outdir}",
                        os.path.join(outdir, "home.7z")], check=True, stdout=subprocess.DEVNULL)
        print(f"extracted to {outdir}/home")
    else:
        print(f"7z not found; extract manually: 7z x -p$(cat {outdir}/password.txt) {outdir}/home.7z")
    return 0


if __name__ == "__main__":
    sys.exit(main())
