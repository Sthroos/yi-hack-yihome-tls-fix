# yi-hack-yihome-tls-fix

Restores Yi Home cloud access on **yi-hack (MStar) cameras** broken by Yi's
November 2026 certificate change. The official firmware update silently
disables certificate verification. This fix keeps TLS fully verified with a
tiny bridge that runs on the camera itself.

> **Do not press "Update" in the Yi Home app to fix this.** Firmware
> `4.5.0.0C_202608061757` gets the camera back online by accepting *any*
> server certificate, which exposes the camera's cloud credentials to
> man-in-the-middle attacks. See [Why not the official update](#why-not-the-official-update).

---

## Symptoms

Since **2026-11-23** the camera shows as offline in the Yi Home app, while:

* LAN access (yi-hack web UI, RTSP, SSH) still works
* `ping 1.1.1.1` and DNS work on the camera
* `ps | grep cloudAPI_real` shows the same cloud calls piling up
  (`/v4/ipc/on_line`, `/v2/ipc/sync_time`, `/v5/alert/gen_presigned_url`)

It looks like a network or firewall problem, but it isn't one.

## Cause

`api.eu.xiaoyi.com` switched to a GlobalSign R46 certificate chain (RSA-4096
root, SHA-384 cross-signature, ECDHE-only). The camera's `cloudAPI` is built
with **CyaSSL 3.3.0 (2014)**, which supports neither SHA-384 nor ECDHE.
Adding the new root certificates to the camera's CA bundles does not help.

Full analysis, including how to decrypt and inspect the official update
yourself: **[docs/firmware-analysis.md](docs/firmware-analysis.md)**.

## The fix

```
cloudAPI (2019, still verifies certificates)
   │  TLS 1.2, RSA key exchange; certificate from YOUR private CA, which the camera trusts
   ▼
127.0.0.1:443  yi-tls-bridge  (mbedTLS 3.6, static, 755 KB, runs on the camera)
   │  TLS 1.2, full chain + hostname verification against a current CA bundle
   ▼
api.eu.xiaoyi.com
```

* **Both legs are verified.** The old `cloudAPI` verifies the bridge, and the
  bridge verifies Yi. Nothing is ever accepted unverified.
* **The bridge also serves DNS on 127.0.0.1:53.** The camera's glibc has no
  `nsswitch.conf`, so `/etc/hosts` is ignored. The bridge answers the Yi API
  host with `127.0.0.1` and forwards every other query to the DHCP nameservers.
* **No extra hardware, container or router rule.** It works on any network:
  at home, at relatives', or behind a travel router in a holiday cabin.
* **It fails safe.** If the bridge stops, the camera's original DNS is
  restored within 3 seconds. After 3 quick crashes the supervisor gives up and
  leaves DNS restored. Cloud traffic then fails, but it never goes out unverified.
* **It survives yi-hack updates.** Everything lives on the SD card under
  `/tmp/sd/yi-hack/yi-tls-bridge/` and starts from yi-hack's official custom
  hook `/tmp/sd/yi-hack/startup.sh`.

### Tested on

| | |
|---|---|
| Camera | Yi 1080p Home, model suffix `y203c` (MStar, Cortex-A7) |
| yi-hack | yi-hack-MStar **0.5.8** |
| Base firmware | `4.5.0.0C_201910080934` |
| Region | EU (`api.eu.xiaoyi.com`) |

Other yi-hack-MStar models with the same 2019 `cloudAPI` very likely work too,
but are untested. Reports welcome.

## Requirements

* yi-hack-MStar with SSH (root) access and an **SD card** in the camera
* **Cloud enabled** in yi-hack (*Disable cloud* off)
* The camera still running its **original 2019 `cloudAPI_real`**. If you
  replaced it, see [troubleshooting](#i-replaced-cloudapi_real-with-the-one-from-the-official-update).
* On your PC: `bash`, `openssl`, `ssh`, and a CA bundle
  (default `/etc/ssl/certs/ca-certificates.crt`, Debian/Ubuntu/Fedora/Arch)
* No router changes. If you previously set up a DNAT/proxy for the camera,
  **remove it**, or the bridge will (correctly) reject the proxy's certificate.

## Install

One command per camera, run from a Linux PC (or WSL on Windows; macOS is untested):

```sh
git clone https://github.com/Sthroos/yi-hack-yihome-tls-fix
cd yi-hack-yihome-tls-fix
./install.sh --reboot 192.168.1.50
```

You type the camera's root password once. `install.sh`:

1. runs **pre-flight checks**: yi-hack present, SD card mounted, cloud enabled,
   and `cloudAPI_real` not replaced by the official update's non-verifying one
2. **detects the API region** from the camera's running cloud calls
   (falls back to `api.eu.xiaoyi.com`; override with a second argument, e.g. `api.us.xiaoyi.com`)
3. on first use, **creates `./pki`**: your own private CA and a server certificate.
   The CA private key is destroyed right after signing, so it can never sign
   anything else. Later runs reuse `./pki` for all your cameras.
4. copies the bridge, certificates, a CA bundle (from your PC) and `start.sh`
   to `/tmp/sd/yi-hack/yi-tls-bridge/`
5. appends your private CA to `/home/app/ca/gd_bundle-g2-g1.crt` and
   `/home/app/ca/ca.crt` (originals kept as `.orig`)
6. adds one line to `/tmp/sd/yi-hack/startup.sh` and reboots (`--reboot`)

Re-running is safe: nothing is duplicated, and an update only takes effect
after a reboot. To refresh the CA bundle later, run it again.

### Verify

On the camera, a minute or two after boot:

```sh
cat /tmp/resolv.conf            # nameserver 127.0.0.1
cat /tmp/resolv.conf.upstream   # your real nameservers
cat /tmp/yi-tls-bridge.log      # "started", "dns_started", then "relayed" lines
ps | grep -c '[c]loudAPI_real'  # small and not growing
```

A healthy log looks like:

```
{"event":"started","detail":"127.0.0.1:443 -> api.eu.xiaoyi.com:443"}
{"event":"dns_started","detail":"127.0.0.1:53 api.eu.xiaoyi.com -> 127.0.0.1, rest via /tmp/resolv.conf.upstream"}
{"event":"relayed","detail":"up=526 down=347 secs=0 cipher_down=TLS-RSA-WITH-AES-128-CBC-SHA256"}
```

Then check the Yi Home app, including **remotely over mobile data**.

The log contains no URLs, request bodies or credentials.

## Blocking telemetry, log uploads and firmware updates

The bridge's DNS also enforces [`camera/blocklist`](camera/blocklist) (answered
NXDOMAIN), and `start.sh` adds local reject routes for the hardcoded IPs in
[`camera/blocked-ips`](camera/blocked-ips). Out of the box this blocks:

* **diagnostic log uploads** (`hch.xiaoyi.com`, `monitor-log.xiaoyi.com`):
  the firmware's log bundle includes `/tmp/wpa_supplicant.conf`, i.e. your
  **Wi-Fi password**, and one upload URL is plain `http://`
* **telemetry** (`log.*.xiaoyi.com`, `yicamera-router.mi-ae.com.sg`, and
  `http://101.132.254.51:8081`, a hardcoded IP that DNS cannot block)
* **firmware downloads** (`download.*.xiaoyi.com`, the CDN mirrors and
  `115.28.170.6`), so nobody can accidentally install the official update
  that disables certificate verification. The app may still *offer* the
  update; installing it fails harmlessly.

Edit the files, re-run `install.sh`, reboot. Blocked lookups appear in the log
as `dns_blocked`. Everything works the same on any network, because nothing
depends on your router.

## Uninstall

On the camera:

```sh
sed -i '\#/tmp/sd/yi-hack/yi-tls-bridge/start.sh#d' /tmp/sd/yi-hack/startup.sh
rm -rf /tmp/sd/yi-hack/yi-tls-bridge
for f in /home/app/ca/gd_bundle-g2-g1.crt /home/app/ca/ca.crt; do [ -f "$f.orig" ] && cp "$f.orig" "$f"; done
sync; reboot -f
```

## Why not the official update

The update `4.5.0.0C_202608061757` keeps the same CyaSSL 3.3.0, trusts only
GlobalSign R1 (which doesn't anchor the new chain), ships no CA file at all,
and still connects. A test with a certificate from an unrelated private CA
confirmed it: **the updated `cloudAPI` does not verify the server**.

That means anyone able to intercept the camera's traffic can impersonate Yi's
API and collect what the camera sends, including the device password used for
P2P (live view) authentication and the passwords for uploaded motion clips.
That includes a compromised IoT device on the same Wi-Fi, a hijacked router or
DNS server, or anyone on the path. Details:
[docs/firmware-analysis.md §3](docs/firmware-analysis.md#3-the-official-update-4500c_202608061757).

On yi-hack cameras the update usually doesn't even apply, because the 2.1 MB
image doesn't fit in the ~1.4 MB free on `/home`. If it did, it would replace
`/home/app`.

If you run stock firmware without yi-hack, the update is currently the only
way back to the cloud. Just be aware of what it trades away.

## Alternative: network proxy

If you would rather not change the camera at all (apart from trusting your CA),
the same idea works as a proxy on a Docker host in your LAN:
[`proxy/`](proxy/) contains an nginx config (legacy TLS towards the camera,
verified TLS towards Yi, upstream keepalive) and a hardened compose file.
It needs a DNAT rule on your router: camera IPs → `api.<region>.xiaoyi.com:443`
→ `<proxy>:8443`. The camera trusts your CA via `camera/install-ca.sh`.

The trade-offs: it only works on that network, the router rule and container
must keep running, and the camera-to-proxy leg depends on your LAN.
The on-camera bridge has none of these dependencies, which is why it is the
recommended fix.

## Troubleshooting

| Log event | Meaning |
|---|---|
| `downstream_handshake` | the camera's CyaSSL rejected the bridge. Is your CA in `/home/app/ca/*.crt`? Was `server.crt` made for the right host? |
| `upstream_verify` | Yi's certificate did not verify against `ca-bundle.pem`. Update the bundle, or check whether something on your network intercepts TLS (an old DNAT rule?). Never retried. |
| `upstream_handshake … attempt=N` | the handshake to Yi stalled. Retried up to 3 times; occasional lines are normal, frequent ones point at your WAN path |
| `dns_failed` / `dns_no_nameserver` | `/tmp/resolv.conf.upstream` is empty or its nameservers don't answer |
| `giving_up_dns_restored` | the bridge kept crashing; DNS was restored and the supervisor stopped. Check the lines before it |
| `busy` | more than 8 simultaneous connections; harmless if rare |

### I replaced `cloudAPI_real` with the one from the official update

Put the 2019 binary back. That one verifies certificates, the new one does not:

```sh
mv /home/yi-hack/bin/cloudAPI_real.2019 /home/yi-hack/bin/cloudAPI_real   # or whatever you named the backup
```

### The camera has no SD card

The bridge lives on the SD card. Without one the cloud stays offline (safely).
Putting it on `/home` instead works (755 KB binary + ~220 KB CA bundle fit in
the ~1.4 MB free), but then you need your own boot hook.

## Building from source

```sh
sudo apt install gcc-arm-linux-gnueabihf make git python3-jinja2 python3-jsonschema
./bridge/build.sh            # -> dist/yi-tls-bridge-armhf + dist/SHA256SUMS
./bridge/build.sh host       # -> build/yi-tls-bridge-host (for tests)
```

The build is reproducible: with Ubuntu 24.04's `gcc-arm-linux-gnueabihf`
13.3.0 and Mbed TLS v3.6.2, `build.sh` produces a binary identical to
`dist/yi-tls-bridge-armhf` (SHA-256 in [`dist/SHA256SUMS`](dist/SHA256SUMS)).

Mbed TLS is built with TLS 1.3 disabled
([`bridge/config/mbedtls_user_config.h`](bridge/config/mbedtls_user_config.h)).
The bridge forks per connection and creates a fresh DRBG in each child. Leaving
TLS 1.3 out keeps the PSA RNG, whose state would otherwise be duplicated across
`fork()`, out of the picture.

## Tests

[`tests/e2e.py`](tests/e2e.py) builds a fake Yi API with the same
characteristics as the real one (RSA-4096 root, SHA-384 cross-sign,
ECDHE-only), a fake DNS server, and drives the bridge with the camera's
legacy client profile:

```sh
sudo python3 -I tests/e2e.py build/yi-tls-bridge-host
sudo python3 -I tests/e2e.py dist/yi-tls-bridge-armhf --qemu      # needs qemu-user
```

The suite covers the legacy ciphers (AES128-SHA, AES128-SHA256,
AES128-GCM-SHA256), trust via R46 and via the R3 cross-sign, **rejection** of a
wrong hostname and of an untrusted root, retry after a stalled upstream
handshake, and the DNS forwarder (A → 127.0.0.1, AAAA empty, other names
forwarded, loopback nameservers skipped) and the blocklist (exact names,
`.domain` suffix matching, no false positives on similar names). All 14 pass
on x86-64 and on the armhf binary under QEMU.

## Security notes

* `pki/server.key` is the only secret, and it only lets someone impersonate
  Yi's API *to your own cameras*. Keep `pki/` out of git (it is in `.gitignore`).
* The CA key is shredded right after signing, so your cameras trust exactly
  one certificate.
* The bridge listens on `127.0.0.1` only, for both 443 and 53.
* Bridge logs never contain URLs or payloads. `cloudAPI` puts credentials in
  query strings.
* `ca-bundle.pem` is copied from your PC. Re-run `install.sh` now and then to refresh it.

## Other weaknesses of this camera

What remains after this fix, from the firmware analysis and a camera's open ports:

| Issue | Risk | What you can do |
|---|---|---|
| `p2p_tnp` (live view via the app) listens on UDP 0.0.0.0, a 2019 proprietary P2P stack | the largest unknown: similar P2P stacks in other brands have had severe flaws | can't be fixed here; for remote viewing without it, use RTSP over your own VPN |
| `/tmp/sd/Factory/factory_test.sh` runs as root at boot if present | anyone with the SD card in hand gets root | physical security; matters most for cameras in shared places |
| yi-hack web UI (80) and RTSP (554) are plain HTTP/RTSP | credentials readable on the local network | set a username/password (yi-hack option), keep cameras on an isolated network |
| SSH (dropbear) with password login | brute force from the local network | use key-only login (see the yi-hack wiki) |
| ONVIF WS-Discovery (3702/udp), mDNS (5353/udp) | the camera announces itself on the network | `ONVIF_WSDD=no` if your NVR/Home Assistant uses a fixed IP |
| Devices on the same VLAN reach the camera directly | a compromised IoT gadget on the same Wi-Fi can probe the camera | client isolation on the SSID, or a dedicated camera VLAN that only allows LAN→camera and camera→internet |
| Kernel 3.18, glibc 2.19, CyaSSL 3.3.0 (2014) | unmaintained; many known CVEs | CyaSSL now only talks to the bridge on 127.0.0.1; isolate the rest |

## License

Apache-2.0, see [LICENSE](LICENSE) and [NOTICE](NOTICE). The prebuilt binary
statically links Mbed TLS (Apache-2.0) and glibc (LGPL-2.1+). `bridge/build.sh`
rebuilds it from source.

Not affiliated with Kami Vision / YI Technology or the yi-hack projects.
Use at your own risk.
