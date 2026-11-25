# Firmware analysis

Findings from analysing a Yi 1080p Home camera (model suffix `y203c`, MStar SoC)
running yi-hack-MStar 0.5.8 on base firmware `4.5.0.0C_201910080934`, and the
official update `4.5.0.0C_202608061757` that the Yi Home app offered in
November 2026. Every claim below can be reproduced with the tools in this
repository and files from your own camera.

## 1. What changed on Yi's side

Since 2026-11-23, `api.eu.xiaoyi.com` presents a new certificate:

```
leaf:          CN=api.eu.xiaoyi.com            (valid from 2026-11-23)
intermediate:  GlobalSign GCC R46 OV TLS CA 2025   signed by GlobalSign Root R46, sha256WithRSA
cross-sign:    GlobalSign Root R46 (RSA-4096)       signed by GlobalSign Root CA - R3, sha384WithRSA
```

The server negotiates `ECDHE-RSA-AES128-GCM-SHA256` with modern clients.
The previous certificate chained to GoDaddy G2.

Check it yourself:

```sh
echo | openssl s_client -connect api.eu.xiaoyi.com:443 -servername api.eu.xiaoyi.com -showcerts 2>&1 | grep -E 'depth=|s:|i:'
```

## 2. Why 2019 firmware breaks

`cloudAPI` (called by `dispatch`, `cloud`, `p2p_tnp`, `oss` and other processes
for every cloud request) is a dynamically linked ARM binary with **CyaSSL 3.3.0**
(the 2014 predecessor of wolfSSL) and **libcurl 7.38.0** statically built in.
From the binary:

| Capability | Present? | How to check |
|---|---|---|
| SHA-384 / SHA-512 | no | the SHA-512 round constant `0x428a2f98d728ae22` is not in the binary |
| ECC / ECDHE | no | only `TLS_RSA_*` and `TLS_DHE_RSA_*` suite names; no curve names or P-256 constants |
| CA files | `/home/app/ca/gd_bundle-g2-g1.crt`, `/home/app/ca/ca.crt` | `strings cloudAPI \| grep /home/app/ca` |

`gd_bundle-g2-g1.crt` holds three GoDaddy certificates, and `ca.crt` holds
GlobalSign Root CA (R1, 1998). Neither anchors the new chain, and the
cross-signed R46 certificate uses SHA-384, which this CyaSSL cannot verify.
**Adding GlobalSign R3/R46 to the bundles does not help** (tested).

A failed request makes the caller retry, so `ps` shows `cloudAPI_real`
processes piling up and the camera appears offline in the Yi Home app.
LAN access, DNS and plain ping keep working, which makes it look like a
network or firewall problem.

## 3. The official update `4.5.0.0C_202608061757`

The app labels it *"Certificate expiring soon. Update to the latest firmware
to prevent device malfunction."*

### Download and package format

The camera calls `GET https://api.eu.xiaoyi.com/vmanager/upgrade?...` and then runs

```
/home/app/upgrade_firmware http://download.eu.xiaoyi.com/yifirmware/smarthomecam/familymonitor-y203c/4.5.0.0C_202608061757 <md5>
```

which downloads `<url>home_y203cm` **over plain HTTP**, checks the MD5, moves
the file to `/home/home_y203cm` and reboots. On the next boot
`/home/app/init.sh` finds it (or `/tmp/sd/home_y203cm` on the SD card) and runs
`/home/base/tools/extpkg.sh`:

```
[0:22]       version + '\n'
[22:1046]    4 × 256-byte RSA-2048 blocks, PKCS#1 v1.5 type 1, public exponent 65537
             -> "rsa_pub_dec" (MStar /dev/rsa engine) -> 980 bytes
[1046:]      rest
decrypted || rest:
  [0:33]     MD5 of the 7z payload
  [33:66]    7z password
  [66:88]    version again (must match)
  [88:]      7z archive -> home/app/..., then home/app/script/update.sh
```

The RSA public key is embedded in `rsa_pub_dec` at offset 2908.
[`tools/decrypt-yi-firmware.py`](../tools/decrypt-yi-firmware.py) contains it and
reproduces the whole process on a PC:

```sh
curl -fO http://download.eu.xiaoyi.com/yifirmware/smarthomecam/familymonitor-y203c/4.5.0.0C_202608061757home_y203cm
md5sum 4.5.0.0C_202608061757home_y203cm      # 5ca6d5c79716b59492217ab50ced4e1a
./tools/decrypt-yi-firmware.py 4.5.0.0C_202608061757home_y203cm out/
```

`update.sh` runs `rm -rf /home/app/*` and copies the new `home/app` in place.
It leaves `/home/yi-hack` alone. On yi-hack the update usually never applies,
because `/home` (12 MB jffs2) has about 1.4 MB free and the 2.1 MB image does
not fit, so `move_file` fails.

### What the new `cloudAPI` does

* Same TLS stack: CyaSSL 3.3.0, libcurl 7.38.0, still no SHA-384 or ECDHE.
* The reference to `gd_bundle-g2-g1.crt` is gone; only `/home/app/ca/ca.crt` (GlobalSign R1) is referenced.
* The package ships **no** `ca.crt`, and `update.sh` wipes `/home/app` first.
* **It accepts a server certificate from an arbitrary, untrusted CA.** Tested:
  with the camera's traffic redirected to a proxy whose certificate was signed
  by a private CA that appears in neither bundle, the new `cloudAPI` returned
  `{"code":"20000",...}` for `sync_time`, `on_line`, `tnp/on_line` and
  `alert/event`.

Conclusion: the update restores cloud access by **not verifying the server
certificate**. The connection is still encrypted, but it is no longer
authenticated. Anyone who can intercept the camera's traffic (a hostile device
on the same Wi-Fi, a compromised router, DNS spoofing, anyone on the path) can
impersonate `api.eu.xiaoyi.com`. They then receive what `cloudAPI` sends:

* `password=` in `/v4/ipc/on_line` (used for P2P authentication, i.e. live viewing)
* `pic_pwd` / `video_pwd` and the upload URLs for motion clips
* the ability to answer the camera with forged responses

Live video itself runs over a separate P2P channel (`"p2p_encrypt":"true"`).
What leaks is the credentials that grant access to it.

## 4. Other findings in the 2026 firmware

* **SD-card factory hook:** `init.sh` and `dispatch` run
  `/tmp/sd/Factory/factory_test.sh` (and read `/tmp/sd/Factory/wpa_supplicant.conf`)
  at boot if present. Physical access to the SD card means root.
* **Log bundles contain the Wi-Fi password:** `dispatch`, `rmm` and `crypt_file`
  build `/tmp/sd/log_<x>.tar.gz` including `/tmp/wpa_supplicant.conf`.
  Upload endpoints in `cloud` / `p2p_tnp`: `https://hch.xiaoyi.com:9443/upload/log`
  and `http://hch.xiaoyi.com:8443/upload/log`, plus a `send_debug_info` routine.
  Whether Yi can trigger an upload remotely could not be determined from strings alone.
* **Plain-HTTP endpoints:** `http://101.132.254.51:8081` (monitor/gather
  telemetry, hardcoded IP), `http://log.{eu,us}.xiaoyi.com`,
  `http://yicamera-router.mi-ae.com.sg/v1/ipc/router`, a `bindtrack` beacon with
  `bind_key=` in the URL, and firmware mirrors (`download.xiaoyi.com`,
  Cloudfront, Qiniu, `115.28.170.6:8084`). The OTA image is RSA-signed, so
  the HTTP download itself cannot be tampered with undetected.
* **Leftovers:** test endpoints (`familymonitor-interface-test.mi-ae.com.sg`)
  and Xiaomi router integration (`miwifi.com`).

## 5. Other notes

* yi-hack replaces `/home/app/cloudAPI` with a wrapper (bind mount) that
  calls `/home/yi-hack/bin/cloudAPI_real`, or `cloudAPI_fake` when
  *Disable cloud* is on. Even after a stock update, yi-hack would keep calling
  the old binary.
* The camera's glibc (2.19) has **no `/etc/nsswitch.conf`**, so the built-in
  order `dns [!UNAVAIL=return] files` applies and `/etc/hosts` is ignored while
  DNS answers. That is why the bridge also serves DNS.
* `/etc/hosts` → `/tmp/hosts` and `/etc/resolv.conf` → `/tmp/resolv.conf` are
  symlinks into tmpfs, so they are writable and reset on every boot.
* `cloudAPI` puts the device password, the hmac and upload passwords in URL
  query strings. Do not log full URLs in any proxy.
