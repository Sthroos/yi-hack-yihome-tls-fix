#!/bin/sh
# Runs ON THE CAMERA from /tmp/sd/yi-hack/startup.sh (yi-hack's custom hook).
#
# The camera's glibc has no /etc/nsswitch.conf, so DNS wins over /etc/hosts.
# The bridge therefore also serves DNS on 127.0.0.1:53 (-d): the Yi API host
# resolves to 127.0.0.1, everything else is forwarded to the DHCP nameservers.
#
# This supervisor:
#   - snapshots the DHCP nameservers to /tmp/resolv.conf.upstream
#   - points /tmp/resolv.conf (= /etc/resolv.conf) at 127.0.0.1 once the bridge runs
#   - re-applies that after DHCP renewals rewrite resolv.conf
#   - restores the original resolv.conf whenever the bridge is down, and gives
#     up after 3 quick failures so the camera never stays without DNS.
# Idempotent: a second invocation exits while the first supervisor lives.
# The supervisor detaches its stdio so an SSH session that starts it can close.

BASE="$(dirname "$0")"
UPSTREAM="$(cat "$BASE/upstream_host" 2>/dev/null)"
LOG=/tmp/yi-tls-bridge.log
LOCK=/tmp/yi-tls-bridge.lock
RESOLV=/tmp/resolv.conf
UPRESOLV=/tmp/resolv.conf.upstream

[ -n "$UPSTREAM" ] || { echo "yi-tls-bridge: $BASE/upstream_host missing" >&2; exit 1; }
for f in yi-tls-bridge server.crt server.key ca-bundle.pem; do
    [ -s "$BASE/$f" ] || { echo "yi-tls-bridge: $BASE/$f missing" >&2; exit 1; }
done

mkdir "$LOCK" 2>/dev/null || exit 0

log() { echo "{\"ts\":$(date +%s),\"level\":\"$1\",\"event\":\"$2\",\"detail\":\"supervisor\"}" >> "$LOG"; }

# Save the real nameservers unless resolv.conf already points at us.
snapshot_upstream() {
    grep '^nameserver' "$RESOLV" 2>/dev/null | grep -v '127\.0\.0\.1' > "$UPRESOLV.new"
    if [ -s "$UPRESOLV.new" ]; then mv "$UPRESOLV.new" "$UPRESOLV"; else rm -f "$UPRESOLV.new"; fi
}

point_dns_to_bridge() {
    [ "$(cat "$RESOLV" 2>/dev/null)" = "nameserver 127.0.0.1" ] && return 0
    snapshot_upstream
    [ -s "$UPRESOLV" ] || return 1
    echo "nameserver 127.0.0.1" > "$RESOLV.new" && mv "$RESOLV.new" "$RESOLV"
}

restore_dns() {
    [ -s "$UPRESOLV" ] && cp "$UPRESOLV" "$RESOLV.new" && mv "$RESOLV.new" "$RESOLV"
}

# /etc/hosts -> /tmp/hosts on yi-hack; harmless here, used if nsswitch ever says "files" first.
[ -f /tmp/hosts ] || echo "127.0.0.1 localhost" > /tmp/hosts
grep -q "[[:space:]]$UPSTREAM\$" /tmp/hosts || echo "127.0.0.1 $UPSTREAM" >> /tmp/hosts

(
    fails=0
    while true; do
        if [ -f "$LOG" ] && [ "$(wc -c < "$LOG")" -gt 32768 ]; then
            tail -c 16384 "$LOG" > "$LOG.tmp" && mv "$LOG.tmp" "$LOG"
        fi
        snapshot_upstream
        if [ ! -s "$UPRESOLV" ]; then
            log warn no_upstream_dns
            sleep 10
            continue
        fi
        started=$(date +%s)
        "$BASE/yi-tls-bridge" -c "$BASE/server.crt" -k "$BASE/server.key" \
            -a "$BASE/ca-bundle.pem" -u "$UPSTREAM" -r "$UPRESOLV" -d >> "$LOG" 2>&1 &
        bpid=$!
        sleep 2
        while kill -0 "$bpid" 2>/dev/null; do
            point_dns_to_bridge
            sleep 3
        done
        restore_dns
        if [ $(( $(date +%s) - started )) -lt 30 ]; then fails=$((fails + 1)); else fails=0; fi
        if [ "$fails" -ge 3 ]; then
            log fatal giving_up_dns_restored
            rmdir "$LOCK"
            exit 1
        fi
        sleep 5
    done
) </dev/null >/dev/null 2>&1 &
