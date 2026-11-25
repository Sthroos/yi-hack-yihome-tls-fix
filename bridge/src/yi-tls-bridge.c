/*
 * yi-tls-bridge - local TLS bridge for yi-hack cameras.
 *
 * The stock 2019 cloudAPI (CyaSSL 3.3.0) cannot validate the GlobalSign R46
 * chain Yi moved to on 2026-11-23 (no SHA-384, no ECDHE, likely no RSA-4096).
 * Yi's 2026 firmware "fixes" this by not verifying the server at all.
 *
 * This bridge keeps verification on both legs:
 *   cloudAPI --(TLS 1.2, RSA kex, cert from a private CA the camera trusts)--> 127.0.0.1:443
 *   bridge   --(TLS 1.2, full chain + hostname verification)--> real Yi API host
 *
 * /etc/hosts points the API host at 127.0.0.1, so the bridge resolves the
 * upstream itself with a minimal DNS A query against the resolver from
 * resolv.conf (it must not use /etc/hosts or it would connect to itself).
 *
 * One forked child per connection. Each child creates its own DRBG after
 * fork() so no random state is shared between connections. TLS 1.3 is
 * compiled out of mbedTLS to keep the PSA RNG out of the picture.
 */

#include <arpa/inet.h>
#include <errno.h>
#include <strings.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <poll.h>
#include <signal.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/prctl.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#include "mbedtls/ctr_drbg.h"
#include "mbedtls/entropy.h"
#include "mbedtls/error.h"
#include "mbedtls/net_sockets.h"
#include "mbedtls/pk.h"
#include "mbedtls/ssl.h"
#include "mbedtls/x509_crt.h"

#define DNS_TIMEOUT_MS      3000
#define DNS_TRIES           2
#define CONNECT_TIMEOUT_MS  10000
#define HANDSHAKE_TIMEOUT_S 15
#define UPSTREAM_HANDSHAKE_TIMEOUT_S 6
#define UPSTREAM_ATTEMPTS   3
#define IDLE_TIMEOUT_MS     60000
#define RELAY_BUF           4096

struct config {
    const char *listen_addr;
    int         listen_port;
    const char *cert_file;
    const char *key_file;
    const char *ca_file;
    const char *upstream_host;
    int         upstream_port;
    const char *resolv_file;
    int         max_children;
    int         dns_enabled;
    const char *blocklist_file;
};

/* Immutable after startup; shared copy-on-write with children. */
static mbedtls_x509_crt g_server_crt;
static mbedtls_pk_context g_server_key;
static mbedtls_x509_crt g_ca_chain;

static volatile sig_atomic_t g_children;
static volatile pid_t g_dns_pid;

/* Structured, audit-safe log line: no payload, no URLs. */
static void log_json(const char *level, const char *event, const char *fmt, ...)
{
    char detail[256] = "";
    if (fmt != NULL) {
        va_list ap;
        va_start(ap, fmt);
        vsnprintf(detail, sizeof(detail), fmt, ap);
        va_end(ap);
        for (char *p = detail; *p != '\0'; p++) {
            if (*p == '"' || *p == '\\' || (unsigned char)*p < 0x20) {
                *p = ' ';
            }
        }
    }
    fprintf(stderr, "{\"ts\":%ld,\"pid\":%d,\"level\":\"%s\",\"event\":\"%s\",\"detail\":\"%s\"}\n",
            (long)time(NULL), (int)getpid(), level, event, detail);
}

static const char *tls_err(int ret)
{
    static char buf[128];
    mbedtls_strerror(ret, buf, sizeof(buf));
    return buf;
}

static void die(const char *event, const char *detail)
{
    log_json("fatal", event, "%s", detail);
    exit(1);
}

/* ---------------------------------------------------------------- DNS */

#define MAX_NAMESERVERS 3

static int read_nameservers(const char *path, struct in_addr *out, int max)
{
    FILE *f = fopen(path, "r");
    if (f == NULL) {
        return 0;
    }
    char line[256];
    int count = 0;
    while (count < max && fgets(line, sizeof(line), f) != NULL) {
        char addr[64];
        if (sscanf(line, " nameserver %63s", addr) == 1 && inet_pton(AF_INET, addr, &out[count]) == 1) {
            count++;
        }
    }
    fclose(f);
    return count;
}

static int dns_encode_name(const char *host, uint8_t *out, size_t cap)
{
    size_t pos = 0;
    const char *label = host;
    while (*label != '\0') {
        const char *dot = strchr(label, '.');
        size_t len = dot ? (size_t)(dot - label) : strlen(label);
        if (len == 0 || len > 63 || pos + len + 2 > cap) {
            return -1;
        }
        out[pos++] = (uint8_t)len;
        memcpy(out + pos, label, len);
        pos += len;
        label += len + (dot ? 1 : 0);
    }
    out[pos++] = 0;
    return (int)pos;
}

/* Advance past a (possibly compressed) name; returns new offset or -1. */
static int dns_skip_name(const uint8_t *msg, int len, int off)
{
    while (off < len) {
        uint8_t c = msg[off];
        if (c == 0) {
            return off + 1;
        }
        if ((c & 0xC0) == 0xC0) {
            return (off + 2 <= len) ? off + 2 : -1;
        }
        off += c + 1;
    }
    return -1;
}

/* One A query to one nameserver, with retries. */
static int query_a(struct in_addr ns, const char *host, struct in_addr *out)
{

    uint8_t q[512];
    uint16_t id = (uint16_t)((getpid() ^ time(NULL)) & 0xFFFF);
    memset(q, 0, 12);
    q[0] = id >> 8; q[1] = id & 0xFF;
    q[2] = 0x01;                 /* RD */
    q[5] = 0x01;                 /* QDCOUNT = 1 */
    int nlen = dns_encode_name(host, q + 12, sizeof(q) - 16);
    if (nlen < 0) {
        return -1;
    }
    int qlen = 12 + nlen;
    q[qlen++] = 0; q[qlen++] = 1;   /* QTYPE A */
    q[qlen++] = 0; q[qlen++] = 1;   /* QCLASS IN */

    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0) {
        return -1;
    }
    struct sockaddr_in sa = { .sin_family = AF_INET, .sin_port = htons(53), .sin_addr = ns };
    int result = -1;

    for (int attempt = 0; attempt < DNS_TRIES && result != 0; attempt++) {
        if (sendto(fd, q, (size_t)qlen, 0, (struct sockaddr *)&sa, sizeof(sa)) != qlen) {
            continue;
        }
        struct pollfd pfd = { .fd = fd, .events = POLLIN };
        if (poll(&pfd, 1, DNS_TIMEOUT_MS) <= 0) {
            continue;
        }
        uint8_t r[1500];
        ssize_t rlen = recv(fd, r, sizeof(r), 0);
        if (rlen < 12 || r[0] != q[0] || r[1] != q[1] || (r[3] & 0x0F) != 0) {
            continue;
        }
        int qd = (r[4] << 8) | r[5];
        int an = (r[6] << 8) | r[7];
        int off = 12;
        for (int i = 0; i < qd && off > 0; i++) {
            off = dns_skip_name(r, (int)rlen, off);
            if (off > 0) {
                off += 4;
            }
        }
        for (int i = 0; i < an && off > 0 && off + 10 <= rlen; i++) {
            off = dns_skip_name(r, (int)rlen, off);
            if (off < 0 || off + 10 > rlen) {
                break;
            }
            int type = (r[off] << 8) | r[off + 1];
            int rdlen = (r[off + 8] << 8) | r[off + 9];
            off += 10;
            if (off + rdlen > rlen) {
                break;
            }
            if (type == 1 && rdlen == 4) {
                memcpy(out, r + off, 4);
                result = 0;
                break;
            }
            off += rdlen;   /* CNAME or other: keep scanning */
        }
    }
    close(fd);
    return result;
}

/* Minimal A-record lookup that deliberately bypasses /etc/hosts. */
static int resolve_a(const char *resolv_file, const char *host, struct in_addr *out)
{
    struct in_addr ns[MAX_NAMESERVERS];
    int count = read_nameservers(resolv_file, ns, MAX_NAMESERVERS);
    if (count == 0) {
        log_json("error", "dns_no_nameserver", "%s", resolv_file);
        return -1;
    }
    for (int i = 0; i < count; i++) {
        if (ns[i].s_addr == htonl(INADDR_LOOPBACK)) {
            continue;   /* our own forwarder would answer 127.0.0.1: loop */
        }
        if (query_a(ns[i], host, out) == 0) {
            return 0;
        }
        log_json("warn", "dns_server_failed", "%s", inet_ntoa(ns[i]));
    }
    return -1;
}

/* ------------------------------------------------------- DNS forwarder */

/*
 * The camera's glibc has no /etc/nsswitch.conf, so its built-in order is
 * "dns [!UNAVAIL=return] files": /etc/hosts is ignored while DNS answers.
 * We therefore answer the upstream host ourselves (A -> 127.0.0.1, other
 * types -> empty NOERROR) and forward every other query unchanged.
 */

/* Read the (uncompressed) question name; returns 0 and sets *end, or -1. */
static int dns_read_qname(const uint8_t *msg, int len, int off, char *name, size_t cap, int *end)
{
    size_t pos = 0;
    while (off < len && msg[off] != 0) {
        int l = msg[off];
        if ((l & 0xC0) != 0 || off + 1 + l > len || pos + (size_t)l + 2 > cap) {
            return -1;              /* compression is not valid in a question */
        }
        if (pos > 0) {
            name[pos++] = '.';
        }
        memcpy(name + pos, msg + off + 1, (size_t)l);
        pos += (size_t)l;
        off += l + 1;
    }
    if (off >= len) {
        return -1;
    }
    name[pos] = '\0';
    *end = off + 1;
    return 0;
}

/* ------------------------------------------------------------ blocklist */

#define MAX_BLOCKED 128

/* Immutable after startup. Entries starting with '.' match that domain and all subdomains. */
static char g_blocked[MAX_BLOCKED][256];
static int g_blocked_count;

static void load_blocklist(const char *path)
{
    FILE *f = fopen(path, "r");
    if (f == NULL) {
        die("load_blocklist", strerror(errno));
    }
    char line[300];
    while (fgets(line, sizeof(line), f) != NULL) {
        char *p = line;
        while (*p == ' ' || *p == '\t') {
            p++;
        }
        size_t n = strcspn(p, " \t\r\n#");
        if (n == 0) {
            continue;
        }
        if (n >= sizeof(g_blocked[0]) || g_blocked_count >= MAX_BLOCKED) {
            die("load_blocklist", "entry too long or too many entries");
        }
        memcpy(g_blocked[g_blocked_count], p, n);
        g_blocked[g_blocked_count][n] = '\0';
        g_blocked_count++;
    }
    fclose(f);
}

static int is_blocked(const char *name)
{
    size_t nlen = strlen(name);
    for (int i = 0; i < g_blocked_count; i++) {
        const char *b = g_blocked[i];
        if (b[0] == '.') {
            size_t blen = strlen(b);
            if (strcasecmp(name, b + 1) == 0 ||
                (nlen > blen && strcasecmp(name + nlen - blen, b) == 0)) {
                return 1;
            }
        } else if (strcasecmp(name, b) == 0) {
            return 1;
        }
    }
    return 0;
}

static ssize_t dns_forward(const char *resolv_file, const uint8_t *q, size_t qlen, uint8_t *r, size_t rcap)
{
    struct in_addr ns[MAX_NAMESERVERS];
    int count = read_nameservers(resolv_file, ns, MAX_NAMESERVERS);
    for (int i = 0; i < count; i++) {
        if (ns[i].s_addr == htonl(INADDR_LOOPBACK)) {
            continue;               /* never forward to ourselves */
        }
        int fd = socket(AF_INET, SOCK_DGRAM, 0);
        if (fd < 0) {
            return -1;
        }
        struct sockaddr_in sa = { .sin_family = AF_INET, .sin_port = htons(53), .sin_addr = ns[i] };
        ssize_t n = -1;
        if (sendto(fd, q, qlen, 0, (struct sockaddr *)&sa, sizeof(sa)) == (ssize_t)qlen) {
            struct pollfd pfd = { .fd = fd, .events = POLLIN };
            if (poll(&pfd, 1, DNS_TIMEOUT_MS) > 0) {
                n = recv(fd, r, rcap, 0);
            }
        }
        close(fd);
        if (n >= 12 && r[0] == q[0] && r[1] == q[1]) {
            return n;
        }
    }
    return -1;
}

static void dns_server_loop(const struct config *cfg)
{
    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    struct sockaddr_in la = { .sin_family = AF_INET, .sin_port = htons(53) };
    la.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    if (fd < 0 || bind(fd, (struct sockaddr *)&la, sizeof(la)) != 0) {
        die("dns_listen", strerror(errno));
    }
    log_json("info", "dns_started", "127.0.0.1:53 %s -> 127.0.0.1, %d blocked, rest via %s",
             cfg->upstream_host, g_blocked_count, cfg->resolv_file);

    for (;;) {
        uint8_t q[512], r[1500];
        struct sockaddr_in from;
        socklen_t flen = sizeof(from);
        ssize_t qlen = recvfrom(fd, q, sizeof(q), 0, (struct sockaddr *)&from, &flen);
        if (qlen < 12 || (q[2] & 0x80) != 0) {
            continue;               /* too short, or a response */
        }
        int qd = (q[4] << 8) | q[5];
        int qend = 0;
        char qname[256];
        int parsed = (qd == 1) && dns_read_qname(q, (int)qlen, 12, qname, sizeof(qname), &qend) == 0
                     && qend + 4 <= qlen;

        if (parsed && is_blocked(qname)) {
            int alen = qend + 4;
            memcpy(r, q, (size_t)alen);
            r[2] = 0x84 | (q[2] & 0x01);    /* QR, AA, keep RD */
            r[3] = 0x83;                    /* RA, NXDOMAIN */
            r[6] = 0; r[7] = 0; r[8] = 0; r[9] = 0; r[10] = 0; r[11] = 0;
            sendto(fd, r, (size_t)alen, 0, (struct sockaddr *)&from, flen);
            log_json("info", "dns_blocked", "%s", qname);
            continue;
        }
        if (parsed && strcasecmp(qname, cfg->upstream_host) == 0) {
            int qtype = (q[qend] << 8) | q[qend + 1];
            int alen = qend + 4;
            memcpy(r, q, (size_t)alen);
            r[2] = 0x84 | (q[2] & 0x01);    /* QR, AA, keep RD */
            r[3] = 0x80;                    /* RA, NOERROR */
            r[6] = 0; r[7] = 0; r[8] = 0; r[9] = 0; r[10] = 0; r[11] = 0;
            if (qtype == 1) {
                static const uint8_t rr[] = { 0xC0, 0x0C, 0, 1, 0, 1, 0, 0, 0, 60, 0, 4, 127, 0, 0, 1 };
                memcpy(r + alen, rr, sizeof(rr));
                alen += (int)sizeof(rr);
                r[7] = 1;
            }
            sendto(fd, r, (size_t)alen, 0, (struct sockaddr *)&from, flen);
            continue;
        }
        ssize_t rlen = dns_forward(cfg->resolv_file, q, (size_t)qlen, r, sizeof(r));
        if (rlen > 0) {
            sendto(fd, r, (size_t)rlen, 0, (struct sockaddr *)&from, flen);
        }
    }
}

/* ---------------------------------------------------------- sockets */

static int connect_timeout(struct in_addr addr, int port, int timeout_ms)
{
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) {
        return -1;
    }
    int flags = fcntl(fd, F_GETFL, 0);
    fcntl(fd, F_SETFL, flags | O_NONBLOCK);
    struct sockaddr_in sa = { .sin_family = AF_INET, .sin_port = htons((uint16_t)port), .sin_addr = addr };
    int rc = connect(fd, (struct sockaddr *)&sa, sizeof(sa));
    if (rc != 0 && errno != EINPROGRESS) {
        close(fd);
        return -1;
    }
    if (rc != 0) {
        struct pollfd pfd = { .fd = fd, .events = POLLOUT };
        int err = 0;
        socklen_t elen = sizeof(err);
        if (poll(&pfd, 1, timeout_ms) <= 0 ||
            getsockopt(fd, SOL_SOCKET, SO_ERROR, &err, &elen) != 0 || err != 0) {
            close(fd);
            return -1;
        }
    }
    fcntl(fd, F_SETFL, flags);
    return fd;
}

static void set_io_timeout(int fd, int seconds)
{
    struct timeval tv = { .tv_sec = seconds, .tv_usec = 0 };
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
}

/* --------------------------------------------------------------- TLS */

/* Only what CyaSSL 3.3.0 can negotiate: RSA key exchange, AES, SHA-1/SHA-256. */
static const int k_downstream_suites[] = {
    MBEDTLS_TLS_RSA_WITH_AES_128_GCM_SHA256,
    MBEDTLS_TLS_RSA_WITH_AES_256_GCM_SHA384,
    MBEDTLS_TLS_RSA_WITH_AES_128_CBC_SHA256,
    MBEDTLS_TLS_RSA_WITH_AES_256_CBC_SHA256,
    MBEDTLS_TLS_RSA_WITH_AES_128_CBC_SHA,
    MBEDTLS_TLS_RSA_WITH_AES_256_CBC_SHA,
    0
};

static int tls_write_all(mbedtls_ssl_context *ssl, const unsigned char *buf, size_t len)
{
    while (len > 0) {
        int n = mbedtls_ssl_write(ssl, buf, len);
        if (n == MBEDTLS_ERR_SSL_WANT_READ || n == MBEDTLS_ERR_SSL_WANT_WRITE) {
            continue;
        }
        if (n <= 0) {
            return -1;
        }
        buf += n;
        len -= (size_t)n;
    }
    return 0;
}

/* Move whatever is readable from src to dst. 0 = ok, 1 = clean close, -1 = error. */
static int pump(mbedtls_ssl_context *src, mbedtls_ssl_context *dst, unsigned long *moved)
{
    unsigned char buf[RELAY_BUF];
    do {
        int n = mbedtls_ssl_read(src, buf, sizeof(buf));
        if (n == MBEDTLS_ERR_SSL_WANT_READ || n == MBEDTLS_ERR_SSL_WANT_WRITE) {
            return 0;
        }
        if (n == 0 || n == MBEDTLS_ERR_SSL_PEER_CLOSE_NOTIFY) {
            return 1;
        }
        if (n < 0) {
            return -1;
        }
        if (tls_write_all(dst, buf, (size_t)n) != 0) {
            return -1;
        }
        *moved += (unsigned long)n;
    } while (mbedtls_ssl_get_bytes_avail(src) > 0);
    return 0;
}

static void handle_client(const struct config *cfg, int client_fd)
{
    mbedtls_entropy_context entropy;
    mbedtls_ctr_drbg_context drbg;
    mbedtls_ssl_config down_conf, up_conf;
    mbedtls_ssl_context down, up;
    mbedtls_net_context down_net = { .fd = client_fd };
    mbedtls_net_context up_net = { .fd = -1 };
    int ret;

    mbedtls_entropy_init(&entropy);
    mbedtls_ctr_drbg_init(&drbg);
    mbedtls_ssl_config_init(&down_conf);
    mbedtls_ssl_config_init(&up_conf);
    mbedtls_ssl_init(&down);
    mbedtls_ssl_init(&up);

    const char *pers = "yi-tls-bridge";
    if ((ret = mbedtls_ctr_drbg_seed(&drbg, mbedtls_entropy_func, &entropy,
                                     (const unsigned char *)pers, strlen(pers))) != 0) {
        log_json("error", "drbg_seed", "%s", tls_err(ret));
        goto out;
    }

    /* Downstream: legacy TLS 1.2 server for the camera's CyaSSL. */
    mbedtls_ssl_config_defaults(&down_conf, MBEDTLS_SSL_IS_SERVER,
                                MBEDTLS_SSL_TRANSPORT_STREAM, MBEDTLS_SSL_PRESET_DEFAULT);
    mbedtls_ssl_conf_rng(&down_conf, mbedtls_ctr_drbg_random, &drbg);
    mbedtls_ssl_conf_min_tls_version(&down_conf, MBEDTLS_SSL_VERSION_TLS1_2);
    mbedtls_ssl_conf_max_tls_version(&down_conf, MBEDTLS_SSL_VERSION_TLS1_2);
    mbedtls_ssl_conf_ciphersuites(&down_conf, k_downstream_suites);
    if ((ret = mbedtls_ssl_conf_own_cert(&down_conf, &g_server_crt, &g_server_key)) != 0 ||
        (ret = mbedtls_ssl_setup(&down, &down_conf)) != 0) {
        log_json("error", "downstream_setup", "%s", tls_err(ret));
        goto out;
    }
    /* SO_RCVTIMEO alone does not work: mbedtls maps EAGAIN to WANT_READ and the
     * handshake loop would spin forever. Use mbedtls' own read timeout. */
    mbedtls_ssl_conf_read_timeout(&down_conf, HANDSHAKE_TIMEOUT_S * 1000);
    mbedtls_ssl_set_bio(&down, &down_net, mbedtls_net_send, NULL, mbedtls_net_recv_timeout);

    set_io_timeout(client_fd, HANDSHAKE_TIMEOUT_S);   /* bounds blocking sends */
    while ((ret = mbedtls_ssl_handshake(&down)) != 0) {
        if (ret != MBEDTLS_ERR_SSL_WANT_READ && ret != MBEDTLS_ERR_SSL_WANT_WRITE) {
            log_json("warn", "downstream_handshake", "%s", tls_err(ret));
            goto out;
        }
    }

    /* Upstream: modern TLS 1.2 client with full verification.
     * Handshakes to Yi intermittently stall, so use a short timeout and retry;
     * the camera is already waiting on the downstream side. */
    mbedtls_ssl_config_defaults(&up_conf, MBEDTLS_SSL_IS_CLIENT,
                                MBEDTLS_SSL_TRANSPORT_STREAM, MBEDTLS_SSL_PRESET_DEFAULT);
    mbedtls_ssl_conf_rng(&up_conf, mbedtls_ctr_drbg_random, &drbg);
    mbedtls_ssl_conf_min_tls_version(&up_conf, MBEDTLS_SSL_VERSION_TLS1_2);
    mbedtls_ssl_conf_authmode(&up_conf, MBEDTLS_SSL_VERIFY_REQUIRED);
    mbedtls_ssl_conf_ca_chain(&up_conf, &g_ca_chain, NULL);
    mbedtls_ssl_conf_read_timeout(&up_conf, UPSTREAM_HANDSHAKE_TIMEOUT_S * 1000);
    if ((ret = mbedtls_ssl_setup(&up, &up_conf)) != 0 ||
        (ret = mbedtls_ssl_set_hostname(&up, cfg->upstream_host)) != 0) {
        log_json("error", "upstream_setup", "%s", tls_err(ret));
        goto out;
    }

    int connected = 0;
    for (int attempt = 1; attempt <= UPSTREAM_ATTEMPTS && !connected; attempt++) {
        if (attempt > 1) {
            mbedtls_ssl_session_reset(&up);
            if (up_net.fd >= 0) {
                close(up_net.fd);
                up_net.fd = -1;
            }
        }
        struct in_addr addr = { 0 };
        if (resolve_a(cfg->resolv_file, cfg->upstream_host, &addr) != 0) {
            log_json("warn", "dns_failed", "%s attempt=%d", cfg->upstream_host, attempt);
            continue;
        }
        up_net.fd = connect_timeout(addr, cfg->upstream_port, CONNECT_TIMEOUT_MS);
        if (up_net.fd < 0) {
            log_json("warn", "upstream_connect", "%s attempt=%d", inet_ntoa(addr), attempt);
            continue;
        }
        set_io_timeout(up_net.fd, UPSTREAM_HANDSHAKE_TIMEOUT_S);
        mbedtls_ssl_set_bio(&up, &up_net, mbedtls_net_send, NULL, mbedtls_net_recv_timeout);
        while ((ret = mbedtls_ssl_handshake(&up)) != 0) {
            if (ret != MBEDTLS_ERR_SSL_WANT_READ && ret != MBEDTLS_ERR_SSL_WANT_WRITE) {
                break;
            }
        }
        if (ret == 0) {
            connected = 1;
            break;
        }
        uint32_t flags = mbedtls_ssl_get_verify_result(&up);
        if (flags != 0 && flags != (uint32_t)-1) {
            /* A verification failure is a verdict, not a glitch: never retry it. */
            char vinfo[128] = "";
            mbedtls_x509_crt_verify_info(vinfo, sizeof(vinfo), "", flags);
            log_json("error", "upstream_verify", "%s", vinfo);
            goto out;
        }
        log_json("warn", "upstream_handshake", "%s attempt=%d", tls_err(ret), attempt);
    }
    if (!connected) {
        log_json("error", "upstream_failed", "gave up after %d attempts", UPSTREAM_ATTEMPTS);
        goto out;
    }

    /* Relay until either side closes or the connection idles out. */
    unsigned long bytes_up = 0, bytes_down = 0;
    time_t started = time(NULL);
    set_io_timeout(client_fd, 0);
    set_io_timeout(up_net.fd, 0);
    mbedtls_net_set_nonblock(&down_net);
    mbedtls_net_set_nonblock(&up_net);
    mbedtls_ssl_set_bio(&down, &down_net, mbedtls_net_send, mbedtls_net_recv, NULL);
    mbedtls_ssl_set_bio(&up, &up_net, mbedtls_net_send, mbedtls_net_recv, NULL);
    for (;;) {
        if (mbedtls_ssl_get_bytes_avail(&down) == 0 && mbedtls_ssl_get_bytes_avail(&up) == 0) {
            struct pollfd pfd[2] = {
                { .fd = client_fd, .events = POLLIN },
                { .fd = up_net.fd, .events = POLLIN },
            };
            int pr = poll(pfd, 2, IDLE_TIMEOUT_MS);
            if (pr == 0) {
                log_json("info", "idle_timeout", NULL);
                break;
            }
            if (pr < 0) {
                if (errno == EINTR) {
                    continue;
                }
                break;
            }
            if ((pfd[0].revents | pfd[1].revents) & (POLLERR | POLLNVAL)) {
                break;
            }
        }
        int a = pump(&down, &up, &bytes_up);
        int b = pump(&up, &down, &bytes_down);
        if (a != 0 || b != 0) {
            break;
        }
    }
    mbedtls_ssl_close_notify(&up);
    mbedtls_ssl_close_notify(&down);
    log_json("info", "relayed", "up=%lu down=%lu secs=%ld cipher_down=%s",
             bytes_up, bytes_down, (long)(time(NULL) - started),
             mbedtls_ssl_get_ciphersuite(&down));

out:
    mbedtls_ssl_free(&up);
    mbedtls_ssl_free(&down);
    mbedtls_ssl_config_free(&up_conf);
    mbedtls_ssl_config_free(&down_conf);
    mbedtls_ctr_drbg_free(&drbg);
    mbedtls_entropy_free(&entropy);
    if (up_net.fd >= 0) {
        close(up_net.fd);
    }
    close(client_fd);
}

/* ------------------------------------------------------------- main */

static void on_sigchld(int sig)
{
    (void)sig;
    int saved = errno;
    pid_t pid;
    while ((pid = waitpid(-1, NULL, WNOHANG)) > 0) {
        if (pid == g_dns_pid) {
            /* Without DNS the camera has no name resolution at all: exit so
             * the supervisor restarts both. _exit() is async-signal-safe. */
            static const char msg[] = "{\"level\":\"fatal\",\"event\":\"dns_died\"}\n";
            if (write(STDERR_FILENO, msg, sizeof(msg) - 1) < 0) { /* nothing else to do */ }
            _exit(3);
        } else {
            g_children--;
        }
    }
    errno = saved;
}

static void usage(const char *argv0)
{
    fprintf(stderr,
            "usage: %s -c cert.pem -k key.pem -a ca-bundle.pem -u upstream-host\n"
            "          [-l 127.0.0.1] [-p 443] [-P 443] [-r /etc/resolv.conf] [-n 8] [-d]\n"
            "  -d  also serve DNS on 127.0.0.1:53 (upstream host -> 127.0.0.1, rest forwarded via -r)\n"
            "  -b  with -d: answer NXDOMAIN for names in this file ('.example.com' = domain + subdomains)\n",
            argv0);
    exit(2);
}

static int parse_port(const char *s)
{
    char *end = NULL;
    long v = strtol(s, &end, 10);
    if (end == s || *end != '\0' || v < 1 || v > 65535) {
        die("bad_argument", "port out of range");
    }
    return (int)v;
}

int main(int argc, char **argv)
{
    struct config cfg = {
        .listen_addr = "127.0.0.1", .listen_port = 443, .upstream_port = 443,
        .resolv_file = "/etc/resolv.conf", .max_children = 8,
    };
    int opt;
    while ((opt = getopt(argc, argv, "c:k:a:u:l:p:P:r:n:db:")) != -1) {
        switch (opt) {
        case 'c': cfg.cert_file = optarg; break;
        case 'k': cfg.key_file = optarg; break;
        case 'a': cfg.ca_file = optarg; break;
        case 'u': cfg.upstream_host = optarg; break;
        case 'l': cfg.listen_addr = optarg; break;
        case 'p': cfg.listen_port = parse_port(optarg); break;
        case 'P': cfg.upstream_port = parse_port(optarg); break;
        case 'r': cfg.resolv_file = optarg; break;
        case 'n': cfg.max_children = atoi(optarg); break;
        case 'd': cfg.dns_enabled = 1; break;
        case 'b': cfg.blocklist_file = optarg; break;
        default: usage(argv[0]);
        }
    }
    if (cfg.cert_file == NULL || cfg.key_file == NULL || cfg.ca_file == NULL ||
        cfg.upstream_host == NULL || cfg.max_children < 1 || cfg.max_children > 64) {
        usage(argv[0]);
    }

    int ret;
    mbedtls_x509_crt_init(&g_server_crt);
    mbedtls_pk_init(&g_server_key);
    mbedtls_x509_crt_init(&g_ca_chain);
    if ((ret = mbedtls_x509_crt_parse_file(&g_server_crt, cfg.cert_file)) != 0) {
        die("load_cert", tls_err(ret));
    }
    {
        /* Key parsing may need an RNG for blinding checks; a throwaway one is fine here. */
        mbedtls_entropy_context e;
        mbedtls_ctr_drbg_context d;
        mbedtls_entropy_init(&e);
        mbedtls_ctr_drbg_init(&d);
        if ((ret = mbedtls_ctr_drbg_seed(&d, mbedtls_entropy_func, &e, NULL, 0)) != 0 ||
            (ret = mbedtls_pk_parse_keyfile(&g_server_key, cfg.key_file, NULL,
                                            mbedtls_ctr_drbg_random, &d)) != 0) {
            die("load_key", tls_err(ret));
        }
        mbedtls_ctr_drbg_free(&d);
        mbedtls_entropy_free(&e);
    }
    /* A bundle may contain certs mbedTLS cannot parse; >0 means "some skipped". */
    ret = mbedtls_x509_crt_parse_file(&g_ca_chain, cfg.ca_file);
    if (ret < 0 || g_ca_chain.version == 0) {
        die("load_ca", ret < 0 ? tls_err(ret) : "no usable CA certificates");
    }

    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = on_sigchld;
    sa.sa_flags = SA_RESTART | SA_NOCLDSTOP;
    sigaction(SIGCHLD, &sa, NULL);
    signal(SIGPIPE, SIG_IGN);

    int lfd = socket(AF_INET, SOCK_STREAM, 0);
    int one = 1;
    struct sockaddr_in la = { .sin_family = AF_INET, .sin_port = htons((uint16_t)cfg.listen_port) };
    if (lfd < 0 || inet_pton(AF_INET, cfg.listen_addr, &la.sin_addr) != 1) {
        die("listen", "bad listen address");
    }
    setsockopt(lfd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
    if (bind(lfd, (struct sockaddr *)&la, sizeof(la)) != 0 || listen(lfd, 16) != 0) {
        die("listen", strerror(errno));
    }
    if (cfg.blocklist_file != NULL) {
        if (!cfg.dns_enabled) {
            usage(argv[0]);
        }
        load_blocklist(cfg.blocklist_file);
    }
    if (cfg.dns_enabled) {
        pid_t dpid = fork();
        if (dpid == 0) {
            /* Die with the parent so a restart can rebind port 53. */
            prctl(PR_SET_PDEATHSIG, SIGTERM);
            if (getppid() == 1) {
                _exit(1);
            }
            close(lfd);
            dns_server_loop(&cfg);
            _exit(1);
        }
        if (dpid < 0) {
            die("fork", strerror(errno));
        }
        g_dns_pid = dpid;
    }
    log_json("info", "started", "%s:%d -> %s:%d", cfg.listen_addr, cfg.listen_port,
             cfg.upstream_host, cfg.upstream_port);

    for (;;) {
        int cfd = accept(lfd, NULL, NULL);
        if (cfd < 0) {
            if (errno != EINTR) {
                log_json("warn", "accept", "%s", strerror(errno));
            }
            continue;
        }
        if (g_children >= cfg.max_children) {
            log_json("warn", "busy", "rejecting connection");
            close(cfd);
            continue;
        }
        /* Block SIGCHLD so the handler cannot race the counter update. */
        sigset_t block, prev;
        sigemptyset(&block);
        sigaddset(&block, SIGCHLD);
        sigprocmask(SIG_BLOCK, &block, &prev);
        pid_t pid = fork();
        if (pid == 0) {
            sigprocmask(SIG_SETMASK, &prev, NULL);
            close(lfd);
            handle_client(&cfg, cfd);
            _exit(0);
        }
        if (pid > 0) {
            g_children++;
        } else {
            log_json("error", "fork", "%s", strerror(errno));
        }
        sigprocmask(SIG_SETMASK, &prev, NULL);
        close(cfd);
    }
}
