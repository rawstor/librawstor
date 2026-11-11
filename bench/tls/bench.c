/*
 * TLS cost on the rawstor data path (docs/security.md, stage 0).
 *
 * One binary, two roles (server / client), four transports:
 *   plain  TCP, io_uring send/recv
 *   ktls   OpenSSL handshake, then the kernel does the records; the same
 *          io_uring send/recv as plain
 *   ubio   userspace OpenSSL over memory BIOs; io_uring moves ciphertext
 *   ufd    userspace OpenSSL SSL_read/SSL_write on the socket (reference)
 *
 * Workloads: up (client -> server stream), down (server -> client stream),
 * rr (request/response at a queue depth), hs (handshakes per second),
 * echo + probe (does an io_uring feature still work on this transport).
 *
 * Build and run: run.sh.  Not part of the autotools build.
 */
#define _GNU_SOURCE
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <liburing.h>
#include <limits.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <openssl/err.h>
#include <openssl/ssl.h>
#include <sched.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/resource.h>
#include <sys/sendfile.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

enum { M_PLAIN, M_KTLS, M_UBIO, M_UFD };

struct cfg {
    int server;
    int mode;
    const char* mode_name;
    const char* work;
    const char* hs;
    const char* cipher;
    const char* certdir;
    int port;
    int cpu;
    int qd;
    int conns;
    double secs;
    size_t size;
    size_t req;
    size_t resp;
};

static struct cfg C = {
    .mode_name = "plain",
    .work = "rr",
    .hs = "full",
    .cipher = "TLS_AES_256_GCM_SHA384",
    .certdir = ".",
    .port = 7790,
    .cpu = -1,
    .qd = 1,
    .conns = 1,
    .secs = 5.0,
    .size = 1 << 20,
    .req = 4144,
    .resp = 16,
};

#define CBUF (1u << 21)

struct conn {
    int fd;
    int mode;
    SSL* ssl;
    BIO *rb, *wb;
    struct io_uring ring;
    unsigned char* cbuf;
};

static void die(const char* what) {
    fprintf(stderr, "FATAL %s: %s\n", what, strerror(errno));
    ERR_print_errors_fp(stderr);
    exit(2);
}

static uint64_t now_ns(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000000000ull + (uint64_t)ts.tv_nsec;
}

struct stats {
    uint64_t t0;
    double u0, s0;
};

static void cpu_times(double* user, double* sys) {
    struct rusage ru;
    getrusage(RUSAGE_SELF, &ru);
    *user = (double)ru.ru_utime.tv_sec + (double)ru.ru_utime.tv_usec / 1e6;
    *sys = (double)ru.ru_stime.tv_sec + (double)ru.ru_stime.tv_usec / 1e6;
}

static void stats_begin(struct stats* s) {
    cpu_times(&s->u0, &s->s0);
    s->t0 = now_ns();
}

/* ---- io_uring helpers: one synchronous op at a time, like a QD1 caller -- */

static int uring_wait(struct io_uring* r) {
    struct io_uring_cqe* cqe;
    int res = io_uring_wait_cqe(r, &cqe);
    if (res < 0)
        return res;
    res = cqe->res;
    io_uring_cqe_seen(r, cqe);
    return res;
}

static int uring_send1(struct conn* c, const void* b, size_t n) {
    struct io_uring_sqe* sqe = io_uring_get_sqe(&c->ring);
    io_uring_prep_send(sqe, c->fd, b, n, MSG_NOSIGNAL);
    io_uring_submit(&c->ring);
    return uring_wait(&c->ring);
}

static int uring_recv1(struct conn* c, void* b, size_t n) {
    struct io_uring_sqe* sqe = io_uring_get_sqe(&c->ring);
    io_uring_prep_recv(sqe, c->fd, b, n, 0);
    io_uring_submit(&c->ring);
    return uring_wait(&c->ring);
}

static int raw_send_all(struct conn* c, const unsigned char* b, size_t n) {
    while (n > 0) {
        int r = uring_send1(c, b, n);
        if (r <= 0)
            return r < 0 ? r : -EPIPE;
        b += r;
        n -= (size_t)r;
    }
    return 0;
}

/* ---- transport ---------------------------------------------------------- */

static int conn_send_all(struct conn* c, const void* buf, size_t len) {
    const unsigned char* p = buf;
    if (c->mode == M_PLAIN || c->mode == M_KTLS)
        return raw_send_all(c, p, len);
    while (len > 0) {
        size_t chunk = len > (1u << 20) ? (1u << 20) : len;
        int n = SSL_write(c->ssl, p, (int)chunk);
        if (n <= 0)
            return -EIO;
        p += n;
        len -= (size_t)n;
        if (c->mode == M_UBIO) {
            size_t pend;
            while ((pend = BIO_ctrl_pending(c->wb)) > 0) {
                int m = BIO_read(
                    c->wb, c->cbuf, pend > CBUF ? (int)CBUF : (int)pend
                );
                if (m <= 0)
                    return -EIO;
                int r = raw_send_all(c, c->cbuf, (size_t)m);
                if (r)
                    return r;
            }
        }
    }
    return 0;
}

/* Plaintext bytes (at least one), 0 on EOF, negative errno. */
static ssize_t conn_recv_some(struct conn* c, void* buf, size_t len) {
    if (c->mode == M_PLAIN || c->mode == M_KTLS)
        return uring_recv1(c, buf, len);
    if (len > INT_MAX)
        len = INT_MAX;
    for (;;) {
        int n = SSL_read(c->ssl, buf, (int)len);
        if (n > 0)
            return n;
        int err = SSL_get_error(c->ssl, n);
        if (err == SSL_ERROR_ZERO_RETURN)
            return 0;
        if (err == SSL_ERROR_WANT_READ && c->mode == M_UBIO) {
            int r = uring_recv1(c, c->cbuf, CBUF);
            if (r <= 0)
                return r;
            BIO_write(c->rb, c->cbuf, r);
            continue;
        }
        if (err == SSL_ERROR_SYSCALL && n == 0)
            return 0;
        return -EIO;
    }
}

/* 1 = got everything, 0 = clean EOF before the first byte, <0 error. */
static int conn_recv_exact(struct conn* c, void* buf, size_t len) {
    unsigned char* p = buf;
    size_t got = 0;
    while (got < len) {
        ssize_t r = conn_recv_some(c, p + got, len - got);
        if (r == 0)
            return got == 0 ? 0 : -ECONNRESET;
        if (r < 0)
            return (int)r;
        got += (size_t)r;
    }
    return 1;
}

/* ---- TLS setup ---------------------------------------------------------- */

static SSL_CTX* mk_ctx(int server, int tickets) {
    SSL_CTX* x =
        SSL_CTX_new(server ? TLS_server_method() : TLS_client_method());
    if (!x)
        die("SSL_CTX_new");
    SSL_CTX_set_min_proto_version(x, TLS1_3_VERSION);
    SSL_CTX_set_max_proto_version(x, TLS1_3_VERSION);
    if (SSL_CTX_set_ciphersuites(x, C.cipher) != 1)
        die("set_ciphersuites");
    SSL_CTX_set1_groups_list(x, "X25519");
    char cert[600], key[600], ca[600];
    const char* who = server ? "server" : "client";
    snprintf(cert, sizeof cert, "%s/%s.pem", C.certdir, who);
    snprintf(key, sizeof key, "%s/%s.key", C.certdir, who);
    snprintf(ca, sizeof ca, "%s/ca.pem", C.certdir);
    if (SSL_CTX_use_certificate_chain_file(x, cert) != 1)
        die("use_certificate_chain_file");
    if (SSL_CTX_use_PrivateKey_file(x, key, SSL_FILETYPE_PEM) != 1)
        die("use_PrivateKey_file");
    if (SSL_CTX_load_verify_locations(x, ca, NULL) != 1)
        die("load_verify_locations");
    SSL_CTX_set_verify(
        x, SSL_VERIFY_PEER | (server ? SSL_VERIFY_FAIL_IF_NO_PEER_CERT : 0),
        NULL
    );
    if (C.mode == M_KTLS)
        SSL_CTX_set_options(x, SSL_OP_ENABLE_KTLS);
    if (server) {
        /* required for resumption when the server verifies client certs */
        SSL_CTX_set_session_id_context(x, (const unsigned char*)"rawbench", 8);
        SSL_CTX_set_num_tickets(x, tickets ? 1 : 0);
    }
    return x;
}

static SSL* handshake(int fd, SSL_CTX* x, int server, SSL_SESSION* sess) {
    SSL* ssl = SSL_new(x);
    if (!ssl)
        die("SSL_new");
    SSL_set_fd(ssl, fd);
    if (sess)
        SSL_set_session(ssl, sess);
    int r = server ? SSL_accept(ssl) : SSL_connect(ssl);
    if (r != 1) {
        fprintf(
            stderr, "FATAL handshake failed (err %d)\n", SSL_get_error(ssl, r)
        );
        ERR_print_errors_fp(stderr);
        exit(2);
    }
    return ssl;
}

static void conn_setup(struct conn* c, int fd, SSL* ssl) {
    memset(c, 0, sizeof *c);
    c->fd = fd;
    c->mode = C.mode;
    c->ssl = ssl;
    c->cbuf = malloc(CBUF + 65536);
    if (io_uring_queue_init(64, &c->ring, 0) < 0)
        die("io_uring_queue_init");
    if (c->mode == M_KTLS) {
        if (!BIO_get_ktls_send(SSL_get_wbio(ssl)) ||
            !BIO_get_ktls_recv(SSL_get_rbio(ssl))) {
            fprintf(
                stderr, "KTLS_NOT_ACTIVE send=%d recv=%d\n",
                (int)BIO_get_ktls_send(SSL_get_wbio(ssl)),
                (int)BIO_get_ktls_recv(SSL_get_rbio(ssl))
            );
            exit(3);
        }
    } else if (c->mode == M_UBIO) {
        c->rb = BIO_new(BIO_s_mem());
        c->wb = BIO_new(BIO_s_mem());
        SSL_set_bio(ssl, c->rb, c->wb);
    }
}

static void conn_close(struct conn* c) {
    io_uring_queue_exit(&c->ring);
    close(c->fd);
    free(c->cbuf);
}

/* ---- sockets ------------------------------------------------------------ */

static int tune(int fd) {
    int one = 1;
    setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &one, sizeof one);
    return fd;
}

static int listen_fd(void) {
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    int one = 1;
    setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof one);
    struct sockaddr_in a = {.sin_family = AF_INET, .sin_port = htons(C.port)};
    a.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    if (bind(fd, (struct sockaddr*)&a, sizeof a) < 0)
        die("bind");
    if (listen(fd, 128) < 0)
        die("listen");
    return fd;
}

static int connect_fd(void) {
    struct sockaddr_in a = {.sin_family = AF_INET, .sin_port = htons(C.port)};
    a.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    for (int i = 0; i < 100; ++i) {
        int fd = socket(AF_INET, SOCK_STREAM, 0);
        if (connect(fd, (struct sockaddr*)&a, sizeof a) == 0)
            return tune(fd);
        close(fd);
        usleep(50000);
    }
    die("connect");
    return -1;
}

/* ---- workloads: streams ------------------------------------------------- */

static void
report_cpu(const char* role, const struct stats* s, uint64_t bytes) {
    double u, sy;
    cpu_times(&u, &sy);
    double secs = (double)(now_ns() - s->t0) / 1e9;
    printf(
        "%s mode=%s work=%s secs=%.3f bytes=%llu cpu_user=%.3f cpu_sys=%.3f\n",
        role, C.mode_name, C.work, secs, (unsigned long long)bytes, u - s->u0,
        sy - s->s0
    );
}

static void stream_sender(struct conn* c, int timed, const char* role) {
    unsigned char* buf = malloc(C.size);
    for (size_t i = 0; i < C.size; ++i)
        buf[i] = (unsigned char)(i * 131 + 7);
    struct stats st;
    stats_begin(&st);
    uint64_t total = 0;
    while (!timed || (double)(now_ns() - st.t0) / 1e9 < C.secs) {
        if (conn_send_all(c, buf, C.size))
            break;
        total += C.size;
    }
    report_cpu(role, &st, total);
    free(buf);
}

static void stream_receiver(struct conn* c, int timed, const char* role) {
    unsigned char* buf = malloc(C.size);
    struct stats st;
    uint64_t total = 0;
    int started = 0;
    for (;;) {
        ssize_t r = conn_recv_some(c, buf, C.size);
        if (r <= 0)
            break;
        if (!started) {
            stats_begin(&st);
            started = 1;
        }
        total += (uint64_t)r;
        if (timed && (double)(now_ns() - st.t0) / 1e9 >= C.secs)
            break;
    }
    if (started)
        report_cpu(role, &st, total);
    free(buf);
}

/* ---- workloads: request/response ---------------------------------------- */

static int cmp_u64(const void* a, const void* b) {
    uint64_t x = *(const uint64_t*)a, y = *(const uint64_t*)b;
    return x < y ? -1 : x > y;
}

static void rr_client(struct conn* c) {
    unsigned char* req = calloc(1, C.req);
    unsigned char* resp = calloc(1, C.resp);
    size_t cap = 4u << 20;
    uint64_t* lat = malloc(cap * sizeof *lat);
    size_t nlat = 0;
    uint64_t* fifo = calloc((size_t)C.qd, sizeof *fifo);
    int head = 0, tail = 0, inflight = 0;
    struct stats st;
    stats_begin(&st);
    uint64_t done = 0;
    for (int i = 0; i < C.qd; ++i) {
        fifo[tail] = now_ns();
        tail = (tail + 1) % C.qd;
        if (conn_send_all(c, req, C.req))
            die("send");
        ++inflight;
    }
    int stop = 0;
    while (inflight > 0) {
        int r = conn_recv_exact(c, resp, C.resp);
        if (r != 1)
            die("recv");
        uint64_t t = now_ns();
        if (nlat < cap)
            lat[nlat++] = t - fifo[head];
        head = (head + 1) % C.qd;
        --inflight;
        ++done;
        if (!stop && (double)(t - st.t0) / 1e9 >= C.secs)
            stop = 1;
        if (!stop) {
            fifo[tail] = now_ns();
            tail = (tail + 1) % C.qd;
            if (conn_send_all(c, req, C.req))
                die("send");
            ++inflight;
        }
    }
    double u, sy;
    cpu_times(&u, &sy);
    double secs = (double)(now_ns() - st.t0) / 1e9;
    qsort(lat, nlat, sizeof *lat, cmp_u64);
#define PCT(p) ((double)lat[(size_t)((double)(nlat - 1) * (p))] / 1e3)
    printf(
        "CLIENT mode=%s work=rr req=%zu resp=%zu qd=%d secs=%.3f ops=%llu "
        "iops=%.0f p50_us=%.1f p99_us=%.1f p999_us=%.1f bytes=%llu "
        "cpu_user=%.3f cpu_sys=%.3f\n",
        C.mode_name, C.req, C.resp, C.qd, secs, (unsigned long long)done,
        (double)done / secs, PCT(0.5), PCT(0.99), PCT(0.999),
        (unsigned long long)(done * (C.req + C.resp)), u - st.u0, sy - st.s0
    );
    free(req);
    free(resp);
    free(lat);
    free(fifo);
}

static void rr_server(struct conn* c) {
    unsigned char* req = malloc(C.req);
    unsigned char* resp = calloc(1, C.resp);
    struct stats st;
    int started = 0;
    uint64_t n = 0;
    for (;;) {
        int r = conn_recv_exact(c, req, C.req);
        if (r != 1)
            break;
        if (!started) {
            stats_begin(&st);
            started = 1;
        }
        if (conn_send_all(c, resp, C.resp))
            break;
        ++n;
    }
    if (started)
        report_cpu("SERVER", &st, n * (C.req + C.resp));
    free(req);
    free(resp);
}

/* ---- workload: handshakes ----------------------------------------------- */

static void hs_server(void) {
    int lfd = listen_fd();
    SSL_CTX* x =
        strcmp(C.hs, "tcp") ? mk_ctx(1, !strcmp(C.hs, "resume")) : NULL;
    struct stats st;
    stats_begin(&st);
    for (int i = 0; i < C.conns; ++i) {
        int fd = tune(accept(lfd, NULL, NULL));
        if (fd < 0)
            die("accept");
        if (x) {
            SSL* ssl = handshake(fd, x, 1, NULL);
            SSL_write(ssl, "x", 1);
            SSL_set_shutdown(ssl, SSL_SENT_SHUTDOWN | SSL_RECEIVED_SHUTDOWN);
            SSL_free(ssl);
        } else {
            if (write(fd, "x", 1) != 1)
                die("write");
        }
        close(fd);
    }
    report_cpu("SERVER", &st, 0);
}

static void hs_client(void) {
    SSL_CTX* x = strcmp(C.hs, "tcp") ? mk_ctx(0, 0) : NULL;
    int resume = !strcmp(C.hs, "resume");
    SSL_SESSION* sess = NULL;
    int reused = 0;
    struct stats st;
    stats_begin(&st);
    for (int i = 0; i < C.conns; ++i) {
        int fd = connect_fd();
        char b;
        if (x) {
            SSL* ssl = handshake(fd, x, 0, resume ? sess : NULL);
            if (SSL_read(ssl, &b, 1) != 1)
                die("read");
            if (SSL_session_reused(ssl))
                ++reused;
            if (resume && !sess)
                sess = SSL_get1_session(ssl);
            /* without this the session is marked non-resumable on free */
            SSL_set_shutdown(ssl, SSL_SENT_SHUTDOWN | SSL_RECEIVED_SHUTDOWN);
            SSL_free(ssl);
        } else if (read(fd, &b, 1) != 1) {
            die("read");
        }
        close(fd);
    }
    double u, sy;
    cpu_times(&u, &sy);
    double secs = (double)(now_ns() - st.t0) / 1e9;
    printf(
        "CLIENT mode=ufd work=hs hs=%s conns=%d secs=%.3f hs_per_s=%.0f "
        "reused=%d cpu_user=%.3f cpu_sys=%.3f\n",
        C.hs, C.conns, secs, (double)C.conns / secs, reused, u - st.u0,
        sy - st.s0
    );
}

/* ---- io_uring feature probes -------------------------------------------- */

#define PN (256u * 1024u)
#define PCH (64u * 1024u)
#define BGID 7

static unsigned char pat(size_t i) {
    return (unsigned char)(i * 131 + 7);
}

static void echo_server(void) {
    int lfd = listen_fd();
    SSL_CTX* x = C.mode == M_PLAIN ? NULL : mk_ctx(1, 0);
    for (int i = 0; i < C.conns; ++i) {
        int fd = tune(accept(lfd, NULL, NULL));
        SSL* ssl = x ? handshake(fd, x, 1, NULL) : NULL;
        struct conn c;
        conn_setup(&c, fd, ssl);
        unsigned char* buf = malloc(1 << 20);
        for (;;) {
            ssize_t r = conn_recv_some(&c, buf, 1 << 20);
            if (r <= 0)
                break;
            if (conn_send_all(&c, buf, (size_t)r))
                break;
        }
        free(buf);
        conn_close(&c);
    }
}

static const char* const probe_names[] = {
    "send",           "sendmsg",     "send_zc",
    "send_zc_fixed",  "write_fixed", "recv_bufsel",
    "recv_multishot", "read_fixed",  "sendfile",
};
#define NPROBE (sizeof probe_names / sizeof *probe_names)

/* Sender side under test. Returns 0 or negative errno. */
static int probe_send(struct conn* c, int which, unsigned char* data) {
    struct io_uring* r = &c->ring;
    size_t off = 0;
    if (which == 3 || which == 4) {
        struct iovec iov = {.iov_base = data, .iov_len = PN};
        int rr = io_uring_register_buffers(r, &iov, 1);
        if (rr < 0)
            return rr;
    }
    if (which == 8) {
        int mfd = memfd_create("probe", 0);
        if (write(mfd, data, PN) != (ssize_t)PN)
            return -EIO;
        off_t o = 0;
        while ((size_t)o < PN) {
            ssize_t n = sendfile(c->fd, mfd, &o, PN - (size_t)o);
            if (n < 0)
                return -errno;
        }
        close(mfd);
        return 0;
    }
    while (off < PN) {
        size_t n = PN - off > PCH ? PCH : PN - off;
        struct io_uring_sqe* sqe = io_uring_get_sqe(r);
        struct msghdr mh;
        struct iovec iv;
        switch (which) {
        case 0:
            io_uring_prep_send(sqe, c->fd, data + off, n, MSG_NOSIGNAL);
            break;
        case 1:
            iv.iov_base = data + off;
            iv.iov_len = n;
            memset(&mh, 0, sizeof mh);
            mh.msg_iov = &iv;
            mh.msg_iovlen = 1;
            io_uring_prep_sendmsg(sqe, c->fd, &mh, MSG_NOSIGNAL);
            break;
        case 2:
            io_uring_prep_send_zc(sqe, c->fd, data + off, n, MSG_NOSIGNAL, 0);
            break;
        case 3:
            io_uring_prep_send_zc_fixed(
                sqe, c->fd, data + off, n, MSG_NOSIGNAL, 0, 0
            );
            break;
        case 4:
            io_uring_prep_write_fixed(
                sqe, c->fd, data + off, (unsigned)n, 0, 0
            );
            break;
        }
        io_uring_submit(r);
        int res = 0, have = 0, more = 0, notif = 0;
        for (;;) {
            struct io_uring_cqe* cqe;
            int w = io_uring_wait_cqe(r, &cqe);
            if (w < 0)
                return w;
            if (cqe->flags & IORING_CQE_F_NOTIF) {
                notif = 1;
            } else {
                res = cqe->res;
                have = 1;
                more = (cqe->flags & IORING_CQE_F_MORE) != 0;
            }
            io_uring_cqe_seen(r, cqe);
            if (have && (!more || notif))
                break;
        }
        if (res < 0)
            return res;
        if (res == 0)
            return -EPIPE;
        off += (size_t)res;
    }
    return 0;
}

/* Receiver side under test; fills out[0..PN). */
static int probe_recv(struct conn* c, int which, unsigned char* out) {
    struct io_uring* r = &c->ring;
    size_t got = 0;
    if (which == 7) {
        struct iovec iov = {.iov_base = out, .iov_len = PN};
        int rr = io_uring_register_buffers(r, &iov, 1);
        if (rr < 0)
            return rr;
        while (got < PN) {
            struct io_uring_sqe* sqe = io_uring_get_sqe(r);
            io_uring_prep_read_fixed(
                sqe, c->fd, out + got, (unsigned)(PN - got), 0, 0
            );
            io_uring_submit(r);
            int res = uring_wait(r);
            if (res < 0)
                return res;
            if (res == 0)
                return -EPIPE;
            got += (size_t)res;
        }
        return 0;
    }
    /* buffer ring for 5 and 6 */
    enum { NBUF = 16 };
    int err = 0;
    struct io_uring_buf_ring* br =
        io_uring_setup_buf_ring(r, NBUF, BGID, 0, &err);
    if (!br)
        return err ? err : -ENOMEM;
    unsigned char* bufs = malloc((size_t)NBUF * PCH);
    int mask = io_uring_buf_ring_mask(NBUF);
    for (int i = 0; i < NBUF; ++i)
        io_uring_buf_ring_add(
            br, bufs + (size_t)i * PCH, PCH, (unsigned short)i, mask, i
        );
    io_uring_buf_ring_advance(br, NBUF);
    int rc = 0;
    int armed = 0;
    while (got < PN && rc == 0) {
        if (!armed) {
            struct io_uring_sqe* sqe = io_uring_get_sqe(r);
            if (which == 5)
                io_uring_prep_recv(sqe, c->fd, NULL, 0, 0);
            else
                io_uring_prep_recv_multishot(sqe, c->fd, NULL, 0, 0);
            sqe->flags |= IOSQE_BUFFER_SELECT;
            sqe->buf_group = BGID;
            io_uring_submit(r);
            armed = 1;
        }
        struct io_uring_cqe* cqe;
        int w = io_uring_wait_cqe(r, &cqe);
        if (w < 0) {
            rc = w;
            break;
        }
        int res = cqe->res;
        unsigned fl = cqe->flags;
        io_uring_cqe_seen(r, cqe);
        if (res == -ENOBUFS) {
            armed = 0;
            continue;
        }
        if (res < 0) {
            rc = res;
            break;
        }
        if (res == 0) {
            rc = -EPIPE;
            break;
        }
        if (fl & IORING_CQE_F_BUFFER) {
            int bid = (int)(fl >> IORING_CQE_BUFFER_SHIFT);
            size_t n = (size_t)res;
            if (got + n > PN)
                n = PN - got;
            memcpy(out + got, bufs + (size_t)bid * PCH, n);
            got += n;
            io_uring_buf_ring_add(
                br, bufs + (size_t)bid * PCH, PCH, (unsigned short)bid, mask, 0
            );
            io_uring_buf_ring_advance(br, 1);
        } else {
            rc = -EBADMSG;
            break;
        }
        if (!(fl & IORING_CQE_F_MORE))
            armed = 0;
    }
    if (rc == 0 && armed && which == 6) {
        /* multishot still armed: cancel and reap, so the ring can close */
        struct io_uring_sqe* sqe = io_uring_get_sqe(r);
        io_uring_prep_cancel_fd(sqe, c->fd, IORING_ASYNC_CANCEL_ALL);
        io_uring_submit(r);
        struct io_uring_cqe* cqe;
        int guard = 0;
        while (guard++ < 8 && io_uring_peek_cqe(r, &cqe) == 0)
            io_uring_cqe_seen(r, cqe);
    }
    free(bufs);
    return rc;
}

static void probe_client(void) {
    SSL_CTX* x = C.mode == M_PLAIN ? NULL : mk_ctx(0, 0);
    for (size_t t = 0; t < NPROBE; ++t) {
        int fd = connect_fd();
        SSL* ssl = x ? handshake(fd, x, 0, NULL) : NULL;
        struct conn c;
        conn_setup(&c, fd, ssl);
        unsigned char* data = aligned_alloc(4096, PN);
        unsigned char* out = aligned_alloc(4096, PN);
        for (size_t i = 0; i < PN; ++i)
            data[i] = pat(i);
        memset(out, 0, PN);
        int rc;
        int is_recv_test = (t == 5 || t == 6 || t == 7);
        if (is_recv_test) {
            rc = raw_send_all(&c, data, PN);
            if (rc == 0)
                rc = probe_recv(&c, (int)t, out);
        } else {
            rc = probe_send(&c, (int)t, data);
            size_t got = 0;
            while (rc == 0 && got < PN) {
                int r = uring_recv1(&c, out + got, PN - got);
                if (r <= 0) {
                    rc = r < 0 ? r : -EPIPE;
                    break;
                }
                got += (size_t)r;
            }
        }
        const char* verdict;
        char buf[64];
        if (rc != 0) {
            snprintf(buf, sizeof buf, "FAIL(%s)", strerror(-rc));
            verdict = buf;
        } else if (memcmp(data, out, PN) != 0) {
            verdict = "FAIL(data mismatch)";
        } else {
            verdict = "ok";
        }
        printf(
            "PROBE mode=%s op=%s result=%s\n", C.mode_name, probe_names[t],
            verdict
        );
        fflush(stdout);
        free(data);
        free(out);
        conn_close(&c);
    }
}

/* ---- main --------------------------------------------------------------- */

static int parse_mode(const char* m) {
    if (!strcmp(m, "plain"))
        return M_PLAIN;
    if (!strcmp(m, "ktls"))
        return M_KTLS;
    if (!strcmp(m, "ubio"))
        return M_UBIO;
    if (!strcmp(m, "ufd"))
        return M_UFD;
    fprintf(stderr, "bad mode %s\n", m);
    exit(1);
}

int main(int argc, char** argv) {
    signal(SIGPIPE, SIG_IGN);
    if (argc < 2) {
        fprintf(stderr, "usage: bench server|client [--key value]...\n");
        return 1;
    }
    C.server = !strcmp(argv[1], "server");
    for (int i = 2; i + 1 < argc; i += 2) {
        const char *k = argv[i], *v = argv[i + 1];
        if (!strcmp(k, "--mode"))
            C.mode_name = v;
        else if (!strcmp(k, "--work"))
            C.work = v;
        else if (!strcmp(k, "--hs"))
            C.hs = v;
        else if (!strcmp(k, "--cipher"))
            C.cipher = v;
        else if (!strcmp(k, "--certs"))
            C.certdir = v;
        else if (!strcmp(k, "--port"))
            C.port = atoi(v);
        else if (!strcmp(k, "--cpu"))
            C.cpu = atoi(v);
        else if (!strcmp(k, "--qd"))
            C.qd = atoi(v);
        else if (!strcmp(k, "--conns"))
            C.conns = atoi(v);
        else if (!strcmp(k, "--secs"))
            C.secs = atof(v);
        else if (!strcmp(k, "--size"))
            C.size = (size_t)atol(v);
        else if (!strcmp(k, "--req"))
            C.req = (size_t)atol(v);
        else if (!strcmp(k, "--resp"))
            C.resp = (size_t)atol(v);
        else {
            fprintf(stderr, "bad option %s\n", k);
            return 1;
        }
    }
    C.mode = parse_mode(C.mode_name);
    if (C.cpu >= 0) {
        cpu_set_t set;
        CPU_ZERO(&set);
        CPU_SET(C.cpu, &set);
        sched_setaffinity(0, sizeof set, &set);
    }
    const char* w = C.work;
    if (!strcmp(w, "hs")) {
        if (C.server)
            hs_server();
        else
            hs_client();
        return 0;
    }
    if (!strcmp(w, "echo") || !strcmp(w, "probe")) {
        if (C.server)
            echo_server();
        else
            probe_client();
        return 0;
    }
    /* data workloads: one connection */
    SSL_CTX* x = NULL;
    int fd, srv_lfd = -1;
    SSL* ssl = NULL;
    if (C.mode != M_PLAIN)
        x = mk_ctx(C.server, 0);
    if (C.server) {
        srv_lfd = listen_fd();
        fd = tune(accept(srv_lfd, NULL, NULL));
        if (fd < 0)
            die("accept");
    } else {
        fd = connect_fd();
    }
    if (x)
        ssl = handshake(fd, x, C.server, NULL);
    struct conn c;
    conn_setup(&c, fd, ssl);
    if (!strcmp(w, "up")) {
        if (C.server)
            stream_receiver(&c, 0, "SERVER");
        else
            stream_sender(&c, 1, "CLIENT");
    } else if (!strcmp(w, "down")) {
        if (C.server)
            stream_sender(&c, 0, "SERVER");
        else
            stream_receiver(&c, 1, "CLIENT");
    } else if (!strcmp(w, "rr")) {
        if (C.server)
            rr_server(&c);
        else
            rr_client(&c);
    } else {
        fprintf(stderr, "bad work %s\n", w);
        return 1;
    }
    conn_close(&c);
    return 0;
}
