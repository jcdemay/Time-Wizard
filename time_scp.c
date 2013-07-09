/*
 * Copyright (c) 2013 Jonathan-Christofer Demay (jcdemay@gmail.com)
 *
 * Do whatever the fuck you want with this code. I can't stop you anyway.
 * You can use it, copy it, modify it, distribute it, and/or sell it.
 * No conditions. No strings attached. Just don't blame me.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 */

#define _GNU_SOURCE

#include <linux/seccomp.h>
#include <linux/filter.h>
#include <linux/audit.h>
#include <linux/stat.h>

#include <sys/prctl.h>
#include <sys/syscall.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/uio.h>
#include <sys/wait.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <poll.h>

#include <asm/unistd.h>

#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <limits.h>
#include <signal.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#ifndef __linux__
#error "Linux only."
#endif

#ifndef __x86_64__
#error "This implementation targets x86_64."
#endif

/* Wrap defines as compound literals so they can be passed as function arguments. */
#define SF_STMT(code, k) ((struct sock_filter)BPF_STMT((code), (k)))
#define SF_JUMP(code, k, jt, jf) ((struct sock_filter)BPF_JUMP((code), (k), (jt), (jf)))

#ifndef SECCOMP_GET_NOTIF_SIZES
#define SECCOMP_GET_NOTIF_SIZES 3
#endif

/* -------------------- config -------------------- */

typedef enum { MODE_PASS=0, MODE_STATIC, MODE_OFFSET, MODE_FREEZE } Mode;

static Mode   g_mode          = MODE_PASS;
static bool   g_timecl_enable = true;
static bool   g_filets_enable = false;
static bool   g_clamp_enable  = false;
static bool   g_clamp_nsec    = false;
static bool   g_all_clocks    = false;
static bool   g_debug         = false;

static int64_t g_static_epoch = 0;
static int64_t g_offset_epoch = 0;

static bool    g_freeze_init  = false;
static int64_t g_frozen_epoch = 0;

static FILE* g_logf = NULL;

static void vlog(const char* fmt, ...) {
    if (!g_debug || !g_logf) return;
    va_list ap;
    va_start(ap, fmt);
    vfprintf(g_logf, fmt, ap);
    va_end(ap);
    fflush(g_logf);
}

static void die(const char* what) {
    perror(what);
    exit(1);
}

static const char* mode_name(Mode m) {
    switch (m) {
        case MODE_STATIC: return "static";
        case MODE_OFFSET: return "offset";
        case MODE_FREEZE: return "freeze";
        default:          return "pass";
    }
}

static Mode parse_mode(const char* s) {
    if (!s) return MODE_PASS;
    if (strcmp(s, "static") == 0) return MODE_STATIC;
    if (strcmp(s, "offset") == 0) return MODE_OFFSET;
    if (strcmp(s, "freeze") == 0) return MODE_FREEZE;
    return MODE_PASS;
}

/* -------------------- host now via raw syscalls -------------------- */

static bool host_now_timespec(struct timespec* out) {
    if (!out) return false;

#ifdef SYS_clock_gettime
    if (syscall(SYS_clock_gettime, CLOCK_REALTIME, out) == 0) return true;
#endif
#ifdef SYS_gettimeofday
    {
        struct timeval tv;
        if (syscall(SYS_gettimeofday, &tv, NULL) == 0) {
            out->tv_sec = tv.tv_sec;
            out->tv_nsec = (long)tv.tv_usec * 1000L;
            return true;
        }
    }
#endif
#ifdef SYS_time
    {
        long t = syscall(SYS_time, NULL);
        if (t >= 0) {
            out->tv_sec = (time_t)t;
            out->tv_nsec = 0;
            return true;
        }
    }
#endif
    return false;
}

static int64_t ensure_freeze_init_from_host(void) {
    if (g_mode != MODE_FREEZE) return 0;
    if (!g_freeze_init) {
        struct timespec ts;
        if (host_now_timespec(&ts)) g_frozen_epoch = (int64_t)ts.tv_sec;
        else g_frozen_epoch = 0;
        g_freeze_init = true;
    }
    return g_frozen_epoch;
}

static int64_t choose_epoch_time(int64_t real_epoch) {
    if (g_mode == MODE_STATIC) return g_static_epoch;
    if (g_mode == MODE_OFFSET) return real_epoch + g_offset_epoch;
    if (g_mode == MODE_FREEZE) {
        if (!g_freeze_init) { g_frozen_epoch = real_epoch; g_freeze_init = true; }
        return g_frozen_epoch;
    }
    return real_epoch;
}

static int64_t choose_epoch_file(int64_t real_epoch) {
    if (g_mode == MODE_STATIC) return g_static_epoch;
    if (g_mode == MODE_OFFSET) return real_epoch + g_offset_epoch;
    if (g_mode == MODE_FREEZE) { ensure_freeze_init_from_host(); return g_frozen_epoch; }
    return real_epoch;
}

static bool should_force_clock(int64_t clk_id) {
    if (g_all_clocks) return true;
    return (clk_id == CLOCK_REALTIME)
#ifdef CLOCK_REALTIME_COARSE
        || (clk_id == CLOCK_REALTIME_COARSE)
#endif
#ifdef CLOCK_TAI
        || (clk_id == CLOCK_TAI)
#endif
        ;
}

typedef struct { int64_t sec; int64_t nsec; } NowSpec;

static NowSpec forced_now_spec(void) {
    if (g_mode == MODE_STATIC) return (NowSpec){ g_static_epoch, 0 };
    if (g_mode == MODE_FREEZE) return (NowSpec){ ensure_freeze_init_from_host(), 0 };

    struct timespec host;
    if (!host_now_timespec(&host)) return (NowSpec){ 0, 0 };

    if (g_mode == MODE_PASS) return (NowSpec){ (int64_t)host.tv_sec, (int64_t)host.tv_nsec };

    int64_t mapped = choose_epoch_time((int64_t)host.tv_sec);
    return (NowSpec){ mapped, (int64_t)host.tv_nsec };
}

static void clamp_secnsec(int64_t* sec, int64_t* nsec, const NowSpec* now) {
    if (!g_clamp_enable || !sec || !nsec || !now) return;

    if (!g_clamp_nsec) {
        if (*sec > now->sec) { *sec = now->sec; *nsec = now->nsec; }
        return;
    }
    if (*sec > now->sec || (*sec == now->sec && *nsec > now->nsec)) {
        *sec = now->sec;
        *nsec = now->nsec;
    }
}

/* -------------------- process_vm_{readv,writev} helpers -------------------- */

static bool read_mem(pid_t pid, uintptr_t addr, void* buf, size_t len) {
    if (len == 0) return true;
    struct iovec local = { .iov_base = buf, .iov_len = len };
    struct iovec remote = { .iov_base = (void*)addr, .iov_len = len };
    ssize_t n = process_vm_readv(pid, &local, 1, &remote, 1, 0);
    return (n == (ssize_t)len);
}

static bool write_mem(pid_t pid, uintptr_t addr, const void* buf, size_t len) {
    if (len == 0) return true;
    struct iovec local = { .iov_base = (void*)buf, .iov_len = len };
    struct iovec remote = { .iov_base = (void*)addr, .iov_len = len };
    ssize_t n = process_vm_writev(pid, &local, 1, &remote, 1, 0);
    return (n == (ssize_t)len);
}

static bool read_cstring(pid_t pid, uintptr_t addr, char* out, size_t out_sz) {
    if (!out || out_sz == 0) return false;
    out[0] = '\0';
    if (addr == 0) return false;

    size_t off = 0;
    while (off + 1 < out_sz) {
        char chunk[256];
        size_t want = sizeof(chunk);
        if (off + want >= out_sz) want = out_sz - off - 1;

        if (!read_mem(pid, addr + off, chunk, want)) return false;

        for (size_t i = 0; i < want; i++) {
            out[off + i] = chunk[i];
            if (chunk[i] == '\0') return true;
        }
        off += want;
    }
    out[out_sz - 1] = '\0';
    return true;
}

/* -------------------- pidfd helpers (dup tracee fds) -------------------- */

static int sys_pidfd_open(pid_t pid, unsigned int flags) {
#ifdef SYS_pidfd_open
    return (int)syscall(SYS_pidfd_open, pid, flags);
#else
    errno = ENOSYS;
    return -1;
#endif
}
static int sys_pidfd_getfd(int pidfd, int targetfd, unsigned int flags) {
#ifdef SYS_pidfd_getfd
    return (int)syscall(SYS_pidfd_getfd, pidfd, targetfd, flags);
#else
    errno = ENOSYS;
    return -1;
#endif
}

static int dup_tracee_fd(pid_t pid, int tracee_fd) {
    // try pidfd_getfd first
    int pidfd = sys_pidfd_open(pid, 0);
    if (pidfd >= 0) {
        int dupfd = sys_pidfd_getfd(pidfd, tracee_fd, 0);
        close(pidfd);
        if (dupfd >= 0) return dupfd;
    }

    // fallback: open /proc/<pid>/fd/<n> (best-effort)
    char p[128];
    snprintf(p, sizeof(p), "/proc/%d/fd/%d", pid, tracee_fd);
    int fd = open(p, O_PATH | O_CLOEXEC);
    if (fd >= 0) return fd;

    return -1;
}

static int open_tracee_cwd(pid_t pid) {
    char p[128];
    snprintf(p, sizeof(p), "/proc/%d/cwd", pid);
    return open(p, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
}

static bool is_abs_path(const char* s) {
    return s && s[0] == '/';
}

/* -------------------- patching of stat/statx in local buffers -------------------- */

static void patch_stat_local(struct stat* st, const NowSpec* now) {
    if (!st || !now || g_mode == MODE_PASS) return;

    struct timespec* tss[3] = { &st->st_atim, &st->st_mtim, &st->st_ctim };
    for (int i = 0; i < 3; i++) {
        int64_t sec  = choose_epoch_file((int64_t)tss[i]->tv_sec);
        int64_t nsec = (int64_t)tss[i]->tv_nsec;

        if (g_mode == MODE_STATIC || g_mode == MODE_FREEZE) nsec = 0;
        clamp_secnsec(&sec, &nsec, now);

        tss[i]->tv_sec  = (time_t)sec;
        tss[i]->tv_nsec = (long)nsec;
    }
}

static void patch_statx_local(struct statx* sx, uint32_t requested_mask, const NowSpec* now) {
    if (!sx || !now || g_mode == MODE_PASS) return;

    uint32_t patch_mask = sx->stx_mask & requested_mask;

    // helper macro for timestamps
#define ADJ_TS(field, bit) do { \
    if (patch_mask & (bit)) { \
        int64_t sec  = choose_epoch_file((int64_t)sx->field.tv_sec); \
        int64_t nsec = (int64_t)sx->field.tv_nsec; \
        if (g_mode == MODE_STATIC || g_mode == MODE_FREEZE) nsec = 0; \
        clamp_secnsec(&sec, &nsec, now); \
        sx->field.tv_sec  = (int64_t)sec; \
        sx->field.tv_nsec = (uint32_t)nsec; \
    } \
} while (0)

    ADJ_TS(stx_atime, STATX_ATIME);
    ADJ_TS(stx_mtime, STATX_MTIME);
    ADJ_TS(stx_ctime, STATX_CTIME);
#ifdef STATX_BTIME
    ADJ_TS(stx_btime, STATX_BTIME);
#endif
#undef ADJ_TS
}

/* -------------------- send/recv fd over unix socket -------------------- */

static void send_fd_with_ack(int sock, int fd_to_send) {
    struct msghdr msg = {0};
    char buf[1] = { 'F' };
    struct iovec iov = { .iov_base = buf, .iov_len = sizeof(buf) };
    msg.msg_iov = &iov;
    msg.msg_iovlen = 1;

    char cmsgbuf[CMSG_SPACE(sizeof(int))];
    memset(cmsgbuf, 0, sizeof(cmsgbuf));
    msg.msg_control = cmsgbuf;
    msg.msg_controllen = sizeof(cmsgbuf);

    struct cmsghdr* cmsg = CMSG_FIRSTHDR(&msg);
    cmsg->cmsg_level = SOL_SOCKET;
    cmsg->cmsg_type = SCM_RIGHTS;
    cmsg->cmsg_len = CMSG_LEN(sizeof(int));
    memcpy(CMSG_DATA(cmsg), &fd_to_send, sizeof(int));

    if (sendmsg(sock, &msg, 0) < 0) die("sendmsg(SCM_RIGHTS)");

    // wait for ack
    char ack = 0;
    if (read(sock, &ack, 1) != 1 || ack != 'A') die("ack(read)");
}

static int recv_fd_and_ack(int sock) {
    struct msghdr msg = {0};
    char buf[1] = {0};
    struct iovec iov = { .iov_base = buf, .iov_len = sizeof(buf) };
    msg.msg_iov = &iov;
    msg.msg_iovlen = 1;

    char cmsgbuf[CMSG_SPACE(sizeof(int))];
    memset(cmsgbuf, 0, sizeof(cmsgbuf));
    msg.msg_control = cmsgbuf;
    msg.msg_controllen = sizeof(cmsgbuf);

    if (recvmsg(sock, &msg, 0) < 0) die("recvmsg(SCM_RIGHTS)");
    if (buf[0] != 'F') die("recvmsg(bad tag)");

    int got_fd = -1;
    struct cmsghdr* cmsg = CMSG_FIRSTHDR(&msg);
    if (!cmsg || cmsg->cmsg_type != SCM_RIGHTS) die("recvmsg(no rights)");
    memcpy(&got_fd, CMSG_DATA(cmsg), sizeof(int));
    if (got_fd < 0) die("recvmsg(fd)");

    // send ack
    char ack = 'A';
    if (write(sock, &ack, 1) != 1) die("ack(write)");

    return got_fd;
}

/* -------------------- BPF filter build -------------------- */

static void add_syscall(int* list, size_t* n, size_t max, int nr) {
    if (nr < 0) return;
    for (size_t i = 0; i < *n; i++) if (list[i] == nr) return;
    if (*n < max) list[(*n)++] = nr;
}

static int build_filter_prog(struct sock_fprog* out_prog) {
    int syscalls[32];
    size_t n = 0;

    if (g_timecl_enable && g_mode != MODE_PASS) {
#ifdef __NR_time
        add_syscall(syscalls, &n, 32, __NR_time);
#endif
#ifdef __NR_gettimeofday
        add_syscall(syscalls, &n, 32, __NR_gettimeofday);
#endif
#ifdef __NR_clock_gettime
        add_syscall(syscalls, &n, 32, __NR_clock_gettime);
#endif
#ifdef __NR_clock_gettime64
        add_syscall(syscalls, &n, 32, __NR_clock_gettime64);
#endif
    }

    if (g_filets_enable && g_mode != MODE_PASS) {
#ifdef __NR_newfstatat
        add_syscall(syscalls, &n, 32, __NR_newfstatat);
#endif
#ifdef __NR_fstat
        add_syscall(syscalls, &n, 32, __NR_fstat);
#endif
#ifdef __NR_statx
        add_syscall(syscalls, &n, 32, __NR_statx);
#endif
#ifdef __NR_utimensat
        add_syscall(syscalls, &n, 32, __NR_utimensat);
#endif
    }

    // if nothing to intercept: allow all (but keep a minimal valid filter)
    size_t max_insns = 4 + (n ? (n * 2) : 0) + 1;
    struct sock_filter* insns = calloc(max_insns, sizeof(*insns));
    if (!insns) return -1;

    size_t pc = 0;

    // arch check
    insns[pc++] = SF_STMT(BPF_LD  | BPF_W | BPF_ABS, (uint32_t)offsetof(struct seccomp_data, arch));
    insns[pc++] = SF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, AUDIT_ARCH_X86_64, 1, 0);
    insns[pc++] = SF_STMT(BPF_RET | BPF_K, SECCOMP_RET_KILL_PROCESS);

    // load syscall nr
    insns[pc++] = SF_STMT(BPF_LD  | BPF_W | BPF_ABS, (uint32_t)offsetof(struct seccomp_data, nr));

    for (size_t i = 0; i < n; i++) {
        insns[pc++] = SF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, (uint32_t)syscalls[i], 0, 1);
        insns[pc++] = SF_STMT(BPF_RET | BPF_K, SECCOMP_RET_USER_NOTIF);
    }

    insns[pc++] = SF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW);

    out_prog->len = (unsigned short)pc;
    out_prog->filter = insns;
    return 0;
}

static int install_filter_new_listener(void) {
    struct sock_fprog prog;
    memset(&prog, 0, sizeof(prog));

    if (build_filter_prog(&prog) != 0) die("build_filter_prog");

    if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0) die("PR_SET_NO_NEW_PRIVS");

    int fd = (int)syscall(SYS_seccomp, SECCOMP_SET_MODE_FILTER,
                          SECCOMP_FILTER_FLAG_NEW_LISTENER, &prog);

    // prog.filter allocated; safe to free after install
    free(prog.filter);

    return fd;
}

/* -------------------- syscall emulation handlers -------------------- */

static void resp_err(struct seccomp_notif_resp* resp, uint64_t id, int err) {
    resp->id = id;
    resp->val = 0;
    resp->error = -err;
    resp->flags = 0;
}

static void resp_ok(struct seccomp_notif_resp* resp, uint64_t id, int64_t val) {
    resp->id = id;
    resp->val = val;
    resp->error = 0;
    resp->flags = 0;
}

static void resp_continue(struct seccomp_notif_resp* resp, uint64_t id) {
    resp->id = id;
    resp->val = 0;
    resp->error = 0;
    resp->flags = SECCOMP_USER_NOTIF_FLAG_CONTINUE;
}

static void handle_time_syscalls(pid_t pid, struct seccomp_notif* req, struct seccomp_notif_resp* resp) {
    int nr = req->data.nr;
    uint64_t id = req->id;

#ifdef __NR_time
    if (nr == __NR_time) {
        uintptr_t tloc = (uintptr_t)req->data.args[0];

        struct timespec host;
        if (!host_now_timespec(&host)) { resp_err(resp, id, EIO); return; }

        int64_t chosen = choose_epoch_time((int64_t)host.tv_sec);

        if (tloc) {
            time_t v = (time_t)chosen;
            if (!write_mem(pid, tloc, &v, sizeof(v))) { resp_err(resp, id, EFAULT); return; }
        }
        resp_ok(resp, id, chosen);
        return;
    }
#endif

#ifdef __NR_gettimeofday
    if (nr == __NR_gettimeofday) {
        uintptr_t tvp = (uintptr_t)req->data.args[0];

        struct timespec host;
        if (!host_now_timespec(&host)) { resp_err(resp, id, EIO); return; }

        int64_t chosen = choose_epoch_time((int64_t)host.tv_sec);

        if (tvp) {
            struct timeval tv;
            tv.tv_sec = (time_t)chosen;
            tv.tv_usec = 0;
            if (!write_mem(pid, tvp, &tv, sizeof(tv))) { resp_err(resp, id, EFAULT); return; }
        }
        resp_ok(resp, id, 0);
        return;
    }
#endif

#ifdef __NR_clock_gettime
    if (nr == __NR_clock_gettime) {
        int64_t clk_id = (int64_t)req->data.args[0];
        uintptr_t tsp = (uintptr_t)req->data.args[1];

        if (!should_force_clock(clk_id)) { resp_continue(resp, id); return; }

        NowSpec now = forced_now_spec();
        struct timespec ts;
        ts.tv_sec = (time_t)now.sec;
        ts.tv_nsec = 0;

        if (tsp) {
            if (!write_mem(pid, tsp, &ts, sizeof(ts))) { resp_err(resp, id, EFAULT); return; }
        }
        resp_ok(resp, id, 0);
        return;
    }
#endif

#ifdef __NR_clock_gettime64
    if (nr == __NR_clock_gettime64) {
        int64_t clk_id = (int64_t)req->data.args[0];
        uintptr_t tsp = (uintptr_t)req->data.args[1];

        if (!should_force_clock(clk_id)) { resp_continue(resp, id); return; }

        NowSpec now = forced_now_spec();
        struct timespec ts;
        ts.tv_sec = (time_t)now.sec;
        ts.tv_nsec = 0;

        if (tsp) {
            if (!write_mem(pid, tsp, &ts, sizeof(ts))) { resp_err(resp, id, EFAULT); return; }
        }
        resp_ok(resp, id, 0);
        return;
    }
#endif

    // default: continue
    resp_continue(resp, id);
}

static void handle_file_syscalls(pid_t pid, struct seccomp_notif* req, struct seccomp_notif_resp* resp) {
    int nr = req->data.nr;
    uint64_t id = req->id;

#ifdef __NR_fstat
    if (nr == __NR_fstat) {
        int fd = (int)req->data.args[0];
        uintptr_t bufp = (uintptr_t)req->data.args[1];
        if (!bufp) { resp_err(resp, id, EFAULT); return; }

        int dupfd = dup_tracee_fd(pid, fd);
        if (dupfd < 0) { resp_err(resp, id, EBADF); return; }

        struct stat st;
        if (fstat(dupfd, &st) != 0) { int e = errno; close(dupfd); resp_err(resp, id, e); return; }
        close(dupfd);

        NowSpec now = forced_now_spec();
        patch_stat_local(&st, &now);

        if (!write_mem(pid, bufp, &st, sizeof(st))) { resp_err(resp, id, EFAULT); return; }
        resp_ok(resp, id, 0);
        return;
    }
#endif

#ifdef __NR_newfstatat
    if (nr == __NR_newfstatat) {
        int dirfd = (int)req->data.args[0];
        uintptr_t pathp = (uintptr_t)req->data.args[1];
        uintptr_t bufp  = (uintptr_t)req->data.args[2];
        int flags = (int)req->data.args[3];

        if (!bufp) { resp_err(resp, id, EFAULT); return; }

        char path[PATH_MAX+1];
        if (!read_cstring(pid, pathp, path, sizeof(path))) { resp_err(resp, id, EFAULT); return; }

        int call_dirfd = AT_FDCWD;
        int tmpfd = -1;

        if (dirfd == AT_FDCWD) {
            if (!is_abs_path(path) && path[0] != '\0') {
                tmpfd = open_tracee_cwd(pid);
                if (tmpfd < 0) { resp_err(resp, id, errno); return; }
                call_dirfd = tmpfd;
            }
        } else {
            tmpfd = dup_tracee_fd(pid, dirfd);
            if (tmpfd < 0) { resp_err(resp, id, EBADF); return; }
            call_dirfd = tmpfd;
        }

        struct stat st;
        long rc = syscall(__NR_newfstatat, call_dirfd, path, &st, flags);
        int saved = errno;

        if (tmpfd >= 0) close(tmpfd);

        if (rc != 0) { resp_err(resp, id, saved); return; }

        NowSpec now = forced_now_spec();
        patch_stat_local(&st, &now);

        if (!write_mem(pid, bufp, &st, sizeof(st))) { resp_err(resp, id, EFAULT); return; }
        resp_ok(resp, id, 0);
        return;
    }
#endif

#ifdef __NR_statx
    if (nr == __NR_statx) {
        int dirfd = (int)req->data.args[0];
        uintptr_t pathp = (uintptr_t)req->data.args[1];
        int flags = (int)req->data.args[2];
        unsigned int mask = (unsigned int)req->data.args[3];
        uintptr_t bufp = (uintptr_t)req->data.args[4];

        if (!bufp) { resp_err(resp, id, EFAULT); return; }

        char path[PATH_MAX+1];
        if (!read_cstring(pid, pathp, path, sizeof(path))) { resp_err(resp, id, EFAULT); return; }

        int call_dirfd = AT_FDCWD;
        int tmpfd = -1;

        if (dirfd == AT_FDCWD) {
            if (!is_abs_path(path) && path[0] != '\0') {
                tmpfd = open_tracee_cwd(pid);
                if (tmpfd < 0) { resp_err(resp, id, errno); return; }
                call_dirfd = tmpfd;
            }
        } else {
            tmpfd = dup_tracee_fd(pid, dirfd);
            if (tmpfd < 0) { resp_err(resp, id, EBADF); return; }
            call_dirfd = tmpfd;
        }

        struct statx sx;
        memset(&sx, 0, sizeof(sx));

        long rc = syscall(__NR_statx, call_dirfd, path, flags, mask, &sx);
        int saved = errno;

        if (tmpfd >= 0) close(tmpfd);

        if (rc != 0) { resp_err(resp, id, saved); return; }

        NowSpec now = forced_now_spec();
        patch_statx_local(&sx, mask, &now);

        if (!write_mem(pid, bufp, &sx, sizeof(sx))) { resp_err(resp, id, EFAULT); return; }
        resp_ok(resp, id, 0);
        return;
    }
#endif

#ifdef __NR_utimensat
    if (nr == __NR_utimensat) {
        int dirfd = (int)req->data.args[0];
        uintptr_t pathp = (uintptr_t)req->data.args[1];
        uintptr_t timesp = (uintptr_t)req->data.args[2]; // const struct timespec[2] or NULL
        int flags = (int)req->data.args[3];

        char path[PATH_MAX+1];
        if (pathp != 0) {
            if (!read_cstring(pid, pathp, path, sizeof(path))) { resp_err(resp, id, EFAULT); return; }
        } else {
            // some uses with AT_EMPTY_PATH can pass NULL? best-effort
            path[0] = '\0';
        }

        int call_dirfd = AT_FDCWD;
        int tmpfd = -1;

        // need a real dirfd in case of relative path or AT_EMPTY_PATH.
        if (dirfd == AT_FDCWD) {
            if ((!is_abs_path(path) && path[0] != '\0') || (flags & AT_EMPTY_PATH)) {
                tmpfd = open_tracee_cwd(pid);
                if (tmpfd < 0) { resp_err(resp, id, errno); return; }
                call_dirfd = tmpfd;
            }
        } else {
            tmpfd = dup_tracee_fd(pid, dirfd);
            if (tmpfd < 0) { resp_err(resp, id, EBADF); return; }
            call_dirfd = tmpfd;
        }

        struct timespec in[2];
        struct timespec out[2];
        NowSpec now = forced_now_spec();

        if (timesp == 0) {
            // times==NULL => use "now" for both
            in[0].tv_sec = (time_t)now.sec; in[0].tv_nsec = (long)now.nsec;
            in[1].tv_sec = (time_t)now.sec; in[1].tv_nsec = (long)now.nsec;
        } else {
            if (!read_mem(pid, timesp, in, sizeof(in))) { if (tmpfd>=0) close(tmpfd); resp_err(resp, id, EFAULT); return; }
        }

        for (int i = 0; i < 2; i++) {
            int64_t sec  = (int64_t)in[i].tv_sec;
            int64_t nsec = (int64_t)in[i].tv_nsec;

#ifdef UTIME_NOW
            if (in[i].tv_nsec == UTIME_NOW) {
                sec = now.sec;
                nsec = now.nsec;
                if (g_mode == MODE_OFFSET) sec -= g_offset_epoch;
                else sec = choose_epoch_file(sec);
                if (g_mode == MODE_STATIC || g_mode == MODE_FREEZE) nsec = 0;
                out[i].tv_sec = (time_t)sec;
                out[i].tv_nsec = (long)nsec;
                continue;
            }
            if (in[i].tv_nsec == UTIME_OMIT) {
                out[i] = in[i];
                continue;
            }
#endif

            if (g_mode == MODE_OFFSET) {
                // view -> disk
                sec -= g_offset_epoch;
            } else {
                sec = choose_epoch_file(sec);
            }

            if (g_mode == MODE_STATIC || g_mode == MODE_FREEZE) nsec = 0;

            NowSpec clamp_now = now;
            if (g_mode == MODE_OFFSET) clamp_now.sec -= g_offset_epoch;

            clamp_secnsec(&sec, &nsec, &clamp_now);

            out[i].tv_sec = (time_t)sec;
            out[i].tv_nsec = (long)nsec;
        }

        long rc = syscall(__NR_utimensat, call_dirfd, path, (timesp ? out : out), flags);
        int saved = errno;

        if (tmpfd >= 0) close(tmpfd);

        if (rc != 0) { resp_err(resp, id, saved); return; }
        resp_ok(resp, id, 0);
        return;
    }
#endif

    resp_continue(resp, id);
}

/* -------------------- command line interface -------------------- */

static void usage(const char* argv0) {
    fprintf(stderr,
        "Usage:\n"
        "  %s [opts] -- <command> [args...]\n"
        "Opts:\n"
        "  -mode pass|static|offset|freeze\n"
        "  -epoch <int64>          (static epoch OR offset seconds)\n"
        "  -timecl 0|1\n"
        "  -filets 0|1\n"
        "  -clamp 0|1\n"
        "  -clampnsec 0|1\n"
        "  -allclocks 0|1\n"
        "  -debug 0|1\n"
        "  -log <path>             (default: stderr)\n",
        argv0
    );
    exit(2);
}

int main(int argc, char** argv) {
    g_logf = stderr;

    char** cmd = NULL;
    int cmd_argc = 0;

    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--") == 0) {
            cmd = &argv[i + 1];
            cmd_argc = argc - (i + 1);
            break;
        }
        if (strcmp(argv[i], "-mode") == 0) {
            if (++i >= argc) usage(argv[0]);
            g_mode = parse_mode(argv[i]);
            continue;
        }
        if (strcmp(argv[i], "-epoch") == 0) {
            if (++i >= argc) usage(argv[0]);
            int64_t v = (int64_t)strtoll(argv[i], NULL, 10);
            if (g_mode == MODE_OFFSET) g_offset_epoch = v;
            else g_static_epoch = v;
            continue;
        }
        if (strcmp(argv[i], "-timecl") == 0) {
            if (++i >= argc) usage(argv[0]);
            g_timecl_enable = (atoi(argv[i]) != 0);
            continue;
        }
        if (strcmp(argv[i], "-filets") == 0) {
            if (++i >= argc) usage(argv[0]);
            g_filets_enable = (atoi(argv[i]) != 0);
            continue;
        }
        if (strcmp(argv[i], "-clamp") == 0) {
            if (++i >= argc) usage(argv[0]);
            g_clamp_enable = (atoi(argv[i]) != 0);
            continue;
        }
        if (strcmp(argv[i], "-clampnsec") == 0) {
            if (++i >= argc) usage(argv[0]);
            g_clamp_nsec = (atoi(argv[i]) != 0);
            continue;
        }
        if (strcmp(argv[i], "-allclocks") == 0) {
            if (++i >= argc) usage(argv[0]);
            g_all_clocks = (atoi(argv[i]) != 0);
            continue;
        }
        if (strcmp(argv[i], "-debug") == 0) {
            if (++i >= argc) usage(argv[0]);
            g_debug = (atoi(argv[i]) != 0);
            continue;
        }
        if (strcmp(argv[i], "-log") == 0) {
            if (++i >= argc) usage(argv[0]);
            FILE* f = fopen(argv[i], "a");
            if (f) g_logf = f;
            else g_logf = stderr;
            continue;
        }
        usage(argv[0]);
    }

    if (!cmd || cmd_argc <= 0) usage(argv[0]);

    vlog("[seccomp] mode=%s static=%" PRId64 " offset=%" PRId64 " timecl=%d filets=%d clamp=%d clampnsec=%d allclocks=%d\n",
         mode_name(g_mode), g_static_epoch, g_offset_epoch,
         g_timecl_enable, g_filets_enable, g_clamp_enable, g_clamp_nsec, g_all_clocks);

    int sp[2];
    if (socketpair(AF_UNIX, SOCK_SEQPACKET, 0, sp) != 0) die("socketpair");

    pid_t child = fork();
    if (child < 0) die("fork");

    if (child == 0) {
        // child: install filter, send listener fd, wait for ack, then exec
        close(sp[0]);

        int listener_fd = install_filter_new_listener();
        if (listener_fd < 0) die("seccomp(NEW_LISTENER)");

        // pass the listener fd to parent, then wait for ack before exec (avoids ENOSYS race).
        send_fd_with_ack(sp[1], listener_fd);
        close(listener_fd);
        close(sp[1]);

        execvp(cmd[0], cmd);
        _exit(127);
    }

    // parent: receive listener fd and run server loop
    close(sp[1]);
    int listener_fd = recv_fd_and_ack(sp[0]);
    close(sp[0]);

    // non-blocking + poll
    int fl = fcntl(listener_fd, F_GETFL, 0);
    fcntl(listener_fd, F_SETFL, fl | O_NONBLOCK);

    // determine kernel notif sizes (best-effort)
    struct seccomp_notif_sizes sizes;
    memset(&sizes, 0, sizeof(sizes));
    if (syscall(SYS_seccomp, SECCOMP_GET_NOTIF_SIZES, 0, &sizes) != 0) {
        // not fatal: fallback to local sizes
        vlog("[seccomp] SECCOMP_GET_NOTIF_SIZES failed: %s\n", strerror(errno));
        sizes.seccomp_notif = (uint16_t)sizeof(struct seccomp_notif);
        sizes.seccomp_notif_resp = (uint16_t)sizeof(struct seccomp_notif_resp);
    }

    size_t req_sz  = sizes.seccomp_notif  > sizeof(struct seccomp_notif) ? sizes.seccomp_notif  : sizeof(struct seccomp_notif);
    size_t resp_sz = sizes.seccomp_notif_resp > sizeof(struct seccomp_notif_resp) ? sizes.seccomp_notif_resp : sizeof(struct seccomp_notif_resp);

    struct seccomp_notif* req = calloc(1, req_sz);
    struct seccomp_notif_resp* resp = calloc(1, resp_sz);
    if (!req || !resp) die("calloc(notif)");

    bool child_exited = false;
    int child_status = 0;

    for (;;) {
        // check child exit
        if (!child_exited) {
            pid_t w = waitpid(child, &child_status, WNOHANG);
            if (w == child) child_exited = true;
        }

        struct pollfd pfd = { .fd = listener_fd, .events = POLLIN };
        int pr = poll(&pfd, 1, child_exited ? 0 : 200);

        if (pr < 0) {
            if (errno == EINTR) continue;
            break;
        }

        if (pr == 0) {
            if (child_exited) break;
            continue;
        }

        if (!(pfd.revents & POLLIN)) {
            if (child_exited) break;
            continue;
        }

        memset(req, 0, req_sz);
        if (ioctl(listener_fd, SECCOMP_IOCTL_NOTIF_RECV, req) != 0) {
            if (errno == EINTR) continue;
            if (errno == EAGAIN) continue;
            // If the listener is gone / child gone, exit
            if (child_exited) break;
            vlog("[seccomp] NOTIF_RECV failed: %s\n", strerror(errno));
            continue;
        }

        // validate ID (race-safe)
        if (ioctl(listener_fd, SECCOMP_IOCTL_NOTIF_ID_VALID, &req->id) != 0) {
            // request no longer valid
            continue;
        }

        memset(resp, 0, resp_sz);

        pid_t pid = (pid_t)req->pid;

        // dispatch (time first, then file)
        if (g_timecl_enable && g_mode != MODE_PASS) {
            handle_time_syscalls(pid, req, resp);
        } else {
            resp_continue(resp, req->id);
        }

        if (g_filets_enable && g_mode != MODE_PASS) {
            // only override if handler chose CONTINUE (or for file syscalls)
            // dispatch file handler on file syscalls by checking nr family:
            int nr = req->data.nr;
#ifdef __NR_newfstatat
            if (nr == __NR_newfstatat)
                handle_file_syscalls(pid, req, resp);
#endif
#ifdef __NR_fstat
            if (nr == __NR_fstat)
                handle_file_syscalls(pid, req, resp);
#endif
#ifdef __NR_statx
            if (nr == __NR_statx)
                handle_file_syscalls(pid, req, resp);
#endif
#ifdef __NR_utimensat
            if (nr == __NR_utimensat)
                handle_file_syscalls(pid, req, resp);
#endif
        }

        if (ioctl(listener_fd, SECCOMP_IOCTL_NOTIF_SEND, resp) != 0) {
            // if reply failed, the tracee syscall will also fail; log and continue.
            vlog("[seccomp] NOTIF_SEND failed: %s\n", strerror(errno));
        }
    }

    close(listener_fd);
    free(req);
    free(resp);

    // propagate child's exit code if possible
    if (!child_exited) waitpid(child, &child_status, 0);

    if (WIFEXITED(child_status)) return WEXITSTATUS(child_status);
    if (WIFSIGNALED(child_status)) return 128 + WTERMSIG(child_status);
    return 0;
}
