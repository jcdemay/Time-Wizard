/*
 * Copyright (c) 2005 Jonathan-Christofer Demay (jcdemay@gmail.com)
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

#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/user.h>
#include <sys/uio.h>
#include <sys/syscall.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/auxv.h>
#include <signal.h>
#include <errno.h>
#include <unistd.h>
#include <fcntl.h>

#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <cstdio>
#include <cstdarg>
#include <ctime>
#include <time.h>
#include <string>
#include <unordered_map>
#include <vector>
#include <algorithm>

#ifndef __linux__
#error "This tool is Linux-only."
#endif

#ifndef __x86_64__
#error "This implementation currently targets x86_64 syscall ABI (orig_rax, rdi/rsi/rdx/r10/r8/r9)."
#endif

/* -------------------- statx fallback (only if <linux/stat.h> missing) -------------------- */

#ifdef __linux__
#  include <linux/stat.h>
#endif

#ifndef STATX_BASIC_STATS
#ifndef STATX_ATIME
#define STATX_TYPE        0x00000001U
#define STATX_MODE        0x00000002U
#define STATX_NLINK       0x00000004U
#define STATX_UID         0x00000008U
#define STATX_GID         0x00000010U
#define STATX_ATIME       0x00000020U
#define STATX_MTIME       0x00000040U
#define STATX_CTIME       0x00000080U
#define STATX_INO         0x00000100U
#define STATX_SIZE        0x00000200U
#define STATX_BLOCKS      0x00000400U
#define STATX_BTIME       0x00000800U
#define STATX_BASIC_STATS 0x000007ffU
#endif

struct statx_timestamp {
    int64_t  tv_sec;
    uint32_t tv_nsec;
    int32_t  __reserved;
};

struct statx {
    uint32_t stx_mask;
    uint32_t stx_blksize;
    uint64_t stx_attributes;
    uint32_t stx_nlink;
    uint32_t stx_uid;
    uint32_t stx_gid;
    uint16_t stx_mode;
    uint16_t __spare0[1];
    uint64_t stx_ino;
    uint64_t stx_size;
    uint64_t stx_blocks;
    uint64_t stx_attributes_mask;
    struct statx_timestamp stx_atime;
    struct statx_timestamp stx_btime;
    struct statx_timestamp stx_ctime;
    struct statx_timestamp stx_mtime;
    uint32_t stx_rdev_major;
    uint32_t stx_rdev_minor;
    uint32_t stx_dev_major;
    uint32_t stx_dev_minor;
    uint64_t __spare2[14];
};
#endif

/* -------------------- config -------------------- */

enum Mode { MODE_PASS=0, MODE_STATIC, MODE_OFFSET, MODE_FREEZE };

static Mode   g_mode          = MODE_PASS;
static bool   g_timecl_enable = true;
static bool   g_filets_enable = false;
static bool   g_clamp_enable  = false;
static bool   g_clamp_nsec    = false;
static bool   g_all_clocks    = false;
static bool   g_debug         = false;

static bool   g_disable_vdso_by_default = true;
static bool   g_vdso_disabled_runtime   = false;

static int64_t g_static_epoch = 0;
static int64_t g_offset_epoch = 0;

static bool    g_freeze_init  = false;
static int64_t g_frozen_epoch = 0;

static FILE* g_logf = nullptr;

static void vlog(const char* fmt, ...) {
    if (!g_debug || !g_logf) return;
    va_list ap;
    va_start(ap, fmt);
    vfprintf(g_logf, fmt, ap);
    va_end(ap);
    fflush(g_logf);
}

static void die(const char* msg) {
    perror(msg);
    exit(1);
}

static Mode parse_mode(const std::string& s) {
    if (s == "static") return MODE_STATIC;
    if (s == "offset") return MODE_OFFSET;
    if (s == "freeze") return MODE_FREEZE;
    return MODE_PASS;
}

static const char* mode_name(Mode m) {
    switch (m) {
        case MODE_STATIC: return "static";
        case MODE_OFFSET: return "offset";
        case MODE_FREEZE: return "freeze";
        default:          return "pass";
    }
}

/* -------------------- host now via syscalls (no libc time()) -------------------- */

static bool host_now_timespec(struct timespec* out) {
    if (!out) return false;

#ifdef SYS_clock_gettime
    if (syscall(SYS_clock_gettime, CLOCK_REALTIME, out) == 0) return true;
#endif
#ifdef SYS_gettimeofday
    {
        struct timeval tv;
        if (syscall(SYS_gettimeofday, &tv, nullptr) == 0) {
            out->tv_sec  = tv.tv_sec;
            out->tv_nsec = (long)tv.tv_usec * 1000L;
            return true;
        }
    }
#endif
#ifdef SYS_time
    {
        long t = syscall(SYS_time, nullptr);
        if (t >= 0) {
            out->tv_sec = (time_t)t;
            out->tv_nsec = 0;
            return true;
        }
    }
#endif
    return false;
}

static int64_t ensure_freeze_init_from_host() {
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

struct NowSpec { int64_t sec; int64_t nsec; };

static NowSpec forced_now_spec() {
    if (g_mode == MODE_STATIC) return NowSpec{ g_static_epoch, 0 };
    if (g_mode == MODE_FREEZE) return NowSpec{ ensure_freeze_init_from_host(), 0 };

    struct timespec host;
    if (!host_now_timespec(&host)) return NowSpec{0,0};

    if (g_mode == MODE_PASS) return NowSpec{ (int64_t)host.tv_sec, (int64_t)host.tv_nsec };

    int64_t mapped = choose_epoch_time((int64_t)host.tv_sec);
    return NowSpec{ mapped, (int64_t)host.tv_nsec };
}

static inline void clamp_secnsec(int64_t& sec, int64_t& nsec, const NowSpec& now) {
    if (!g_clamp_enable) return;

    if (!g_clamp_nsec) {
        if (sec > now.sec) { sec = now.sec; nsec = now.nsec; }
        return;
    }
    if (sec > now.sec || (sec == now.sec && nsec > now.nsec)) {
        sec = now.sec;
        nsec = now.nsec;
    }
}

/* -------------------- tracee memory IO -------------------- */

static bool read_mem_vm(pid_t pid, uintptr_t addr, void* buf, size_t len) {
    struct iovec local { buf, len };
    struct iovec remote { (void*)addr, len };
    ssize_t n = process_vm_readv(pid, &local, 1, &remote, 1, 0);
    return (n == (ssize_t)len);
}

static bool write_mem_vm(pid_t pid, uintptr_t addr, const void* buf, size_t len) {
    struct iovec local { (void*)buf, len };
    struct iovec remote { (void*)addr, len };
    ssize_t n = process_vm_writev(pid, &local, 1, &remote, 1, 0);
    return (n == (ssize_t)len);
}

static bool read_mem_ptrace(pid_t pid, uintptr_t addr, void* buf, size_t len) {
    size_t off = 0;
    long word;
    errno = 0;
    while (off < len) {
        word = ptrace(PTRACE_PEEKDATA, pid, (void*)(addr + off), nullptr);
        if (word == -1 && errno) return false;
        size_t chunk = std::min(sizeof(long), len - off);
        std::memcpy((char*)buf + off, &word, chunk);
        off += chunk;
    }
    return true;
}

static bool write_mem_ptrace(pid_t pid, uintptr_t addr, const void* buf, size_t len) {
    size_t off = 0;
    while (off < len) {
        long word = 0;
        size_t chunk = std::min(sizeof(long), len - off);

        if (chunk != sizeof(long)) {
            errno = 0;
            long cur = ptrace(PTRACE_PEEKDATA, pid, (void*)(addr + off), nullptr);
            if (cur == -1 && errno) return false;
            std::memcpy(&word, &cur, sizeof(long));
        }

        std::memcpy(&word, (const char*)buf + off, chunk);

        if (ptrace(PTRACE_POKEDATA, pid, (void*)(addr + off), (void*)word) == -1) return false;
        off += chunk;
    }
    return true;
}

static bool read_mem(pid_t pid, uintptr_t addr, void* buf, size_t len) {
    if (len == 0) return true;
    if (read_mem_vm(pid, addr, buf, len)) return true;
    return read_mem_ptrace(pid, addr, buf, len);
}

static bool write_mem(pid_t pid, uintptr_t addr, const void* buf, size_t len) {
    if (len == 0) return true;
    if (write_mem_vm(pid, addr, buf, len)) return true;
    return write_mem_ptrace(pid, addr, buf, len);
}

/* -------------------- vDSO disabling by patching AUXV in tracee -------------------- */

struct AuxvEnt { uint64_t a_type; uint64_t a_val; };

static bool is_mapped_address_looks_like_vdso(uint64_t v) {
    // validation is not needed, setting to 0 is enough.
    // keeping helper for logging.
    return (v != 0);
}

static bool disable_vdso_in_auxv(pid_t tid) {
    // Read regs to locate the initial stack.
    user_regs_struct regs{};
    if (ptrace(PTRACE_GETREGS, tid, nullptr, &regs) == -1) return false;

    uintptr_t sp = (uintptr_t)regs.rsp;

    // Stack layout at entry:
    // argc (u64), argv[], NULL, envp[], NULL, auxv[] (pairs), AT_NULL
    uint64_t argc = 0;
    if (!read_mem(tid, sp, &argc, sizeof(argc))) return false;
    sp += sizeof(uint64_t);

    // skip argv pointers (argc)
    sp += (argc * sizeof(uint64_t));

    // skip argv NULL
    uint64_t tmp = 0;
    if (!read_mem(tid, sp, &tmp, sizeof(tmp))) return false;
    sp += sizeof(uint64_t);

    // skip envp until NULL
    while (true) {
        uint64_t p = 0;
        if (!read_mem(tid, sp, &p, sizeof(p))) return false;
        sp += sizeof(uint64_t);
        if (p == 0) break;
    }

    // now auxv
    bool changed = false;
    uintptr_t aux_base = sp;

    for (int i = 0; i < 8192; i++) {
        AuxvEnt e{};
        if (!read_mem(tid, sp, &e, sizeof(e))) return false;
        if (e.a_type == AT_NULL) break;

        if (e.a_type == AT_SYSINFO_EHDR || e.a_type == AT_SYSINFO) {
            if (is_mapped_address_looks_like_vdso(e.a_val)) {
                AuxvEnt ne = e;
                ne.a_val = 0;
                if (write_mem(tid, sp, &ne, sizeof(ne))) {
                    changed = true;
                    vlog("[ptrace][dbg tid=%d] auxv patched type=%llu val=0 (was=0x%llx) @0x%llx\n",
                         (int)tid,
                         (unsigned long long)e.a_type,
                         (unsigned long long)e.a_val,
                         (unsigned long long)sp);
                }
            }
        }

        sp += sizeof(AuxvEnt);
    }

    if (changed) {
        vlog("[ptrace][dbg tid=%d] vDSO disabled by AUXV patch (auxv_base=0x%llx)\n",
             (int)tid, (unsigned long long)aux_base);
    }
    return changed;
}

/* -------------------- patch engines -------------------- */

static void adjust_stat_buf(pid_t tid, uintptr_t st_ptr, const NowSpec& now) {
    if (!st_ptr || g_mode == MODE_PASS) return;

    struct stat st{};
    if (!read_mem(tid, st_ptr, &st, sizeof(st))) return;

    auto adj_ts = [&](struct timespec& ts) {
        int64_t sec  = choose_epoch_file((int64_t)ts.tv_sec);
        int64_t nsec = (int64_t)ts.tv_nsec;
        if (g_mode == MODE_STATIC || g_mode == MODE_FREEZE) nsec = 0;
        clamp_secnsec(sec, nsec, now);
        ts.tv_sec  = (time_t)sec;
        ts.tv_nsec = (long)nsec;
    };

    adj_ts(st.st_atim);
    adj_ts(st.st_mtim);
    adj_ts(st.st_ctim);

    (void)write_mem(tid, st_ptr, &st, sizeof(st));
}

static void adjust_statx_buf(pid_t tid, uintptr_t stx_ptr, uint32_t requested_mask, const NowSpec& now) {
    if (!stx_ptr || g_mode == MODE_PASS) return;

    struct statx sx{};
    if (!read_mem(tid, stx_ptr, &sx, sizeof(sx))) return;

    // patch only (kernel-filled) & (requested)
    uint32_t patch_mask = sx.stx_mask & requested_mask;

    auto adj = [&](struct statx_timestamp& t) {
        int64_t sec  = choose_epoch_file((int64_t)t.tv_sec);
        int64_t nsec = (int64_t)t.tv_nsec;
        if (g_mode == MODE_STATIC || g_mode == MODE_FREEZE) nsec = 0;
        clamp_secnsec(sec, nsec, now);
        t.tv_sec  = (int64_t)sec;
        t.tv_nsec = (uint32_t)nsec;
    };

    if (patch_mask & STATX_ATIME) adj(sx.stx_atime);
    if (patch_mask & STATX_MTIME) adj(sx.stx_mtime);
    if (patch_mask & STATX_CTIME) adj(sx.stx_ctime);
#ifdef STATX_BTIME
    if (patch_mask & STATX_BTIME) adj(sx.stx_btime);
#endif

    (void)write_mem(tid, stx_ptr, &sx, sizeof(sx));
}

/* -------------------- per-thread state -------------------- */

struct TState {
    bool in_syscall = false;
    long last_sysno = -1;

    uintptr_t pending_stat_ptr = 0;
    uintptr_t pending_statx_ptr = 0;
    uint32_t  pending_statx_mask = 0;
};

static std::unordered_map<pid_t, TState> g_ts;

static inline void clear_pending(TState& st) {
    st.pending_stat_ptr = 0;
    st.pending_statx_ptr = 0;
    st.pending_statx_mask = 0;
}

/* -------------------- syscall numbers helpers -------------------- */

static inline bool is_stat_family(long nr) {
#ifdef __NR_stat
    if (nr == __NR_stat) return true;
#endif
#ifdef __NR_lstat
    if (nr == __NR_lstat) return true;
#endif
#ifdef __NR_fstat
    if (nr == __NR_fstat) return true;
#endif
#ifdef __NR_stat64
    if (nr == __NR_stat64) return true;
#endif
#ifdef __NR_lstat64
    if (nr == __NR_lstat64) return true;
#endif
#ifdef __NR_fstat64
    if (nr == __NR_fstat64) return true;
#endif
    return false;
}

static inline bool is_fstatat_family(long nr) {
#ifdef __NR_newfstatat
    if (nr == __NR_newfstatat) return true;
#endif
#ifdef __NR_fstatat
    if (nr == __NR_fstatat) return true;
#endif
#ifdef __NR_fstatat64
    if (nr == __NR_fstatat64) return true;
#endif
    return false;
}

/* -------------------- utimensat ENTRY rewrite -------------------- */

static bool rewrite_utimensat_entry(pid_t tid, user_regs_struct& r) {
#ifndef __NR_utimensat
    (void)tid; (void)r;
    return false;
#else
    if (!g_filets_enable || g_mode == MODE_PASS) return false;

    uintptr_t times_ptr = (uintptr_t)r.rdx; // arg2
    NowSpec now = forced_now_spec();

    auto write_times_to_addr = [&](uintptr_t dst, const struct timespec ts2[2]) -> bool {
        return write_mem(tid, dst, ts2, sizeof(struct timespec) * 2);
    };

    if (times_ptr == 0) {
        uintptr_t scratch = (uintptr_t)r.rsp - 0x80;
        struct timespec out[2];
        out[0].tv_sec  = (time_t)now.sec;
        out[0].tv_nsec = (long)now.nsec;
        out[1].tv_sec  = (time_t)now.sec;
        out[1].tv_nsec = (long)now.nsec;

        if (g_mode == MODE_OFFSET) {
            out[0].tv_sec = (time_t)((int64_t)out[0].tv_sec - g_offset_epoch);
            out[1].tv_sec = (time_t)((int64_t)out[1].tv_sec - g_offset_epoch);
        }

        if (!write_times_to_addr(scratch, out)) return false;
        r.rdx = (uint64_t)scratch;

        vlog("[ptrace][dbg tid=%d] utimensat ENTRY: times=NULL -> injected @0x%llx\n",
             (int)tid, (unsigned long long)scratch);
        return true;
    }

    struct timespec in[2];
    if (!read_mem(tid, times_ptr, &in, sizeof(in))) return false;

    struct timespec out[2];
    for (int i = 0; i < 2; i++) {
        int64_t sec  = (int64_t)in[i].tv_sec;
        int64_t nsec = (int64_t)in[i].tv_nsec;

#ifdef UTIME_NOW
        if (in[i].tv_nsec == UTIME_NOW) {
            sec  = now.sec;
            nsec = now.nsec;
            if (g_mode == MODE_OFFSET) sec -= g_offset_epoch;
            out[i].tv_sec  = (time_t)sec;
            out[i].tv_nsec = (long)nsec;
            continue;
        }
        if (in[i].tv_nsec == UTIME_OMIT) {
            out[i] = in[i];
            continue;
        }
#endif
        if (g_mode == MODE_OFFSET) {
            sec -= g_offset_epoch; // view -> disk
        } else {
            sec = choose_epoch_file(sec); // static/freeze mapping
        }

        if (g_mode == MODE_STATIC || g_mode == MODE_FREEZE) nsec = 0;

        NowSpec clamp_now = now;
        if (g_mode == MODE_OFFSET) clamp_now.sec -= g_offset_epoch;

        clamp_secnsec(sec, nsec, clamp_now);

        out[i].tv_sec  = (time_t)sec;
        out[i].tv_nsec = (long)nsec;
    }

    if (!write_mem(tid, times_ptr, &out, sizeof(out))) return false;

    vlog("[ptrace][dbg tid=%d] utimensat ENTRY: rewritten in-place @0x%llx\n",
         (int)tid, (unsigned long long)times_ptr);
    return false;
#endif
}

/* -------------------- syscall handlers -------------------- */

static void handle_syscall_entry(pid_t tid, user_regs_struct& r, TState& st) {
    long nr = (long)r.orig_rax;
    st.last_sysno = nr;

    // clear pending each syscall entry
    clear_pending(st);

    // cache pointers for stat/statx
    if (g_filets_enable && g_mode != MODE_PASS) {
        if (is_stat_family(nr)) {
            st.pending_stat_ptr = (uintptr_t)r.rsi;
        } else if (is_fstatat_family(nr)) {
            st.pending_stat_ptr = (uintptr_t)r.rdx;
        }
#ifdef __NR_statx
        else if (nr == __NR_statx) {
            st.pending_statx_mask = (uint32_t)r.r10;
            st.pending_statx_ptr  = (uintptr_t)r.r8;
        }
#endif
    }

#ifdef __NR_utimensat
    if (g_filets_enable && g_mode != MODE_PASS && nr == __NR_utimensat) {
        user_regs_struct newr = r;
        bool changed = rewrite_utimensat_entry(tid, newr);
        if (changed) {
            if (ptrace(PTRACE_SETREGS, tid, nullptr, &newr) == -1) {
                vlog("[ptrace][dbg tid=%d] PTRACE_SETREGS failed for utimensat rewrite\n", (int)tid);
            } else {
                r = newr;
            }
        }
    }
#endif
}

static void handle_syscall_exit(pid_t tid, user_regs_struct& r, TState& st) {
    long nr  = st.last_sysno;
    long ret = (long)r.rax;

    // ---- timecl syscalls ----
#ifdef __NR_time
    if (g_timecl_enable && g_mode != MODE_PASS && nr == __NR_time && ret >= 0) {
        int64_t chosen = choose_epoch_time((int64_t)ret);
        r.rax = (uint64_t)chosen;

        uintptr_t tloc_ptr = (uintptr_t)r.rdi;
        if (tloc_ptr) {
            time_t v = (time_t)chosen;
            (void)write_mem(tid, tloc_ptr, &v, sizeof(v));
        }
        (void)ptrace(PTRACE_SETREGS, tid, nullptr, &r);
        vlog("[ptrace][dbg tid=%d] syscall time forced=%lld\n", (int)tid, (long long)chosen);
    }
#endif

#ifdef __NR_gettimeofday
    if (g_timecl_enable && g_mode != MODE_PASS && nr == __NR_gettimeofday && ret == 0) {
        uintptr_t tv_ptr = (uintptr_t)r.rdi;
        if (tv_ptr) {
            struct timeval tv{};
            if (read_mem(tid, tv_ptr, &tv, sizeof(tv))) {
                int64_t chosen = choose_epoch_time((int64_t)tv.tv_sec);
                tv.tv_sec = (time_t)chosen;
                tv.tv_usec = 0;
                (void)write_mem(tid, tv_ptr, &tv, sizeof(tv));
                vlog("[ptrace][dbg tid=%d] syscall gettimeofday forced=%lld\n", (int)tid, (long long)chosen);
            }
        }
    }
#endif

#ifdef __NR_clock_gettime
    if (g_timecl_enable && g_mode != MODE_PASS && nr == __NR_clock_gettime && ret == 0) {
        int64_t clk_id = (int64_t)r.rdi;
        uintptr_t ts_ptr = (uintptr_t)r.rsi;
        if (ts_ptr && should_force_clock(clk_id)) {
            struct timespec ts{};
            if (read_mem(tid, ts_ptr, &ts, sizeof(ts))) {
                int64_t chosen = choose_epoch_time((int64_t)ts.tv_sec);
                ts.tv_sec = (time_t)chosen;
                ts.tv_nsec = 0;
                (void)write_mem(tid, ts_ptr, &ts, sizeof(ts));
                vlog("[ptrace][dbg tid=%d] syscall clock_gettime forced=%lld\n", (int)tid, (long long)chosen);
            }
        }
    }
#endif

#ifdef __NR_clock_gettime64
    if (g_timecl_enable && g_mode != MODE_PASS && nr == __NR_clock_gettime64 && ret == 0) {
        int64_t clk_id = (int64_t)r.rdi;
        uintptr_t ts_ptr = (uintptr_t)r.rsi;
        if (ts_ptr && should_force_clock(clk_id)) {
            struct timespec ts{};
            if (read_mem(tid, ts_ptr, &ts, sizeof(ts))) {
                int64_t chosen = choose_epoch_time((int64_t)ts.tv_sec);
                ts.tv_sec = (time_t)chosen;
                ts.tv_nsec = 0;
                (void)write_mem(tid, ts_ptr, &ts, sizeof(ts));
                vlog("[ptrace][dbg tid=%d] syscall clock_gettime64 forced=%lld\n", (int)tid, (long long)chosen);
            }
        }
    }
#endif

    // ---- filets patch from cached pointers ----
    if (g_filets_enable && g_mode != MODE_PASS) {
        if (ret == 0) {
            NowSpec now = forced_now_spec();
            if (st.pending_statx_ptr) {
                adjust_statx_buf(tid, st.pending_statx_ptr, st.pending_statx_mask, now);
                vlog("[ptrace][dbg tid=%d] patched statx buf=0x%llx mask=0x%x\n",
                     (int)tid, (unsigned long long)st.pending_statx_ptr, st.pending_statx_mask);
            } else if (st.pending_stat_ptr) {
                adjust_stat_buf(tid, st.pending_stat_ptr, now);
                vlog("[ptrace][dbg tid=%d] patched stat buf=0x%llx\n",
                     (int)tid, (unsigned long long)st.pending_stat_ptr);
            }
        }
        clear_pending(st);
    }
}

/* -------------------- ptrace loop helpers -------------------- */

static void set_ptrace_options(pid_t tid) {
    unsigned long opts =
        PTRACE_O_TRACESYSGOOD |
        PTRACE_O_TRACECLONE |
        PTRACE_O_TRACEFORK  |
        PTRACE_O_TRACEVFORK |
        PTRACE_O_TRACEEXEC;

#ifdef PTRACE_O_EXITKILL
    opts |= PTRACE_O_EXITKILL;
#endif
    if (ptrace(PTRACE_SETOPTIONS, tid, nullptr, (void*)opts) == -1) {
        vlog("[ptrace][dbg] PTRACE_SETOPTIONS failed on %d\n", (int)tid);
    }
}

static void resume_syscall(pid_t tid, int sig = 0) {
    (void)ptrace(PTRACE_SYSCALL, tid, nullptr, (void*)(long)sig);
}

/* -------------------- command line interface -------------------- */

static void usage(const char* argv0) {
    fprintf(stderr,
        "Usage:\n"
        "  %s [opts] -- <command> [args...]\n"
        "  %s --attach <pid> [opts]\n"
        "Opts:\n"
        "  -mode pass|static|offset|freeze\n"
        "  -epoch <int64>          (static epoch OR offset seconds)\n"
        "  -timecl 0|1\n"
        "  -filets 0|1\n"
        "  -clamp 0|1\n"
        "  -clampnsec 0|1\n"
        "  -allclocks 0|1\n"
        "  -debug 0|1\n"
        "  -log <path>             (default: stderr)\n"
        "  -vdso 0|1               (default: 0 => disable vDSO)\n",
        argv0, argv0
    );
    exit(2);
}

static bool parse_bool_arg(const char* s) {
    return (std::atoi(s) != 0);
}

int main(int argc, char** argv) {
    g_logf = stderr;

    pid_t attach_pid = -1;
    std::vector<std::string> cmd;

    bool vdso_opt_seen = false;
    bool vdso_keep = false;

    for (int i = 1; i < argc; i++) {
        std::string a = argv[i];
        if (a == "--") {
            for (int j = i + 1; j < argc; j++) cmd.push_back(argv[j]);
            break;
        }
        if (a == "--attach") {
            if (i + 1 >= argc) usage(argv[0]);
            attach_pid = (pid_t)std::strtol(argv[++i], nullptr, 10);
            continue;
        }
        if (a == "-mode") {
            if (i + 1 >= argc) usage(argv[0]);
            g_mode = parse_mode(argv[++i]);
            continue;
        }
        if (a == "-epoch") {
            if (i + 1 >= argc) usage(argv[0]);
            int64_t v = (int64_t)std::strtoll(argv[++i], nullptr, 10);
            if (g_mode == MODE_STATIC) g_static_epoch = v;
            else if (g_mode == MODE_OFFSET) g_offset_epoch = v;
            else g_static_epoch = v;
            continue;
        }
        if (a == "-timecl") {
            if (i + 1 >= argc) usage(argv[0]);
            g_timecl_enable = parse_bool_arg(argv[++i]);
            continue;
        }
        if (a == "-filets") {
            if (i + 1 >= argc) usage(argv[0]);
            g_filets_enable = parse_bool_arg(argv[++i]);
            continue;
        }
        if (a == "-clamp") {
            if (i + 1 >= argc) usage(argv[0]);
            g_clamp_enable = parse_bool_arg(argv[++i]);
            continue;
        }
        if (a == "-clampnsec") {
            if (i + 1 >= argc) usage(argv[0]);
            g_clamp_nsec = parse_bool_arg(argv[++i]);
            continue;
        }
        if (a == "-allclocks") {
            if (i + 1 >= argc) usage(argv[0]);
            g_all_clocks = parse_bool_arg(argv[++i]);
            continue;
        }
        if (a == "-debug") {
            if (i + 1 >= argc) usage(argv[0]);
            g_debug = parse_bool_arg(argv[++i]);
            continue;
        }
        if (a == "-log") {
            if (i + 1 >= argc) usage(argv[0]);
            const char* path = argv[++i];
            FILE* f = fopen(path, "a");
            if (f) g_logf = f;
            else g_logf = stderr;
            continue;
        }
        if (a == "-vdso") {
            if (i + 1 >= argc) usage(argv[0]);
            vdso_opt_seen = true;
            vdso_keep = parse_bool_arg(argv[++i]); // 1 => keep vdso, 0 => disable
            continue;
        }

        usage(argv[0]);
    }

    if (attach_pid < 0 && cmd.empty()) usage(argv[0]);

    // default: disable vDSO unless -vdso 1
    if (vdso_opt_seen) g_disable_vdso_by_default = !vdso_keep;
    else g_disable_vdso_by_default = true;

    vlog("[ptrace] start mode=%s static=%lld offset=%lld timecl=%d filets=%d clamp=%d clampnsec=%d allclocks=%d vdso_disable=%d\n",
         mode_name(g_mode),
         (long long)g_static_epoch, (long long)g_offset_epoch,
         g_timecl_enable?1:0, g_filets_enable?1:0, g_clamp_enable?1:0, g_clamp_nsec?1:0, g_all_clocks?1:0,
         g_disable_vdso_by_default ? 1 : 0);

    pid_t main_pid = -1;

    if (attach_pid >= 0) {
        // --- attach mode: PTRACE_SEIZE ---
        main_pid = attach_pid;

        unsigned long opts =
            PTRACE_O_TRACESYSGOOD |
            PTRACE_O_TRACECLONE |
            PTRACE_O_TRACEFORK  |
            PTRACE_O_TRACEVFORK |
            PTRACE_O_TRACEEXEC;
#ifdef PTRACE_O_EXITKILL
        opts |= PTRACE_O_EXITKILL;
#endif
        if (ptrace(PTRACE_SEIZE, main_pid, nullptr, (void*)opts) == -1) die("PTRACE_SEIZE");
        if (ptrace(PTRACE_INTERRUPT, main_pid, nullptr, nullptr) == -1) die("PTRACE_INTERRUPT");

        int st = 0;
        if (waitpid(main_pid, &st, __WALL) == -1) die("waitpid(attach)");

        g_ts[main_pid] = TState{};
        resume_syscall(main_pid, 0);
    } else {
        // --- run new process (strace-style): TRACEME + SYSCALL ---
        std::vector<char*> cargv;
        cargv.reserve(cmd.size() + 1);
        for (auto& s : cmd) cargv.push_back((char*)s.c_str());
        cargv.push_back(nullptr);

        pid_t child = fork();
        if (child == -1) die("fork");
        if (child == 0) {
            if (ptrace(PTRACE_TRACEME, 0, nullptr, nullptr) == -1) _exit(127);
            raise(SIGSTOP);
            execvp(cargv[0], cargv.data());
            _exit(127);
        }

        main_pid = child;

        int st = 0;
        if (waitpid(child, &st, __WALL) == -1) die("waitpid(child)");
        set_ptrace_options(child);

        g_ts[child] = TState{};
        resume_syscall(child, 0);
    }

    // --- main loop ---
    while (!g_ts.empty()) {
        int status = 0;
        pid_t tid = waitpid(-1, &status, __WALL);
        if (tid == -1) {
            if (errno == EINTR) continue;
            break;
        }

        if (WIFEXITED(status) || WIFSIGNALED(status)) {
            g_ts.erase(tid);
            continue;
        }

        if (!WIFSTOPPED(status)) {
            resume_syscall(tid, 0);
            continue;
        }

        int sig = WSTOPSIG(status);

        // syscall-stop?
        if (sig == (SIGTRAP | 0x80)) {
            auto& st = g_ts[tid];

            user_regs_struct regs{};
            if (ptrace(PTRACE_GETREGS, tid, nullptr, &regs) == -1) {
                resume_syscall(tid, 0);
                continue;
            }

            if (!st.in_syscall) {
                st.in_syscall = true;
                handle_syscall_entry(tid, regs, st);
            } else {
                st.in_syscall = false;
                handle_syscall_exit(tid, regs, st);
            }

            resume_syscall(tid, 0);
            continue;
        }

        // ptrace event?
        if (sig == SIGTRAP) {
            int event = (status >> 16) & 0xffff;

            if (event == PTRACE_EVENT_EXEC) {
                // After exec, disable vDSO by patching AUXV (default behavior)
                if (g_disable_vdso_by_default) {
                    bool ok = disable_vdso_in_auxv(tid);
                    g_vdso_disabled_runtime = ok;
                    vlog("[ptrace][dbg tid=%d] EXEC event: vdso_disable=%d result=%d\n",
                         (int)tid, g_disable_vdso_by_default?1:0, ok?1:0);
                }
                resume_syscall(tid, 0);
                continue;
            }

            if (event == PTRACE_EVENT_CLONE || event == PTRACE_EVENT_FORK || event == PTRACE_EVENT_VFORK) {
                unsigned long msg = 0;
                (void)ptrace(PTRACE_GETEVENTMSG, tid, nullptr, &msg);
                pid_t newtid = (pid_t)msg;

                set_ptrace_options(newtid);
                g_ts[newtid] = TState{};

                vlog("[ptrace][dbg] new tracee %d from %d (event=%d)\n", (int)newtid, (int)tid, event);

                resume_syscall(tid, 0);
                resume_syscall(newtid, 0);
                continue;
            }

            resume_syscall(tid, 0);
            continue;
        }

        // other signal: forward it
        resume_syscall(tid, sig);
    }

    return 0;
}
