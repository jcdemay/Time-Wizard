/*
 * Copyright (c) 2011 Jonathan-Christofer Demay (jcdemay@gmail.com)
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

#include "dr_api.h"
#include "drmgr.h"
#include "drwrap.h"
#include "drsyms.h"
#include "droption.h"

#include <string>
#include <stdint.h>
#include <stdarg.h>

#include <sys/syscall.h>
#include <sys/time.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>
#include <fcntl.h>

using namespace dynamorio::droption;

/* -------------------- options -------------------- */

static droption_t<std::string> op_log(DROPTION_SCOPE_CLIENT, "log",
                                      "time_dyn.log", "Log file", "");
static droption_t<bool> op_debug(DROPTION_SCOPE_CLIENT, "debug",
                                 false, "Minimal debug logs", "");

static droption_t<std::string> op_mode(DROPTION_SCOPE_CLIENT, "mode",
                                       "pass", "pass|static|offset|freeze", "");
static droption_t<int64_t> op_epoch(DROPTION_SCOPE_CLIENT, "epoch",
                                    0, "Epoch value/offset in seconds", "");
static droption_t<bool> op_freeze(DROPTION_SCOPE_CLIENT, "freeze",
                                  false, "Freeze at first wall-clock seen value", "");

static droption_t<bool> op_allclocks(DROPTION_SCOPE_CLIENT, "allclocks",
                                     false, "Also force monotonic/other clocks", "");
static droption_t<bool> op_timecl(DROPTION_SCOPE_CLIENT, "timecl",
                                  true, "Enable time clocks forcing", "");

static droption_t<bool> op_filets(DROPTION_SCOPE_CLIENT, "filets",
                                  false, "Enable file timestamps forcing", "");
static droption_t<bool> op_clamp(DROPTION_SCOPE_CLIENT, "clamp",
                                 false, "Clamp file timestamps to forced-now", "");
static droption_t<bool> op_clampnsec(DROPTION_SCOPE_CLIENT, "clampnsec",
                                     false, "Strict clamp on (sec,nsec)", "");

/* -------------------- globals -------------------- */

enum Mode { MODE_PASS=0, MODE_STATIC, MODE_OFFSET, MODE_FREEZE };

static Mode    g_mode            = MODE_PASS;
static bool    g_debug           = false;

static bool    g_timecl_enable   = true;
static bool    g_filets_enabled  = false;
static bool    g_filets_clamp    = false;
static bool    g_clamp_nsec      = false;
static bool    g_all_clocks      = false;

static bool    g_freeze_init     = false;
static int64_t g_static_epoch    = 0;
static int64_t g_offset_epoch    = 0;
static int64_t g_frozen_epoch    = 0;

static void   *g_freeze_lock     = nullptr;

/* dr_get_microseconds() epoch calibration using time(NULL) once.
 * Some DR builds historically used "since 1601", others "since 1970".
 */
static int64_t g_dr_epoch_offset_sec = 0; // seconds to subtract from dr_get_* to get UNIX epoch

static file_t  g_log = INVALID_FILE;

/* -------------------- TLS state -------------------- */

struct ThreadState {
    int inwrap;

    // utimensat rewriting buffer:
    struct timespec tsbuf[2];

    // entry->exit cached pointers for syscalls:
    reg_t   pending_stat_ptr;     // struct stat*
    reg_t   pending_statx_ptr;    // struct statx*
    uint32_t pending_statx_mask;

    reg_t pending_time_tloc;    // time_t*
    reg_t pending_gtod_tv;      // struct timeval*
    reg_t pending_cgt_tp;       // struct timespec*
    reg_t pending_cgt_clkid;    // clockid_t
};

static int g_tls_idx = -1;

static inline ThreadState* TS(void *drcontext) {
    return (ThreadState*)drmgr_get_tls_field(drcontext, g_tls_idx);
}

static inline void log_dbg(const char *fmt, ...) {
    if (!g_debug || g_log == INVALID_FILE) return;
    va_list ap;
    va_start(ap, fmt);
    dr_vfprintf(g_log, fmt, ap);
    va_end(ap);
}

/* Top-level wrapper guard to only patch once. */
static inline bool is_nested_wrap(ThreadState *st) {
    return (st != nullptr && st->inwrap > 1);
}

/* -------------------- mode helpers -------------------- */

static Mode ParseMode(const std::string& s) {
    if (s == "static") return MODE_STATIC;
    if (s == "offset") return MODE_OFFSET;
    if (s == "freeze") return MODE_FREEZE;
    return MODE_PASS;
}

static const char* ModeName(Mode m) {
    switch (m) {
        case MODE_STATIC: return "static";
        case MODE_OFFSET: return "offset";
        case MODE_FREEZE: return "freeze";
        default:          return "pass";
    }
}

/* -------------------- timecl engine -------------------- */

struct NowSpec { int64_t sec; int64_t nsec; };

static inline bool ShouldForceClock(reg_t clk_id) {
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

static inline void clamp_sec_nsec(int64_t &sec, int64_t &nsec, const NowSpec &now) {
    if (!g_filets_clamp) return;

    if (!g_clamp_nsec) {
        if (sec > now.sec) { sec = now.sec; nsec = now.nsec; }
        return;
    }
    if (sec > now.sec || (sec == now.sec && nsec > now.nsec)) {
        sec = now.sec;
        nsec = now.nsec;
    }
}

static inline NowSpec host_now_timespec() {
    uint64_t usec = dr_get_microseconds(); // epoch calibrated at init
    int64_t sec = (int64_t)(usec / 1000000ULL) - g_dr_epoch_offset_sec;
    int64_t nsec = (int64_t)(usec % 1000000ULL) * 1000LL;
    return NowSpec{ sec, nsec };
}

static int64_t EnsureFreezeInitFromHostNow() {
    if (g_mode != MODE_FREEZE) return 0;
    if (g_freeze_init) return g_frozen_epoch;

    dr_mutex_lock(g_freeze_lock);
    if (!g_freeze_init) {
        NowSpec hn = host_now_timespec();
        g_frozen_epoch = hn.sec;
        g_freeze_init = true;
    }
    dr_mutex_unlock(g_freeze_lock);
    return g_frozen_epoch;
}

static inline int64_t ChooseEpoch_Time(int64_t real_epoch) {
    if (g_mode == MODE_STATIC)  return g_static_epoch;
    if (g_mode == MODE_OFFSET)  return real_epoch + g_offset_epoch;
    if (g_mode == MODE_FREEZE) {
        // freeze at first wall-clock value observed from app
        if (!g_freeze_init) {
            dr_mutex_lock(g_freeze_lock);
            if (!g_freeze_init) {
                g_frozen_epoch = real_epoch;
                g_freeze_init = true;
            }
            dr_mutex_unlock(g_freeze_lock);
        }
        return g_frozen_epoch;
    }
    return real_epoch;
}

static inline int64_t ChooseEpoch_File(int64_t real_epoch) {
    if (g_mode == MODE_STATIC)  return g_static_epoch;
    if (g_mode == MODE_OFFSET)  return real_epoch + g_offset_epoch;
    if (g_mode == MODE_FREEZE)  return EnsureFreezeInitFromHostNow();
    return real_epoch;
}

static inline NowSpec ForcedNowSpec() {
    if (g_mode == MODE_STATIC)  return NowSpec{ g_static_epoch, 0 };
    if (g_mode == MODE_FREEZE)  return NowSpec{ EnsureFreezeInitFromHostNow(), 0 };

    NowSpec hn = host_now_timespec();
    if (g_mode == MODE_PASS) return hn;

    // MODE_OFFSET: now (view) = host + offset, nsec preserved
    if (g_mode == MODE_OFFSET) return NowSpec{ hn.sec + g_offset_epoch, hn.nsec };

    return hn;
}

/* -------------------- filets engine -------------------- */

static bool safe_read(const void *src, void *dst, size_t sz) {
    size_t got = 0;
    return dr_safe_read(src, sz, dst, &got) && got == sz;
}
static bool safe_write(void *dst, const void *src, size_t sz) {
    size_t put = 0;
    return dr_safe_write(dst, sz, src, &put) && put == sz;
}

static void AdjustStatBuf(reg_t st_ptr, const NowSpec& now) {
    if (!st_ptr || g_mode == MODE_PASS) return;
    struct stat st;
    if (!safe_read((const void*)st_ptr, &st, sizeof(st))) return;

    auto adj_timespec = [&](struct timespec &ts) {
        int64_t sec = ChooseEpoch_File((int64_t)ts.tv_sec);
        int64_t nsec = (int64_t)ts.tv_nsec;
        if (g_mode == MODE_STATIC || g_mode == MODE_FREEZE) nsec = 0;
        clamp_sec_nsec(sec, nsec, now);
        ts.tv_sec = (time_t)sec;
        ts.tv_nsec = (long)nsec;
    };

    adj_timespec(st.st_atim);
    adj_timespec(st.st_mtim);
    adj_timespec(st.st_ctim);

    (void)safe_write((void*)st_ptr, &st, sizeof(st));
}

/* statx fallback (no need for <linux/stat.h>) */
#ifdef __linux__
#ifndef STATX_ATIME
#  define STATX_ATIME       0x00000020U
#  define STATX_MTIME       0x00000040U
#  define STATX_CTIME       0x00000080U
#  define STATX_BTIME       0x00000800U
#endif
#endif /* __linux__ */

#ifdef __linux__
static void AdjustStatxBuf(reg_t stx_ptr, uint32_t requested_mask, const NowSpec& now) {
    if (!stx_ptr || g_mode == MODE_PASS) return;

    struct statx sx;
    if (!safe_read((const void*)stx_ptr, &sx, sizeof(sx))) return;

    uint32_t patch_mask = sx.stx_mask & requested_mask;

    auto adj = [&](struct statx_timestamp &t) {
        int64_t sec = ChooseEpoch_File((int64_t)t.tv_sec);
        int64_t nsec = (int64_t)t.tv_nsec;
        if (g_mode == MODE_STATIC || g_mode == MODE_FREEZE) nsec = 0;
        clamp_sec_nsec(sec, nsec, now);
        t.tv_sec = (int64_t)sec;
        t.tv_nsec = (uint32_t)nsec;
    };

    if (patch_mask & STATX_ATIME) adj(sx.stx_atime);
    if (patch_mask & STATX_MTIME) adj(sx.stx_mtime);
    if (patch_mask & STATX_CTIME) adj(sx.stx_ctime);
    if (patch_mask & STATX_BTIME) adj(sx.stx_btime);

    (void)safe_write((void*)stx_ptr, &sx, sizeof(sx));
}
#endif /* __linux__ */

/* -------------------- syscall hooks -------------------- */

static inline void ClearPending(ThreadState *st) {
    if (!st) return;
    st->pending_stat_ptr = 0;
    st->pending_statx_ptr = 0;
    st->pending_statx_mask = 0;
    st->pending_time_tloc = 0;
    st->pending_gtod_tv = 0;
    st->pending_cgt_tp = 0;
    st->pending_cgt_clkid = 0;
}

static bool event_filter_syscall(void *drcontext, int sysnum) {
    (void)drcontext;

    if (g_timecl_enable) {
#ifdef SYS_time
        if (sysnum == SYS_time) return true;
#endif
#ifdef SYS_gettimeofday
        if (sysnum == SYS_gettimeofday) return true;
#endif
#ifdef SYS_clock_gettime
        if (sysnum == SYS_clock_gettime) return true;
#endif
#ifdef SYS_clock_gettime64
        if (sysnum == SYS_clock_gettime64) return true;
#endif
    }

    if (g_filets_enabled) {
#ifdef SYS_newfstatat
        if (sysnum == SYS_newfstatat) return true;
#endif
#ifdef SYS_fstat
        if (sysnum == SYS_fstat) return true;
#endif
#ifdef SYS_statx
        if (sysnum == SYS_statx) return true;
#endif
#ifdef SYS_utimensat
        if (sysnum == SYS_utimensat) return true;
#endif
    }

    return false;
}

static bool event_pre_syscall(void *drcontext, int sysnum) {
    ThreadState *st = TS(drcontext);
    if (!st) return true;

    // Always clear pending for the syscalls filtering (one syscall at a time)
    ClearPending(st);

    if (st->inwrap > 0) return true; // avoid recursion (double-patching)

    /* ---- timecl: cache output pointers on ENTRY ---- */
    if (g_timecl_enable && g_mode != MODE_PASS) {
#ifdef SYS_time
        if (sysnum == SYS_time) {
            st->pending_time_tloc = (reg_t)dr_syscall_get_param(drcontext, 0);
            return true;
        }
#endif
#ifdef SYS_gettimeofday
        if (sysnum == SYS_gettimeofday) {
            st->pending_gtod_tv = (reg_t)dr_syscall_get_param(drcontext, 0);
            return true;
        }
#endif
#ifdef SYS_clock_gettime
        if (sysnum == SYS_clock_gettime) {
            st->pending_cgt_clkid = (reg_t)dr_syscall_get_param(drcontext, 0);
            st->pending_cgt_tp    = (reg_t)dr_syscall_get_param(drcontext, 1);
            return true;
        }
#endif
#ifdef SYS_clock_gettime64
        if (sysnum == SYS_clock_gettime64) {
            st->pending_cgt_clkid = (reg_t)dr_syscall_get_param(drcontext, 0);
            st->pending_cgt_tp    = (reg_t)dr_syscall_get_param(drcontext, 1);
            return true;
        }
#endif
    }

    /* ---- filets: cache buffers on ENTRY (patch on EXIT) ---- */
    if (g_filets_enabled && g_mode != MODE_PASS) {
#ifdef SYS_newfstatat
        if (sysnum == SYS_newfstatat) {
            // newfstatat(dirfd, path, statbuf, flags): statbuf is arg2
            st->pending_stat_ptr = (reg_t)dr_syscall_get_param(drcontext, 2);
            return true;
        }
#endif
#ifdef SYS_fstat
        if (sysnum == SYS_fstat) {
            // fstat(fd, statbuf): statbuf is arg1
            st->pending_stat_ptr = (reg_t)dr_syscall_get_param(drcontext, 1);
            return true;
        }
#endif
#ifdef SYS_statx
        if (sysnum == SYS_statx) {
            // statx(dirfd, path, flags, mask, statxbuf): mask arg3, buf arg4
            st->pending_statx_mask = (uint32_t)(reg_t)dr_syscall_get_param(drcontext, 3);
            st->pending_statx_ptr  = (reg_t)dr_syscall_get_param(drcontext, 4);
            return true;
        }
#endif

        /* ---- utimensat rewrite on ENTRY ---- */
#ifdef SYS_utimensat
        if (sysnum == SYS_utimensat) {
            // utimensat(dirfd, pathname, times[2], flags): times is arg2
            reg_t times_ptr = (reg_t)dr_syscall_get_param(drcontext, 2);

            NowSpec now = ForcedNowSpec();

            if (times_ptr == 0) {
                // times == NULL => set to real current time (in *disk domain* if MODE_OFFSET)
                st->tsbuf[0].tv_sec  = (time_t)now.sec;
                st->tsbuf[0].tv_nsec = (long) now.nsec;
                st->tsbuf[1] = st->tsbuf[0];

                if (g_mode == MODE_OFFSET) {
                    st->tsbuf[0].tv_sec = (time_t)((int64_t)st->tsbuf[0].tv_sec - g_offset_epoch);
                    st->tsbuf[1].tv_sec = (time_t)((int64_t)st->tsbuf[1].tv_sec - g_offset_epoch);
                }

                dr_syscall_set_param(drcontext, 2, (reg_t)&st->tsbuf[0]);
                log_dbg("[dr][dbg] utimensat ENTRY: times=NULL -> forced now\n");
                return true;
            }

            struct timespec in[2];
            if (!safe_read((const void*)times_ptr, &in, sizeof(in))) return true;

            for (int i = 0; i < 2; i++) {
#ifdef UTIME_NOW
                if (in[i].tv_nsec == UTIME_NOW) {
                    st->tsbuf[i].tv_sec  = (time_t)now.sec;
                    st->tsbuf[i].tv_nsec = (long) now.nsec;

                    if (g_mode == MODE_OFFSET) {
                        st->tsbuf[i].tv_sec = (time_t)((int64_t)st->tsbuf[i].tv_sec - g_offset_epoch);
                    }
                    continue;
                }
                if (in[i].tv_nsec == UTIME_OMIT) {
                    st->tsbuf[i] = in[i];
                    continue;
                }
#endif
                int64_t sec  = (int64_t)in[i].tv_sec;
                int64_t nsec = (int64_t)in[i].tv_nsec;

                if (g_mode == MODE_OFFSET) {
                    // view -> disk
                    sec -= g_offset_epoch;
                } else {
                    sec = ChooseEpoch_File(sec);
                }

                if (g_mode == MODE_STATIC || g_mode == MODE_FREEZE) nsec = 0;

                NowSpec clamp_now = now;
                if (g_mode == MODE_OFFSET) clamp_now.sec -= g_offset_epoch;

                clamp_sec_nsec(sec, nsec, clamp_now);

                st->tsbuf[i].tv_sec  = (time_t)sec;
                st->tsbuf[i].tv_nsec = (long)nsec;
            }

            dr_syscall_set_param(drcontext, 2, (reg_t)&st->tsbuf[0]);
            log_dbg("[dr][dbg] utimensat ENTRY: rewritten times[]\n");
            return true;
        }
#endif /* SYS_utimensat */
    }

    return true;
}

static void event_post_syscall(void *drcontext, int sysnum) {
    ThreadState *st = TS(drcontext);
    if (!st) return;
    if (st->inwrap > 0) return;

    dr_syscall_result_info_t ri;
    ri.size = sizeof(ri);
    if (!dr_syscall_get_result_ex(drcontext, &ri)) return;

    if (!ri.succeeded) {
        return;
    }

    /* ---- timecl patches on EXIT ---- */
    if (g_timecl_enable && g_mode != MODE_PASS) {
#ifdef SYS_time
        if (sysnum == SYS_time) {
            int64_t real = (int64_t)ri.value;
            int64_t chosen = ChooseEpoch_Time(real);

            dr_syscall_set_result(drcontext, (reg_t)chosen);

            if (st->pending_time_tloc) {
                time_t v = (time_t)chosen;
                (void)safe_write((void*)st->pending_time_tloc, &v, sizeof(v));
            }
            log_dbg("[dr][dbg] syscall time forced=%lld\n", (long long)chosen);
            return;
        }
#endif
#ifdef SYS_gettimeofday
        if (sysnum == SYS_gettimeofday) {
            if (!st->pending_gtod_tv) return;
            struct timeval tv;
            if (!safe_read((const void*)st->pending_gtod_tv, &tv, sizeof(tv))) return;

            int64_t chosen = ChooseEpoch_Time((int64_t)tv.tv_sec);
            tv.tv_sec = (time_t)chosen;
            tv.tv_usec = 0;
            (void)safe_write((void*)st->pending_gtod_tv, &tv, sizeof(tv));
            log_dbg("[dr][dbg] syscall gettimeofday forced=%lld\n", (long long)chosen);
            return;
        }
#endif
#ifdef SYS_clock_gettime
        if (sysnum == SYS_clock_gettime) {
            if (!st->pending_cgt_tp) return;
            if (!ShouldForceClock(st->pending_cgt_clkid)) return;

            struct timespec ts;
            if (!safe_read((const void*)st->pending_cgt_tp, &ts, sizeof(ts))) return;

            int64_t chosen = ChooseEpoch_Time((int64_t)ts.tv_sec);
            ts.tv_sec = (time_t)chosen;
            ts.tv_nsec = 0;
            (void)safe_write((void*)st->pending_cgt_tp, &ts, sizeof(ts));
            log_dbg("[dr][dbg] syscall clock_gettime forced=%lld\n", (long long)chosen);
            return;
        }
#endif
#ifdef SYS_clock_gettime64
        if (sysnum == SYS_clock_gettime64) {
            if (!st->pending_cgt_tp) return;
            if (!ShouldForceClock(st->pending_cgt_clkid)) return;

            // Best-effort: assuming timespec layout is compatible enough for typical 64-bit Linux.
            struct timespec ts;
            if (!safe_read((const void*)st->pending_cgt_tp, &ts, sizeof(ts))) return;

            int64_t chosen = ChooseEpoch_Time((int64_t)ts.tv_sec);
            ts.tv_sec = (time_t)chosen;
            ts.tv_nsec = 0;
            (void)safe_write((void*)st->pending_cgt_tp, &ts, sizeof(ts));
            log_dbg("[dr][dbg] syscall clock_gettime64 forced=%lld\n", (long long)chosen);
            return;
        }
#endif
    }

    /* ---- filets patches on EXIT ---- */
    if (g_filets_enabled && g_mode != MODE_PASS) {
        NowSpec now = ForcedNowSpec();

#ifdef SYS_statx
        if (sysnum == SYS_statx && st->pending_statx_ptr) {
            // statx returns 0 on success
            if ((int64_t)ri.value == 0) {
                AdjustStatxBuf(st->pending_statx_ptr, st->pending_statx_mask, now);
                log_dbg("[dr][dbg] syscall patched statx\n");
            }
            return;
        }
#endif

        if (st->pending_stat_ptr) {
            // newfstatat/fstat return 0 on success
            if ((int64_t)ri.value == 0) {
                AdjustStatBuf(st->pending_stat_ptr, now);
                log_dbg("[dr][dbg] syscall patched stat-like\n");
            }
            return;
        }
    }
}

/* -------------------- drwrap wrappers (libc/vdso coverage) -------------------- */

struct wrap_ud {
    ThreadState *st;
    reg_t a0;
    reg_t a1;
    reg_t a2;
    reg_t a3;
    reg_t a4; // statx buf
};

static void wrap_enter(ThreadState *st) { if (st) st->inwrap++; }
static void wrap_leave(ThreadState *st) { if (st) st->inwrap--; }

/* ---- time ---- */

static void pre_time(void *wrapcxt, void **user_data) {
    void *dc = drwrap_get_drcontext(wrapcxt);
    ThreadState *st = TS(dc);
    wrap_enter(st);

    wrap_ud *ud = (wrap_ud*)dr_thread_alloc(dc, sizeof(wrap_ud));
    ud->st = st;
    ud->a0 = (reg_t)drwrap_get_arg(wrapcxt, 0); // time_t*
    *user_data = ud;
}

static void post_time(void *wrapcxt, void *user_data) {
    void *dc = drwrap_get_drcontext(wrapcxt);
    wrap_ud *ud = (wrap_ud*)user_data;
    ThreadState *st = ud ? ud->st : nullptr;

    bool nested = is_nested_wrap(st);

    ptr_int_t ret = (ptr_int_t)(ptr_uint_t)drwrap_get_retval(wrapcxt);
    int64_t real = (int64_t)ret;

    if (!nested) {
        int64_t chosen = (g_timecl_enable && g_mode != MODE_PASS) ? ChooseEpoch_Time(real) : real;

        drwrap_set_retval(wrapcxt, (void*)(ptr_int_t)chosen);
        if (ud && ud->a0) {
            time_t v = (time_t)chosen;
            (void)safe_write((void*)ud->a0, &v, sizeof(v));
        }
        log_dbg("[dr][dbg] RTN time forced=%lld\n", (long long)chosen);
    }

    if (ud) {
        wrap_leave(st);
        dr_thread_free(dc, ud, sizeof(*ud));
    }
}

/* ---- gettimeofday ---- */

static void pre_gettimeofday(void *wrapcxt, void **user_data) {
    void *dc = drwrap_get_drcontext(wrapcxt);
    ThreadState *st = TS(dc);
    wrap_enter(st);

    wrap_ud *ud = (wrap_ud*)dr_thread_alloc(dc, sizeof(wrap_ud));
    ud->st = st;
    ud->a0 = (reg_t)drwrap_get_arg(wrapcxt, 0); // struct timeval*
    ud->a1 = (reg_t)drwrap_get_arg(wrapcxt, 1); // tz*
    *user_data = ud;
}

static void post_gettimeofday(void *wrapcxt, void *user_data) {
    void *dc = drwrap_get_drcontext(wrapcxt);
    wrap_ud *ud = (wrap_ud*)user_data;
    ThreadState *st = ud ? ud->st : nullptr;

    bool nested = is_nested_wrap(st);

    ptr_int_t ret = (ptr_int_t)(ptr_uint_t)drwrap_get_retval(wrapcxt);
    if (!nested && g_timecl_enable && g_mode != MODE_PASS && (int64_t)ret == 0 && ud && ud->a0) {
        struct timeval tv;
        if (safe_read((const void*)ud->a0, &tv, sizeof(tv))) {
            int64_t chosen = ChooseEpoch_Time((int64_t)tv.tv_sec);
            tv.tv_sec = (time_t)chosen;
            tv.tv_usec = 0;
            (void)safe_write((void*)ud->a0, &tv, sizeof(tv));
            log_dbg("[dr][dbg] RTN gettimeofday forced=%lld\n", (long long)chosen);
        }
    }

    if (ud) {
        wrap_leave(st);
        dr_thread_free(dc, ud, sizeof(*ud));
    }
}

/* ---- clock_gettime ---- */

static void pre_clock_gettime(void *wrapcxt, void **user_data) {
    void *dc = drwrap_get_drcontext(wrapcxt);
    ThreadState *st = TS(dc);
    wrap_enter(st);

    wrap_ud *ud = (wrap_ud*)dr_thread_alloc(dc, sizeof(wrap_ud));
    ud->st = st;
    ud->a0 = (reg_t)drwrap_get_arg(wrapcxt, 0); // clockid_t
    ud->a1 = (reg_t)drwrap_get_arg(wrapcxt, 1); // struct timespec*
    *user_data = ud;
}

static void post_clock_gettime(void *wrapcxt, void *user_data) {
    void *dc = drwrap_get_drcontext(wrapcxt);
    wrap_ud *ud = (wrap_ud*)user_data;
    ThreadState *st = ud ? ud->st : nullptr;

    bool nested = is_nested_wrap(st);

    ptr_int_t ret = (ptr_int_t)(ptr_uint_t)drwrap_get_retval(wrapcxt);
    if (!nested && g_timecl_enable && g_mode != MODE_PASS && (int64_t)ret == 0 && ud && ud->a1) {
        if (ShouldForceClock(ud->a0)) {
            struct timespec ts;
            if (safe_read((const void*)ud->a1, &ts, sizeof(ts))) {
                int64_t chosen = ChooseEpoch_Time((int64_t)ts.tv_sec);
                ts.tv_sec = (time_t)chosen;
                ts.tv_nsec = 0;
                (void)safe_write((void*)ud->a1, &ts, sizeof(ts));
                log_dbg("[dr][dbg] RTN clock_gettime forced=%lld\n", (long long)chosen);
            }
        }
    }

    if (ud) {
        wrap_leave(st);
        dr_thread_free(dc, ud, sizeof(*ud));
    }
}

/* ---- stat-like: st* at arg1 (stat/lstat/fstat/...) ---- */

static void pre_stat_stptr_arg1(void *wrapcxt, void **user_data) {
    void *dc = drwrap_get_drcontext(wrapcxt);
    ThreadState *st = TS(dc);
    wrap_enter(st);

    wrap_ud *ud = (wrap_ud*)dr_thread_alloc(dc, sizeof(wrap_ud));
    ud->st = st;
    ud->a1 = (reg_t)drwrap_get_arg(wrapcxt, 1); // struct stat*
    *user_data = ud;
}

static void post_stat_stptr_arg1(void *wrapcxt, void *user_data) {
    void *dc = drwrap_get_drcontext(wrapcxt);
    wrap_ud *ud = (wrap_ud*)user_data;
    ThreadState *st = ud ? ud->st : nullptr;

    bool nested = is_nested_wrap(st);

    ptr_int_t ret = (ptr_int_t)(ptr_uint_t)drwrap_get_retval(wrapcxt);
    if (!nested && g_filets_enabled && g_mode != MODE_PASS && (int64_t)ret == 0 && ud && ud->a1) {
        NowSpec now = ForcedNowSpec();
        AdjustStatBuf(ud->a1, now);
        log_dbg("[dr][dbg] RTN patched struct stat (arg1)\n");
    }

    if (ud) {
        wrap_leave(st);
        dr_thread_free(dc, ud, sizeof(*ud));
    }
}

/* ---- __xstat-like: st* at arg2 (__xstat/__lxstat/...) ---- */

static void pre_xstat_stptr_arg2(void *wrapcxt, void **user_data) {
    void *dc = drwrap_get_drcontext(wrapcxt);
    ThreadState *st = TS(dc);
    wrap_enter(st);

    wrap_ud *ud = (wrap_ud*)dr_thread_alloc(dc, sizeof(wrap_ud));
    ud->st = st;
    ud->a2 = (reg_t)drwrap_get_arg(wrapcxt, 2); // struct stat*
    *user_data = ud;
}

static void post_xstat_stptr_arg2(void *wrapcxt, void *user_data) {
    void *dc = drwrap_get_drcontext(wrapcxt);
    wrap_ud *ud = (wrap_ud*)user_data;
    ThreadState *st = ud ? ud->st : nullptr;

    bool nested = is_nested_wrap(st);

    ptr_int_t ret = (ptr_int_t)(ptr_uint_t)drwrap_get_retval(wrapcxt);
    if (!nested && g_filets_enabled && g_mode != MODE_PASS && (int64_t)ret == 0 && ud && ud->a2) {
        NowSpec now = ForcedNowSpec();
        AdjustStatBuf(ud->a2, now);
        log_dbg("[dr][dbg] RTN patched struct stat (__xstat arg2)\n");
    }

    if (ud) {
        wrap_leave(st);
        dr_thread_free(dc, ud, sizeof(*ud));
    }
}

/* ---- fstatat/newfstatat: st* at arg2 ---- */

static void pre_fstatat_stptr_arg2(void *wrapcxt, void **user_data) {
    void *dc = drwrap_get_drcontext(wrapcxt);
    ThreadState *st = TS(dc);
    wrap_enter(st);

    wrap_ud *ud = (wrap_ud*)dr_thread_alloc(dc, sizeof(wrap_ud));
    ud->st = st;
    ud->a2 = (reg_t)drwrap_get_arg(wrapcxt, 2); // struct stat*
    *user_data = ud;
}

static void post_fstatat_stptr_arg2(void *wrapcxt, void *user_data) {
    void *dc = drwrap_get_drcontext(wrapcxt);
    wrap_ud *ud = (wrap_ud*)user_data;
    ThreadState *st = ud ? ud->st : nullptr;

    bool nested = is_nested_wrap(st);

    ptr_int_t ret = (ptr_int_t)(ptr_uint_t)drwrap_get_retval(wrapcxt);
    if (!nested && g_filets_enabled && g_mode != MODE_PASS && (int64_t)ret == 0 && ud && ud->a2) {
        NowSpec now = ForcedNowSpec();
        AdjustStatBuf(ud->a2, now);
        log_dbg("[dr][dbg] RTN patched struct stat (fstatat arg2)\n");
    }

    if (ud) {
        wrap_leave(st);
        dr_thread_free(dc, ud, sizeof(*ud));
    }
}

/* ---- __fxstatat: st* at arg3 ---- */

static void pre_fxstatat_stptr_arg3(void *wrapcxt, void **user_data) {
    void *dc = drwrap_get_drcontext(wrapcxt);
    ThreadState *st = TS(dc);
    wrap_enter(st);

    wrap_ud *ud = (wrap_ud*)dr_thread_alloc(dc, sizeof(wrap_ud));
    ud->st = st;
    ud->a3 = (reg_t)drwrap_get_arg(wrapcxt, 3); // struct stat*
    *user_data = ud;
}

static void post_fxstatat_stptr_arg3(void *wrapcxt, void *user_data) {
    void *dc = drwrap_get_drcontext(wrapcxt);
    wrap_ud *ud = (wrap_ud*)user_data;
    ThreadState *st = ud ? ud->st : nullptr;

    bool nested = is_nested_wrap(st);

    ptr_int_t ret = (ptr_int_t)(ptr_uint_t)drwrap_get_retval(wrapcxt);
    if (!nested && g_filets_enabled && g_mode != MODE_PASS && (int64_t)ret == 0 && ud && ud->a3) {
        NowSpec now = ForcedNowSpec();
        AdjustStatBuf(ud->a3, now);
        log_dbg("[dr][dbg] RTN patched struct stat (__fxstatat arg3)\n");
    }

    if (ud) {
        wrap_leave(st);
        dr_thread_free(dc, ud, sizeof(*ud));
    }
}

/* ---- statx: mask arg3, buf arg4 ---- */

static void pre_statx_stxptr_arg4(void *wrapcxt, void **user_data) {
    void *dc = drwrap_get_drcontext(wrapcxt);
    ThreadState *st = TS(dc);
    wrap_enter(st);

    wrap_ud *ud = (wrap_ud*)dr_thread_alloc(dc, sizeof(wrap_ud));
    ud->st = st;
    ud->a3 = (reg_t)drwrap_get_arg(wrapcxt, 3); // mask
    ud->a4 = (reg_t)drwrap_get_arg(wrapcxt, 4); // struct statx*
    *user_data = ud;
}

static void post_statx_stxptr_arg4(void *wrapcxt, void *user_data) {
    void *dc = drwrap_get_drcontext(wrapcxt);
    wrap_ud *ud = (wrap_ud*)user_data;
    ThreadState *st = ud ? ud->st : nullptr;

    bool nested = is_nested_wrap(st);

    ptr_int_t ret = (ptr_int_t)(ptr_uint_t)drwrap_get_retval(wrapcxt);
    if (!nested && g_filets_enabled && g_mode != MODE_PASS && (int64_t)ret == 0 && ud && ud->a4) {
        NowSpec now = ForcedNowSpec();
        AdjustStatxBuf(ud->a4, (uint32_t)ud->a3, now);
        log_dbg("[dr][dbg] RTN patched struct statx\n");
    }

    if (ud) {
        wrap_leave(st);
        dr_thread_free(dc, ud, sizeof(*ud));
    }
}

/* -------------------- symbol lookup + wrapping table -------------------- */

static app_pc lookup_symbol_in_module(const module_data_t *mod, const char *name) {
    if (mod == nullptr) return nullptr;

    // Try drsyms first (can see .symtab not only .dynsym)
    size_t offs = 0;
    if (mod->full_path != nullptr &&
        drsym_lookup_symbol(mod->full_path, name, &offs, 0) == DRSYM_SUCCESS) {
        return mod->start + offs;
    }

    // Fallback: exported symbols only
    generic_func_t f = dr_get_proc_address(mod->handle, name);
    return (app_pc)f;
}

static void try_wrap(const module_data_t *mod,
                     const char *name,
                     void (*pre)(void*, void**),
                     void (*post)(void*, void*)) {
    app_pc pc = lookup_symbol_in_module(mod, name);
    if (!pc) return;
    if (drwrap_wrap(pc, pre, post)) {
        log_dbg("[dr][dbg] wrapped %s in %s\n",
                name, (mod->full_path ? mod->full_path : "<unknown>"));
    }
}

static void event_module_load(void *drcontext, const module_data_t *info, bool loaded) {
    (void)drcontext; (void)loaded;

    if (!g_timecl_enable && !g_filets_enabled) return;

    // time family (libc + sometimes vdso)
    if (g_timecl_enable) {
        const char *time_names[] = {"time", "__time", nullptr};
        const char *gtod_names[] = {"gettimeofday", "__gettimeofday", "__vdso_gettimeofday", nullptr};
        const char *cgt_names[]  = {"clock_gettime", "__clock_gettime", "__vdso_clock_gettime", nullptr};

        for (int i=0; time_names[i]; i++)
            try_wrap(info, time_names[i], pre_time, post_time);
        for (int i=0; gtod_names[i]; i++)
            try_wrap(info, gtod_names[i], pre_gettimeofday, post_gettimeofday);
        for (int i=0; cgt_names[i]; i++)
            try_wrap(info, cgt_names[i], pre_clock_gettime, post_clock_gettime);
    }

    // stat family (read-side)
    if (g_filets_enabled) {
        // st* at arg1
        const char *stat_names_arg1[] = {
            "stat","lstat","fstat",
            "stat64","lstat64","fstat64",
            nullptr
        };

        // __xstat/__lxstat: st* at arg2
        const char *xstat_names_arg2[] = {
            "__xstat","__lxstat","__xstat64","__lxstat64",
            "__GI___xstat","__GI___lxstat","__GI___xstat64","__GI___lxstat64",
            nullptr
        };

        // fstatat/newfstatat: st* at arg2
        const char *fstatat_names_arg2[] = {
            "fstatat","newfstatat","fstatat64",
            "__fstatat64_time64","__fstatat_time64",
            "__GI___fstatat64_time64","__GI___fstatat_time64",
            "__libc_fstatat64","__GI___libc_fstatat64",
            nullptr
        };

        // __fxstatat: st* at arg3
        const char *fxstatat_names_arg3[] = {
            "__fxstatat","__fxstatat64","__fxstatat64_time64",
            "__GI___fxstatat","__GI___fxstatat64","__GI___fxstatat64_time64",
            nullptr
        };

        const char *statx_names[] = {"statx","__statx","__statx_time64","__GI___statx","__GI___statx_time64", nullptr};

        for (int i=0; stat_names_arg1[i]; i++)
            try_wrap(info, stat_names_arg1[i], pre_stat_stptr_arg1, post_stat_stptr_arg1);

        for (int i=0; xstat_names_arg2[i]; i++)
            try_wrap(info, xstat_names_arg2[i], pre_xstat_stptr_arg2, post_xstat_stptr_arg2);

        for (int i=0; fstatat_names_arg2[i]; i++)
            try_wrap(info, fstatat_names_arg2[i], pre_fstatat_stptr_arg2, post_fstatat_stptr_arg2);

        for (int i=0; fxstatat_names_arg3[i]; i++)
            try_wrap(info, fxstatat_names_arg3[i], pre_fxstatat_stptr_arg3, post_fxstatat_stptr_arg3);

        for (int i=0; statx_names[i]; i++)
            try_wrap(info, statx_names[i], pre_statx_stxptr_arg4, post_statx_stxptr_arg4);
    }
}

/* -------------------- thread events -------------------- */

static void event_thread_init(void *drcontext) {
    ThreadState *st = (ThreadState*)dr_thread_alloc(drcontext, sizeof(ThreadState));
    st->inwrap = 0;
    st->tsbuf[0] = {0,0};
    st->tsbuf[1] = {0,0};
    st->pending_stat_ptr = 0;
    st->pending_statx_ptr = 0;
    st->pending_statx_mask = 0;
    st->pending_time_tloc = 0;
    st->pending_gtod_tv = 0;
    st->pending_cgt_tp = 0;
    st->pending_cgt_clkid = 0;

    drmgr_set_tls_field(drcontext, g_tls_idx, st);
}

static void event_thread_exit(void *drcontext) {
    ThreadState *st = TS(drcontext);
    if (st) {
        dr_thread_free(drcontext, st, sizeof(ThreadState));
        drmgr_set_tls_field(drcontext, g_tls_idx, nullptr);
    }
}

/* -------------------- exit -------------------- */

static void event_exit(void) {
    if (g_log != INVALID_FILE) {
        dr_fprintf(g_log, "[dr] exit\n");
        dr_close_file(g_log);
        g_log = INVALID_FILE;
    }
    if (g_freeze_lock) {
        dr_mutex_destroy(g_freeze_lock);
        g_freeze_lock = nullptr;
    }
    drwrap_exit();
    drmgr_exit();
    drsym_exit();
}

/* -------------------- init -------------------- */

static void client_init_common(client_id_t id) {
    dr_set_client_name("timeforce_drrio", "https://dynamorio.org/");

    // Parse options
    std::string parse_err;
    if (!dr_parse_options(id, &parse_err, NULL)) {
        dr_fprintf(STDERR, "timeforce_drrio: option parse error: %s\n", parse_err.c_str());
        return;
    }

    g_debug = op_debug.get_value();

    g_mode = ParseMode(op_mode.get_value());
    if (op_freeze.get_value())
        g_mode = MODE_FREEZE;

    g_static_epoch = 0;
    g_offset_epoch = 0;

    if (g_mode == MODE_STATIC) g_static_epoch = op_epoch.get_value();
    if (g_mode == MODE_OFFSET) g_offset_epoch = op_epoch.get_value();

    g_all_clocks     = op_allclocks.get_value();
    g_timecl_enable  = op_timecl.get_value();
    g_filets_enabled = op_filets.get_value();
    g_filets_clamp   = op_clamp.get_value();
    g_clamp_nsec     = op_clampnsec.get_value();

    // Calibrate dr_get_microseconds() epoch using time(NULL)
    {
        uint64_t usec = dr_get_microseconds();
        int64_t dr_sec = (int64_t)(usec / 1000000ULL);
        int64_t unix_sec = (int64_t)time(NULL);

        int64_t diff = dr_sec - unix_sec; // maybe 0, maybe 11644473600
        const int64_t EPOCH_1601_TO_1970 = 11644473600LL;

        // heuristic:
        if (diff > (EPOCH_1601_TO_1970 - 86400) && diff < (EPOCH_1601_TO_1970 + 86400)) {
            g_dr_epoch_offset_sec = EPOCH_1601_TO_1970;
        } else if (diff > -86400 && diff < 86400) {
            g_dr_epoch_offset_sec = 0;
        } else {
            // fallback: assume UNIX epoch (best-effort)
            g_dr_epoch_offset_sec = 0;
        }
    }

    // init extensions
    drmgr_init();
    drwrap_init();
    (void)drsym_init(0);

    g_freeze_lock = dr_mutex_create();

    // TLS
    g_tls_idx = drmgr_register_tls_field();
    DR_ASSERT(g_tls_idx != -1);

    // log file
    g_log = dr_open_file(op_log.get_value().c_str(),
                         DR_FILE_WRITE_APPEND | DR_FILE_ALLOW_LARGE);
    if (g_log == INVALID_FILE) {
        g_log = dr_get_stderr_file();
    }

    dr_fprintf(g_log,
        "[dr] start mode=%s epoch=%lld offset=%lld time=%d filets=%d clamp=%d clampnsec=%d debug=%d allclocks=%d dr_epoch_offs=%lld\n",
        ModeName(g_mode),
        (long long)g_static_epoch,
        (long long)g_offset_epoch,
        g_timecl_enable ? 1 : 0,
        g_filets_enabled ? 1 : 0,
        g_filets_clamp ? 1 : 0,
        g_clamp_nsec ? 1 : 0,
        g_debug ? 1 : 0,
        g_all_clocks ? 1 : 0,
        (long long)g_dr_epoch_offset_sec);

    // events
    dr_register_exit_event(event_exit);

    drmgr_register_thread_init_event(event_thread_init);
    drmgr_register_thread_exit_event(event_thread_exit);

    drmgr_register_module_load_event(event_module_load);

    // syscall filtering + pre/post
    dr_register_filter_syscall_event(event_filter_syscall);
    drmgr_register_pre_syscall_event(event_pre_syscall);
    drmgr_register_post_syscall_event(event_post_syscall);
}

/* Modern entry point */
DR_EXPORT void dr_client_main(client_id_t id, int argc, const char *argv[]) {
    (void)argc; (void)argv;
    client_init_common(id);
}

/* Legacy entry point (kept for compatibility) */
DR_EXPORT void dr_init(client_id_t id) {
    client_init_common(id);
}
