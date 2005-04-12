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

#define _GNU_SOURCE

#include <dlfcn.h>
#include <errno.h>
#include <fcntl.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/syscall.h>
#include <time.h>
#include <unistd.h>
#include <utime.h>

#ifdef __linux__
#include <linux/stat.h>
#endif

/* =========================================================================
   ENV:
     TIMEHOOK_DISABLE=0|1            (default 0)
     TIMEHOOK_LOG_ENABLE=0|1         (default 0)
     TIMEHOOK_LOG_PATH=/path         (default stderr)
     TIMEHOOK_DEBUG=0|1              (default 0)

     TIMEHOOK_MODE=pass|static|offset|freeze  (default pass)
     TIMEHOOK_EPOCH=<int64 seconds>           (default 0)
       - if MODE_STATIC : epoch is forced epoch
       - if MODE_OFFSET : epoch is offset in seconds (can be negative)
       - if MODE_FREEZE : epoch is ignored (freeze uses first seen wall time)

     TIMEHOOK_ALLCLOCKS=0|1          (default 0) also force monotonic/other clocks
     TIMEHOOK_TIMECL=0|1             (default 1) enable time clocks forcing
     TIMEHOOK_FILETS=0|1             (default 0) enable file timestamps forcing
     TIMEHOOK_CLAMP=0|1              (default 0) clamp file ts to forced-now
     TIMEHOOK_CLAMPNSEC=0|1          (default 0) strict clamp (sec,nsec)
   ========================================================================= */

/* -------------------- options -------------------- */

typedef enum {
    MODE_PASS = 0,
    MODE_STATIC,
    MODE_OFFSET,
    MODE_FREEZE
} hook_mode_t;

static int        g_disable        = 0;
static int        g_log_enabled    = 0;
static int        g_debug          = 0;
static FILE*      g_logf           = NULL;

static int        g_timecl_enable  = 1;
static int        g_filets_enable  = 0;
static int        g_filets_clamp   = 0;
static int        g_clamp_nsec     = 0;
static int        g_all_clocks     = 0;

static hook_mode_t g_mode          = MODE_PASS;
static int64_t     g_static_epoch  = 0;
static int64_t     g_offset_epoch  = 0;

static int         g_freeze_init   = 0;
static int64_t     g_frozen_epoch  = 0;

/* re-entrance guard (thread-local) */
static __thread int g_in_hook = 0;

typedef struct {
    int saved;
} HookGuard;

static inline void GuardEnter(HookGuard* g) { g->saved = g_in_hook; g_in_hook = 1; }
static inline void GuardLeave(HookGuard* g) { g_in_hook = g->saved; }

/* -------------------- logging -------------------- */

static void vlog_impl(const char* tag, const char* fmt, va_list ap) {
    if (!g_log_enabled || !g_logf) return;
    if (g_in_hook) return; /* avoid recursion via stdio */
    g_in_hook = 1;
    fprintf(g_logf, "%s", tag);
    vfprintf(g_logf, fmt, ap);
    fflush(g_logf);
    g_in_hook = 0;
}

static void vlog(const char* fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    vlog_impl("[timehook] ", fmt, ap);
    va_end(ap);
}

static void dlog(const char* fmt, ...) {
    if (!g_debug) return;
    va_list ap;
    va_start(ap, fmt);
    vlog_impl("[timehook][dbg] ", fmt, ap);
    va_end(ap);
}

/* -------------------- env parsing -------------------- */

static long env_long(const char* name, long defv) {
    const char* v = getenv(name);
    if (!v || !*v) return defv;
    char* end = NULL;
    errno = 0;
    long x = strtol(v, &end, 10);
    if (errno != 0 || end == v) return defv;
    return x;
}

static int env_bool(const char* name, int defv) {
    const char* v = getenv(name);
    if (!v) return defv;
    return (strcmp(v, "1") == 0) ? 1 : 0;
}

static hook_mode_t parse_mode(const char* s) {
    if (!s) return MODE_PASS;
    if (strcmp(s, "static") == 0) return MODE_STATIC;
    if (strcmp(s, "offset") == 0) return MODE_OFFSET;
    if (strcmp(s, "freeze") == 0) return MODE_FREEZE;
    return MODE_PASS;
}

static const char* mode_name(hook_mode_t m) {
    switch (m) {
        case MODE_STATIC: return "static";
        case MODE_OFFSET: return "offset";
        case MODE_FREEZE: return "freeze";
        default:          return "pass";
    }
}

/* -------------------- raw syscalls (NO libc dependency) -------------------- */

#ifndef SYS_clock_gettime
# ifdef __NR_clock_gettime
#  define SYS_clock_gettime __NR_clock_gettime
# endif
#endif

#ifndef SYS_gettimeofday
# ifdef __NR_gettimeofday
#  define SYS_gettimeofday __NR_gettimeofday
# endif
#endif

#ifndef SYS_time
# ifdef __NR_time
#  define SYS_time __NR_time
# endif
#endif

static inline long RawSyscall(long nr, long a0, long a1, long a2, long a3, long a4, long a5) {
#if defined(__linux__)
    return (long)syscall(nr, a0, a1, a2, a3, a4, a5);
#else
    (void)nr; (void)a0; (void)a1; (void)a2; (void)a3; (void)a4; (void)a5;
    errno = ENOSYS;
    return -1;
#endif
}

/* -------------------- timecl engine -------------------- */

typedef struct { int64_t sec; int64_t nsec; } NowSpec;

static int HostNowTimespec(struct timespec* out) {
    if (!out) return 0;

#if defined(__linux__)
# ifdef SYS_clock_gettime
    if ((long)SYS_clock_gettime >= 0) {
        long rc = RawSyscall((long)SYS_clock_gettime, (long)CLOCK_REALTIME, (long)out, 0,0,0,0);
        if (rc == 0) return 1;
    }
# endif

# ifdef SYS_gettimeofday
    if ((long)SYS_gettimeofday >= 0) {
        struct timeval tv;
        long rc = RawSyscall((long)SYS_gettimeofday, (long)&tv, 0,0,0,0,0);
        if (rc == 0) {
            out->tv_sec  = tv.tv_sec;
            out->tv_nsec = (long)tv.tv_usec * 1000L;
            return 1;
        }
    }
# endif

# ifdef SYS_time
    if ((long)SYS_time >= 0) {
        long t = RawSyscall((long)SYS_time, 0,0,0,0,0,0);
        if (t >= 0) {
            out->tv_sec = (time_t)t;
            out->tv_nsec = 0;
            return 1;
        }
    }
# endif
#endif

    return 0;
}

static int64_t EnsureFreezeInitFromHostNow(void) {
    if (g_mode != MODE_FREEZE) return 0;
    if (!g_freeze_init) {
        struct timespec ts;
        if (HostNowTimespec(&ts)) g_frozen_epoch = (int64_t)ts.tv_sec;
        else g_frozen_epoch = 0;
        g_freeze_init = 1;
        dlog("freeze init: frozen_epoch=%lld\n", (long long)g_frozen_epoch);
    }
    return g_frozen_epoch;
}

static int64_t ChooseEpoch_Time(int64_t real_epoch) {
    if (g_mode == MODE_STATIC) return g_static_epoch;
    if (g_mode == MODE_OFFSET) return real_epoch + g_offset_epoch;
    if (g_mode == MODE_FREEZE) {
        if (!g_freeze_init) { g_frozen_epoch = real_epoch; g_freeze_init = 1; }
        return g_frozen_epoch;
    }
    return real_epoch;
}

static int64_t ChooseEpoch_File(int64_t real_epoch) {
    if (g_mode == MODE_STATIC) return g_static_epoch;
    if (g_mode == MODE_OFFSET) return real_epoch + g_offset_epoch;
    if (g_mode == MODE_FREEZE) { EnsureFreezeInitFromHostNow(); return g_frozen_epoch; }
    return real_epoch;
}

static int ShouldForceClock(clockid_t clk_id) {
    if (g_all_clocks) return 1;
    return (clk_id == CLOCK_REALTIME)
#ifdef CLOCK_REALTIME_COARSE
        || (clk_id == CLOCK_REALTIME_COARSE)
#endif
#ifdef CLOCK_TAI
        || (clk_id == CLOCK_TAI)
#endif
        ;
}

/* static/freeze direct; offset via host_now + offset; no libc time() */
static NowSpec ForcedNowSpec(void) {
    if (g_mode == MODE_STATIC) return (NowSpec){ g_static_epoch, 0 };
    if (g_mode == MODE_FREEZE) return (NowSpec){ EnsureFreezeInitFromHostNow(), 0 };

    struct timespec host;
    if (!HostNowTimespec(&host)) return (NowSpec){0,0};

    if (g_mode == MODE_PASS) return (NowSpec){ (int64_t)host.tv_sec, (int64_t)host.tv_nsec };

    /* MODE_OFFSET: map host wallclock through ChooseEpoch_Time */
    return (NowSpec){ ChooseEpoch_Time((int64_t)host.tv_sec), (int64_t)host.tv_nsec };
}

/* optional strict clamp on (sec,nsec) */
static inline void ClampSecNsec(int64_t* sec, int64_t* nsec, const NowSpec* now) {
    if (!g_filets_clamp || !sec || !nsec || !now) return;

    if (!g_clamp_nsec) {
        if (*sec > now->sec) { *sec = now->sec; *nsec = now->nsec; }
        return;
    }

    if (*sec > now->sec || (*sec == now->sec && *nsec > now->nsec)) {
        *sec = now->sec;
        *nsec = now->nsec;
    }
}

/* -------------------- filets engine -------------------- */

static inline void AdjustTimespec_Read(struct timespec* ts, const NowSpec* now_view) {
    if (!ts || g_mode == MODE_PASS) return;

#ifdef UTIME_NOW
    /* On read side: UTIME_NOW/OMIT should not appear in stat buffers, but keep safe */
    if (ts->tv_nsec == UTIME_NOW || ts->tv_nsec == UTIME_OMIT) return;
#endif

    int64_t sec  = ChooseEpoch_File((int64_t)ts->tv_sec);   /* disk -> view */
    int64_t nsec = (int64_t)ts->tv_nsec;

    if (g_mode == MODE_STATIC || g_mode == MODE_FREEZE) nsec = 0;

    ClampSecNsec(&sec, &nsec, now_view);

    ts->tv_sec  = (time_t)sec;
    ts->tv_nsec = (long)nsec;
}

static inline void AdjustTimeval_Read(struct timeval* tv, const NowSpec* now_view) {
    if (!tv || g_mode == MODE_PASS) return;

    int64_t sec  = ChooseEpoch_File((int64_t)tv->tv_sec);
    int64_t nsec = (int64_t)tv->tv_usec * 1000LL;

    if (g_mode == MODE_STATIC || g_mode == MODE_FREEZE) nsec = 0;

    ClampSecNsec(&sec, &nsec, now_view);

    tv->tv_sec  = (time_t)sec;
    tv->tv_usec = (suseconds_t)(nsec / 1000LL);
}

static void AdjustStat_Read(struct stat* st, const NowSpec* now_view) {
    if (!st || g_mode == MODE_PASS) return;
    AdjustTimespec_Read(&st->st_atim, now_view);
    AdjustTimespec_Read(&st->st_mtim, now_view);
    AdjustTimespec_Read(&st->st_ctim, now_view);
}

/* statx fallback (no need for <linux/stat.h>) */
#ifdef __linux__
#ifndef STATX_BASIC_STATS
#ifndef STATX_ATIME
#define STATX_ATIME       0x00000020U
#define STATX_MTIME       0x00000040U
#define STATX_CTIME       0x00000080U
#define STATX_BTIME       0x00000800U
#define STATX_BASIC_STATS 0x000007ffU

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
#endif /* STATX_BASIC_STATS */
#endif /* __linux__ */

#ifdef __linux__
static inline void AdjustStatxTs_Read(struct statx_timestamp* t, const NowSpec* now_view) {
    if (!t || g_mode == MODE_PASS) return;

    int64_t sec  = ChooseEpoch_File((int64_t)t->tv_sec);
    int64_t nsec = (int64_t)t->tv_nsec;

    if (g_mode == MODE_STATIC || g_mode == MODE_FREEZE) nsec = 0;

    ClampSecNsec(&sec, &nsec, now_view);

    t->tv_sec  = (int64_t)sec;
    t->tv_nsec = (uint32_t)nsec;
}

/* patch_mask = stx_mask & requested_mask */
static void AdjustStatx_Read(struct statx* sx, unsigned int requested_mask, const NowSpec* now_view) {
    if (!sx || g_mode == MODE_PASS) return;

    unsigned int patch_mask = sx->stx_mask & requested_mask;

    if (patch_mask & STATX_ATIME) AdjustStatxTs_Read(&sx->stx_atime, now_view);
    if (patch_mask & STATX_MTIME) AdjustStatxTs_Read(&sx->stx_mtime, now_view);
    if (patch_mask & STATX_CTIME) AdjustStatxTs_Read(&sx->stx_ctime, now_view);
#ifdef STATX_BTIME
    if (patch_mask & STATX_BTIME) AdjustStatxTs_Read(&sx->stx_btime, now_view);
#endif
}
#endif

static inline void MapTimespec_Write(struct timespec* ts_disk,
                                    const struct timespec* ts_view_in,
                                    const NowSpec* now_view) {
    /* ts_view_in: user-provided in "view domain" (application-visible) */
    /* ts_disk: what we will pass to kernel */
    *ts_disk = *ts_view_in;

#ifdef UTIME_NOW
    if (ts_view_in->tv_nsec == UTIME_OMIT) {
        return; /* pass through */
    }
    if (ts_view_in->tv_nsec == UTIME_NOW) {
        /* UTIME_NOW means "set to real current time".
           Under hooks, our "forced now" is now_view (view domain).
           For MODE_OFFSET we must write (view - offset) to disk. */
        int64_t sec = now_view->sec;
        int64_t nsec = now_view->nsec;
        if (g_mode == MODE_OFFSET) sec -= g_offset_epoch; /* view -> disk */

        /* clamp must be in disk domain for write path */
        NowSpec clamp_now = *now_view;
        if (g_mode == MODE_OFFSET) clamp_now.sec -= g_offset_epoch;

        ClampSecNsec(&sec, &nsec, &clamp_now);

        ts_disk->tv_sec  = (time_t)sec;
        ts_disk->tv_nsec = (long)nsec;
        return;
    }
#endif

    /* explicit timestamp: input is view-domain */
    int64_t sec  = (int64_t)ts_view_in->tv_sec;
    int64_t nsec = (int64_t)ts_view_in->tv_nsec;

    if (g_mode == MODE_OFFSET) {
        /* view -> disk */
        sec -= g_offset_epoch;
    } else {
        /* static/freeze: deliberately force */
        sec = ChooseEpoch_File(sec);
    }

    if (g_mode == MODE_STATIC || g_mode == MODE_FREEZE) nsec = 0;

    /* clamp compares against forced-now in view domain;
       convert forced-now to disk domain if MODE_OFFSET */
    NowSpec clamp_now = *now_view;
    if (g_mode == MODE_OFFSET) clamp_now.sec -= g_offset_epoch;

    ClampSecNsec(&sec, &nsec, &clamp_now);

    ts_disk->tv_sec  = (time_t)sec;
    ts_disk->tv_nsec = (long)nsec;
}

static inline void MapTimeval_Write(struct timeval* tv_disk,
                                   const struct timeval* tv_view_in,
                                   const NowSpec* now_view) {
    /* Convert timeval to nsec for clamp logic */
    int64_t sec  = (int64_t)tv_view_in->tv_sec;
    int64_t nsec = (int64_t)tv_view_in->tv_usec * 1000LL;

    if (g_mode == MODE_OFFSET) {
        sec -= g_offset_epoch; /* view -> disk */
    } else {
        sec = ChooseEpoch_File(sec);
    }

    if (g_mode == MODE_STATIC || g_mode == MODE_FREEZE) nsec = 0;

    NowSpec clamp_now = *now_view;
    if (g_mode == MODE_OFFSET) clamp_now.sec -= g_offset_epoch;

    ClampSecNsec(&sec, &nsec, &clamp_now);

    tv_disk->tv_sec  = (time_t)sec;
    tv_disk->tv_usec = (suseconds_t)(nsec / 1000LL);
}

/* -------------------- optional: time-path logging -------------------- */

static int is_time_path(const char* p) {
    if (!p) return 0;
    return (strncmp(p, "/proc/uptime", 11) == 0) ||
           (strncmp(p, "/proc/stat", 9) == 0) ||
           (strncmp(p, "/proc/self/stat", 14) == 0) ||
           (strncmp(p, "/sys/class/rtc/", 15) == 0) ||
           (strncmp(p, "/etc/localtime", 13) == 0) ||
           (strncmp(p, "/etc/timezone", 13) == 0) ||
           (strncmp(p, "/usr/share/zoneinfo/", 20) == 0);
}

/* -------------------- real function pointers -------------------- */

static int   (*real_clock_gettime)(clockid_t, struct timespec*) = NULL;
static int   (*real_gettimeofday)(struct timeval*, void*) = NULL;
static time_t(*real_time_fn)(time_t*) = NULL;

static int   (*real_fstat)(int, struct stat*) = NULL;
static int   (*real_newfstatat)(int, const char*, struct stat*, int) = NULL;
static int   (*real_fstatat)(int, const char*, struct stat*, int) = NULL;
static int   (*real_stat)(const char*, struct stat*) = NULL;
static int   (*real_lstat)(const char*, struct stat*) = NULL;

#ifdef __linux__
static int   (*real_statx)(int, const char*, int, unsigned int, struct statx*) = NULL;
#endif

static int   (*real_utimensat)(int, const char*, const struct timespec[2], int) = NULL;
static int   (*real_futimens)(int, const struct timespec[2]) = NULL;
static int   (*real_utimes)(const char*, const struct timeval[2]) = NULL;
static int   (*real_utime)(const char*, const struct utimbuf*) = NULL;

static int   (*real_openat)(int, const char*, int, ...) = NULL;

#ifdef __GLIBC__
static int   (*real___xstat)(int, const char*, struct stat*) = NULL;
static int   (*real___lxstat)(int, const char*, struct stat*) = NULL;
static int   (*real___fxstatat)(int, int, const char*, struct stat*, int) = NULL;
#endif

/* Extra compat symbols */
#ifdef __GLIBC__
#ifdef __linux__
static int (*real___statx)(int, const char*, int, unsigned int, struct statx*) = NULL;
static int (*real___statx_time64)(int, const char*, int, unsigned int, struct statx*) = NULL;
#endif
#endif

typedef struct {
    const char* name;
    void**      out;
} SymSpec;

static void* must_dlsym(const char* name) {
    /* During dlsym, avoid recursion */
    int saved = g_in_hook;
    g_in_hook = 1;
    void* p = dlsym(RTLD_NEXT, name);
    g_in_hook = saved;
    return p;
}

static void ResolveSymbols(void) {
    SymSpec syms[] = {
        { "clock_gettime", (void**)&real_clock_gettime },
        { "gettimeofday",  (void**)&real_gettimeofday  },
        { "time",          (void**)&real_time_fn       },

        { "fstat",         (void**)&real_fstat         },
        { "newfstatat",    (void**)&real_newfstatat    },
        { "fstatat",       (void**)&real_fstatat       },
        { "stat",          (void**)&real_stat          },
        { "lstat",         (void**)&real_lstat         },

#ifdef __linux__
        { "statx",         (void**)&real_statx         },
#endif
        { "utimensat",     (void**)&real_utimensat     },
        { "futimens",      (void**)&real_futimens      },
        { "utimes",        (void**)&real_utimes        },
        { "utime",         (void**)&real_utime         },

        { "openat",        (void**)&real_openat        },

#ifdef __GLIBC__
        { "__xstat",       (void**)&real___xstat       },
        { "__lxstat",      (void**)&real___lxstat      },
        { "__fxstatat",    (void**)&real___fxstatat    },
#endif

#ifdef __GLIBC__
#ifdef __linux__
        { "__statx",       (void**)&real___statx       },
        { "__statx_time64",(void**)&real___statx_time64},
#endif
#endif
    };

    for (size_t i = 0; i < sizeof(syms)/sizeof(syms[0]); i++) {
        if (!*syms[i].out) {
            *syms[i].out = must_dlsym(syms[i].name);
        }
    }
}

/* -------------------- constructor -------------------- */

static void init_real(void) {
    static int inited = 0;
    if (inited) return;
    inited = 1;

    /* Read env */
    g_disable       = env_bool("TIMEHOOK_DISABLE", 0);
    g_log_enabled   = env_bool("TIMEHOOK_LOG_ENABLE", 0);
    g_debug         = env_bool("TIMEHOOK_DEBUG", 0);

    g_timecl_enable = env_bool("TIMEHOOK_TIMECL", 1);
    g_filets_enable = env_bool("TIMEHOOK_FILETS", 0);
    g_filets_clamp  = env_bool("TIMEHOOK_CLAMP",  0);
    g_clamp_nsec    = env_bool("TIMEHOOK_CLAMPNSEC", 0);
    g_all_clocks    = env_bool("TIMEHOOK_ALLCLOCKS", 0);

    g_mode = parse_mode(getenv("TIMEHOOK_MODE"));

    /* epoch semantics: one value depending on mode */
    int64_t epochv = (int64_t)env_long("TIMEHOOK_EPOCH", 0);

    g_static_epoch = 0;
    g_offset_epoch = 0;
    if (g_mode == MODE_STATIC) g_static_epoch = epochv;
    if (g_mode == MODE_OFFSET) g_offset_epoch = epochv;

    /* Open log */
    const char* logpath = getenv("TIMEHOOK_LOG_PATH");
    if (logpath && *logpath) {
        g_logf = fopen(logpath, "a");
        if (!g_logf) g_logf = stderr;
    } else {
        g_logf = stderr;
    }
    if (g_logf && g_logf != stderr) setvbuf(g_logf, NULL, _IOLBF, 0);

    ResolveSymbols();

    vlog("init: disable=%d log=%d debug=%d mode=%s epoch=%lld timecl=%d filets=%d clamp=%d clampnsec=%d allclocks=%d\n",
         g_disable, g_log_enabled, g_debug, mode_name(g_mode),
         (long long)((g_mode==MODE_STATIC)?g_static_epoch:(g_mode==MODE_OFFSET)?g_offset_epoch:0),
         g_timecl_enable, g_filets_enable, g_filets_clamp, g_clamp_nsec, g_all_clocks);
}

__attribute__((constructor))
static void timehook_ctor(void) {
    init_real();
}

/* -------------------- time clocks wrapping -------------------- */

time_t time(time_t* tloc) {
    init_real();
    if (!real_time_fn) { errno = ENOSYS; return (time_t)-1; }
    if (g_in_hook) return real_time_fn(tloc);

    HookGuard g; GuardEnter(&g);
    time_t real_epoch = real_time_fn(NULL);
    GuardLeave(&g);

    if (g_disable || !g_timecl_enable || g_mode == MODE_PASS) {
        if (tloc) *tloc = real_epoch;
        return real_epoch;
    }

    int64_t chosen = ChooseEpoch_Time((int64_t)real_epoch);
    if (tloc) *tloc = (time_t)chosen;

    dlog("time(): real=%ld forced=%lld\n", (long)real_epoch, (long long)chosen);
    return (time_t)chosen;
}

int gettimeofday(struct timeval* tv, void* tz) {
    init_real();
    if (!real_gettimeofday) { errno = ENOSYS; return -1; }
    if (g_in_hook) return real_gettimeofday(tv, tz);

    HookGuard g; GuardEnter(&g);
    int rc = real_gettimeofday(tv, tz);
    GuardLeave(&g);

    if (g_disable || rc != 0 || !tv) return rc;
    if (!g_timecl_enable || g_mode == MODE_PASS) return rc;

    int64_t chosen = ChooseEpoch_Time((int64_t)tv->tv_sec);
    tv->tv_sec = (time_t)chosen;
    tv->tv_usec = 0;

    dlog("gettimeofday(): forced=%lld\n", (long long)chosen);
    return rc;
}

static const char* clock_name(clockid_t clk) {
    switch (clk) {
        case CLOCK_REALTIME: return "CLOCK_REALTIME";
        case CLOCK_MONOTONIC: return "CLOCK_MONOTONIC";
#ifdef CLOCK_BOOTTIME
        case CLOCK_BOOTTIME: return "CLOCK_BOOTTIME";
#endif
#ifdef CLOCK_REALTIME_COARSE
        case CLOCK_REALTIME_COARSE: return "CLOCK_REALTIME_COARSE";
#endif
#ifdef CLOCK_MONOTONIC_COARSE
        case CLOCK_MONOTONIC_COARSE: return "CLOCK_MONOTONIC_COARSE";
#endif
#ifdef CLOCK_TAI
        case CLOCK_TAI: return "CLOCK_TAI";
#endif
        default: return "CLOCK_?(other)";
    }
}

int clock_gettime(clockid_t clk_id, struct timespec* tp) {
    init_real();
    if (!real_clock_gettime) { errno = ENOSYS; return -1; }
    if (g_in_hook) return real_clock_gettime(clk_id, tp);

    HookGuard g; GuardEnter(&g);
    int rc = real_clock_gettime(clk_id, tp);
    GuardLeave(&g);

    if (g_disable || rc != 0 || !tp) return rc;
    if (!g_timecl_enable || g_mode == MODE_PASS) return rc;
    if (!ShouldForceClock(clk_id)) return rc;

    int64_t chosen = ChooseEpoch_Time((int64_t)tp->tv_sec);
    tp->tv_sec = (time_t)chosen;
    tp->tv_nsec = 0;

    dlog("clock_gettime(%s): forced=%lld\n", clock_name(clk_id), (long long)chosen);
    return rc;
}

/* -------------------- file timestamps wrapping (read) -------------------- */

int fstat(int fd, struct stat* st) {
    init_real();
    if (!real_fstat) { errno = ENOSYS; return -1; }
    if (g_in_hook) return real_fstat(fd, st);

    HookGuard g; GuardEnter(&g);
    int rc = real_fstat(fd, st);
    GuardLeave(&g);

    if (g_disable || rc != 0 || !st) return rc;
    if (!g_filets_enable || g_mode == MODE_PASS) return rc;

    NowSpec now = ForcedNowSpec();
    AdjustStat_Read(st, &now);
    dlog("fstat(fd=%d): patched\n", fd);
    return rc;
}

int stat(const char* pathname, struct stat* st) {
    init_real();
    if (!real_stat) { errno = ENOSYS; return -1; }
    if (g_in_hook) return real_stat(pathname, st);

    HookGuard g; GuardEnter(&g);
    int rc = real_stat(pathname, st);
    GuardLeave(&g);

    if (g_disable || rc != 0 || !st) return rc;
    if (!g_filets_enable || g_mode == MODE_PASS) return rc;

    NowSpec now = ForcedNowSpec();
    AdjustStat_Read(st, &now);
    dlog("stat(%s): patched\n", pathname ? pathname : "(null)");
    return rc;
}

int lstat(const char* pathname, struct stat* st) {
    init_real();
    if (!real_lstat) { errno = ENOSYS; return -1; }
    if (g_in_hook) return real_lstat(pathname, st);

    HookGuard g; GuardEnter(&g);
    int rc = real_lstat(pathname, st);
    GuardLeave(&g);

    if (g_disable || rc != 0 || !st) return rc;
    if (!g_filets_enable || g_mode == MODE_PASS) return rc;

    NowSpec now = ForcedNowSpec();
    AdjustStat_Read(st, &now);
    dlog("lstat(%s): patched\n", pathname ? pathname : "(null)");
    return rc;
}

int newfstatat(int dirfd, const char* pathname, struct stat* st, int flags) {
    init_real();
    if (!real_newfstatat) { errno = ENOSYS; return -1; }
    if (g_in_hook) return real_newfstatat(dirfd, pathname, st, flags);

    HookGuard g; GuardEnter(&g);
    int rc = real_newfstatat(dirfd, pathname, st, flags);
    GuardLeave(&g);

    if (g_disable || rc != 0 || !st) return rc;
    if (!g_filets_enable || g_mode == MODE_PASS) return rc;

    NowSpec now = ForcedNowSpec();
    AdjustStat_Read(st, &now);
    dlog("newfstatat(%s): patched\n", pathname ? pathname : "(null)");
    return rc;
}

int fstatat(int dirfd, const char* pathname, struct stat* st, int flags) {
    init_real();
    /* fallback path */
    if (g_in_hook) {
        if (real_fstatat) return real_fstatat(dirfd, pathname, st, flags);
        if (real_newfstatat) return real_newfstatat(dirfd, pathname, st, flags);
        errno = ENOSYS; return -1;
    }

    HookGuard g; GuardEnter(&g);
    int rc;
    if (real_fstatat) rc = real_fstatat(dirfd, pathname, st, flags);
    else if (real_newfstatat) rc = real_newfstatat(dirfd, pathname, st, flags);
    else { GuardLeave(&g); errno = ENOSYS; return -1; }
    GuardLeave(&g);

    if (g_disable || rc != 0 || !st) return rc;
    if (!g_filets_enable || g_mode == MODE_PASS) return rc;

    NowSpec now = ForcedNowSpec();
    AdjustStat_Read(st, &now);
    dlog("fstatat(%s): patched\n", pathname ? pathname : "(null)");
    return rc;
}

#ifdef __linux__
int statx(int dirfd, const char* pathname, int flags, unsigned int mask, struct statx* buf) {
    init_real();
    if (!real_statx) { errno = ENOSYS; return -1; }
    if (g_in_hook) return real_statx(dirfd, pathname, flags, mask, buf);

    HookGuard g; GuardEnter(&g);
    int rc = real_statx(dirfd, pathname, flags, mask, buf);
    GuardLeave(&g);

    if (g_disable || rc != 0 || !buf) return rc;
    if (!g_filets_enable || g_mode == MODE_PASS) return rc;

    NowSpec now = ForcedNowSpec();
    AdjustStatx_Read(buf, mask, &now);
    dlog("statx(%s, mask=0x%x): patched (stx_mask=0x%x)\n",
         pathname ? pathname : "(null)", mask, buf->stx_mask);
    return rc;
}
#endif

#ifdef __GLIBC__
int __xstat(int ver, const char* pathname, struct stat* st) {
    init_real();
    if (!real___xstat) { errno = ENOSYS; return -1; }
    if (g_in_hook) return real___xstat(ver, pathname, st);

    HookGuard g; GuardEnter(&g);
    int rc = real___xstat(ver, pathname, st);
    GuardLeave(&g);

    if (g_disable || rc != 0 || !st) return rc;
    if (!g_filets_enable || g_mode == MODE_PASS) return rc;

    NowSpec now = ForcedNowSpec();
    AdjustStat_Read(st, &now);
    dlog("__xstat(ver=%d,%s): patched\n", ver, pathname ? pathname : "(null)");
    return rc;
}

int __lxstat(int ver, const char* pathname, struct stat* st) {
    init_real();
    if (!real___lxstat) { errno = ENOSYS; return -1; }
    if (g_in_hook) return real___lxstat(ver, pathname, st);

    HookGuard g; GuardEnter(&g);
    int rc = real___lxstat(ver, pathname, st);
    GuardLeave(&g);

    if (g_disable || rc != 0 || !st) return rc;
    if (!g_filets_enable || g_mode == MODE_PASS) return rc;

    NowSpec now = ForcedNowSpec();
    AdjustStat_Read(st, &now);
    dlog("__lxstat(ver=%d,%s): patched\n", ver, pathname ? pathname : "(null)");
    return rc;
}

int __fxstatat(int ver, int dirfd, const char* pathname, struct stat* st, int flags) {
    init_real();
    if (!real___fxstatat) { errno = ENOSYS; return -1; }
    if (g_in_hook) return real___fxstatat(ver, dirfd, pathname, st, flags);

    HookGuard g; GuardEnter(&g);
    int rc = real___fxstatat(ver, dirfd, pathname, st, flags);
    GuardLeave(&g);

    if (g_disable || rc != 0 || !st) return rc;
    if (!g_filets_enable || g_mode == MODE_PASS) return rc;

    NowSpec now = ForcedNowSpec();
    AdjustStat_Read(st, &now);
    dlog("__fxstatat(ver=%d,%s): patched\n", ver, pathname ? pathname : "(null)");
    return rc;
}
#endif

/* -------------------- file timestamps wrapping (write) -------------------- */

int utimensat(int dirfd, const char* pathname, const struct timespec times[2], int flags) {
    init_real();
    if (!real_utimensat) { errno = ENOSYS; return -1; }
    if (g_in_hook) return real_utimensat(dirfd, pathname, times, flags);

    if (g_disable || !g_filets_enable || g_mode == MODE_PASS) {
        HookGuard g; GuardEnter(&g);
        int rc = real_utimensat(dirfd, pathname, times, flags);
        GuardLeave(&g);
        return rc;
    }

    NowSpec now_view = ForcedNowSpec();

    struct timespec local[2];
    const struct timespec* use = times;

    if (!times) {
        /* times==NULL means "set both to real now" -> we force now_view.
           For MODE_OFFSET we must write (view - offset) to disk. */
        int64_t sec = now_view.sec;
        int64_t nsec = now_view.nsec;
        if (g_mode == MODE_OFFSET) sec -= g_offset_epoch;

        local[0].tv_sec = (time_t)sec; local[0].tv_nsec = (long)nsec;
        local[1].tv_sec = (time_t)sec; local[1].tv_nsec = (long)nsec;
        use = local;
        dlog("utimensat(times=NULL): rewrite to forced now (disk-domain if offset)\n");
    } else {
        MapTimespec_Write(&local[0], &times[0], &now_view);
        MapTimespec_Write(&local[1], &times[1], &now_view);
        use = local;
        dlog("utimensat(times[2]): rewritten\n");
    }

    HookGuard g; GuardEnter(&g);
    int rc = real_utimensat(dirfd, pathname, use, flags);
    GuardLeave(&g);

    return rc;
}

int futimens(int fd, const struct timespec times[2]) {
    init_real();
    if (!real_futimens) { errno = ENOSYS; return -1; }
    if (g_in_hook) return real_futimens(fd, times);

    if (g_disable || !g_filets_enable || g_mode == MODE_PASS) {
        HookGuard g; GuardEnter(&g);
        int rc = real_futimens(fd, times);
        GuardLeave(&g);
        return rc;
    }

    NowSpec now_view = ForcedNowSpec();

    struct timespec local[2];
    const struct timespec* use = times;

    if (!times) {
        int64_t sec = now_view.sec;
        int64_t nsec = now_view.nsec;
        if (g_mode == MODE_OFFSET) sec -= g_offset_epoch;

        local[0].tv_sec = (time_t)sec; local[0].tv_nsec = (long)nsec;
        local[1].tv_sec = (time_t)sec; local[1].tv_nsec = (long)nsec;
        use = local;
        dlog("futimens(times=NULL): rewrite\n");
    } else {
        MapTimespec_Write(&local[0], &times[0], &now_view);
        MapTimespec_Write(&local[1], &times[1], &now_view);
        use = local;
        dlog("futimens(times[2]): rewritten\n");
    }

    HookGuard g; GuardEnter(&g);
    int rc = real_futimens(fd, use);
    GuardLeave(&g);

    return rc;
}

int utimes(const char* filename, const struct timeval times[2]) {
    init_real();
    if (!real_utimes) { errno = ENOSYS; return -1; }
    if (g_in_hook) return real_utimes(filename, times);

    if (g_disable || !g_filets_enable || g_mode == MODE_PASS) {
        HookGuard g; GuardEnter(&g);
        int rc = real_utimes(filename, times);
        GuardLeave(&g);
        return rc;
    }

    NowSpec now_view = ForcedNowSpec();

    struct timeval local[2];
    const struct timeval* use = times;

    if (!times) {
        int64_t sec = now_view.sec;
        int64_t nsec = now_view.nsec;
        if (g_mode == MODE_OFFSET) sec -= g_offset_epoch;

        local[0].tv_sec = (time_t)sec; local[0].tv_usec = (suseconds_t)(nsec/1000LL);
        local[1].tv_sec = (time_t)sec; local[1].tv_usec = (suseconds_t)(nsec/1000LL);
        use = local;
        dlog("utimes(times=NULL): rewrite\n");
    } else {
        MapTimeval_Write(&local[0], &times[0], &now_view);
        MapTimeval_Write(&local[1], &times[1], &now_view);
        use = local;
        dlog("utimes(times[2]): rewritten\n");
    }

    HookGuard g; GuardEnter(&g);
    int rc = real_utimes(filename, use);
    GuardLeave(&g);

    return rc;
}

int utime(const char* filename, const struct utimbuf* times) {
    init_real();
    if (!real_utime) { errno = ENOSYS; return -1; }
    if (g_in_hook) return real_utime(filename, times);

    if (g_disable || !g_filets_enable || g_mode == MODE_PASS) {
        HookGuard g; GuardEnter(&g);
        int rc = real_utime(filename, times);
        GuardLeave(&g);
        return rc;
    }

    NowSpec now_view = ForcedNowSpec();

    struct utimbuf local;
    const struct utimbuf* use = times;

    if (!times) {
        int64_t sec = now_view.sec;
        if (g_mode == MODE_OFFSET) sec -= g_offset_epoch;
        local.actime  = (time_t)sec;
        local.modtime = (time_t)sec;
        use = &local;
        dlog("utime(times=NULL): rewrite\n");
    } else {
        /* utimbuf has seconds-only; treat like timespec with nsec=0 */
        int64_t a = (int64_t)times->actime;
        int64_t m = (int64_t)times->modtime;

        if (g_mode == MODE_OFFSET) {
            a -= g_offset_epoch;
            m -= g_offset_epoch;
        } else {
            a = ChooseEpoch_File(a);
            m = ChooseEpoch_File(m);
        }

        /* clamp: compare against forced-now (convert to disk if offset) */
        NowSpec clamp_now = now_view;
        if (g_mode == MODE_OFFSET) clamp_now.sec -= g_offset_epoch;

        int64_t a_nsec = 0, m_nsec = 0;
        ClampSecNsec(&a, &a_nsec, &clamp_now);
        ClampSecNsec(&m, &m_nsec, &clamp_now);

        local.actime  = (time_t)a;
        local.modtime = (time_t)m;
        use = &local;
        dlog("utime(times): rewritten\n");
    }

    HookGuard g; GuardEnter(&g);
    int rc = real_utime(filename, use);
    GuardLeave(&g);

    return rc;
}

/* -------------------- file timestamps wrapping (open) -------------------- */

int openat(int dirfd, const char* pathname, int flags, ...) {
    init_real();
    if (!real_openat) { errno = ENOSYS; return -1; }

    if (g_in_hook) {
        va_list ap;
        va_start(ap, flags);
        int fd;
        if (flags & O_CREAT) {
            mode_t m = (mode_t)va_arg(ap, int);
            fd = real_openat(dirfd, pathname, flags, m);
        } else {
            fd = real_openat(dirfd, pathname, flags);
        }
        va_end(ap);
        return fd;
    }

    int fd;
    HookGuard g; GuardEnter(&g);
    va_list ap;
    va_start(ap, flags);
    if (flags & O_CREAT) {
        mode_t m = (mode_t)va_arg(ap, int);
        fd = real_openat(dirfd, pathname, flags, m);
    } else {
        fd = real_openat(dirfd, pathname, flags);
    }
    va_end(ap);
    GuardLeave(&g);

    if (!g_disable && g_log_enabled && is_time_path(pathname)) {
        vlog("openat(path=%s, flags=0x%x) => fd=%d\n",
             pathname ? pathname : "(null)", flags, fd);
    }
    return fd;
}

