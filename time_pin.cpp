/*
 * Copyright (c) 2008 Jonathan-Christofer Demay (jcdemay@gmail.com)
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

#include "pin.H"

#include <fstream>
#include <string>
#include <stdint.h>
#include <sys/syscall.h>
#include <sys/time.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

/* -------------------- options -------------------- */

static std::ofstream logf;

KNOB<std::string> KnobLog(KNOB_MODE_WRITEONCE, "pintool", "log", "time_pin.log", "Log file");
KNOB<BOOL>        KnobDebug(KNOB_MODE_WRITEONCE, "pintool", "debug", "0", "Minimal debug logs");

enum Mode { MODE_PASS=0, MODE_STATIC, MODE_OFFSET, MODE_FREEZE };

static Mode  g_mode = MODE_PASS;

static bool  g_timecl_enable   = true;   // -timecl
static bool  g_filets_enabled  = false;  // -filets
static bool  g_filets_clamp    = false;  // -clamp
static bool  g_clamp_nsec      = false;  // -clampnsec
static bool  g_debug           = false;  // -debug
static bool  g_all_clocks      = false;  // -allclocks

static bool  g_freeze_init     = false;
static INT64 g_static_epoch    = 0;
static INT64 g_offset_epoch    = 0;
static INT64 g_frozen_epoch    = 0;

KNOB<std::string> KnobMode(KNOB_MODE_WRITEONCE, "pintool", "mode", "pass", "pass|static|offset|freeze");
KNOB<INT64>       KnobEpoch(KNOB_MODE_WRITEONCE, "pintool", "epoch", "0", "Epoch value/offset in seconds");
KNOB<BOOL>        KnobFreeze(KNOB_MODE_WRITEONCE, "pintool", "freeze", "0", "Freeze at first wall-clock seen value");
KNOB<BOOL>        KnobAllClocks(KNOB_MODE_WRITEONCE, "pintool", "allclocks", "0", "Also force monotonic/other clocks");
KNOB<BOOL>        KnobTimeCL(KNOB_MODE_WRITEONCE, "pintool", "timecl", "1", "Enable time clocks forcing");
KNOB<BOOL>        KnobFileTS(KNOB_MODE_WRITEONCE, "pintool", "filets", "0", "Enable file timestamps forcing");
KNOB<BOOL>        KnobClamp(KNOB_MODE_WRITEONCE, "pintool", "clamp", "0", "Clamp file timestamps to forced-now");
KNOB<BOOL>        KnobClampNSec(KNOB_MODE_WRITEONCE, "pintool", "clampnsec", "0", "Strict clamp on (sec,nsec)");

/* -------------------- TLS state -------------------- */

struct ThreadState {
    int  inwrap;
    // utimensat rewriting
    struct timespec tsbuf[2];
    // syscall args cache (ENTRY -> EXIT), critical for static binaries
    ADDRINT  pending_stat_ptr;     // struct stat*
    ADDRINT  pending_statx_ptr;    // struct statx*
    uint32_t pending_statx_mask;   // requested_mask for statx
};

static TLS_KEY g_tls_key;

static inline ThreadState* TS(THREADID tid) {
    return static_cast<ThreadState*>(PIN_GetThreadData(g_tls_key, tid));
}

static VOID ThreadStart(THREADID tid, CONTEXT*, INT32, VOID*) {
    ThreadState* s = new ThreadState();
    s->inwrap = 0;
    s->tsbuf[0] = {0,0};
    s->tsbuf[1] = {0,0};

    s->pending_stat_ptr = 0;
    s->pending_statx_ptr = 0;
    s->pending_statx_mask = 0;

    PIN_SetThreadData(g_tls_key, s, tid);
}

static VOID ThreadFini(THREADID tid, const CONTEXT*, INT32, VOID*) {
    delete TS(tid);
    PIN_SetThreadData(g_tls_key, nullptr, tid);
}

struct ThreadGuard {
    ThreadState* s;
    explicit ThreadGuard(ThreadState* st) : s(st) { if (s) s->inwrap = 1; }
    ~ThreadGuard() { if (s) s->inwrap = 0; }
    ThreadGuard(const ThreadGuard&) = delete;
    ThreadGuard& operator=(const ThreadGuard&) = delete;
};

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

/* -------------------- raw syscalls helpers (no libc dependency) -------------------- */

static inline long RawSyscall(long nr, long a0=0, long a1=0, long a2=0, long a3=0, long a4=0, long a5=0) {
#if defined(__linux__)
    return (long)syscall(nr, a0, a1, a2, a3, a4, a5);
#else
    (void)nr; (void)a0; (void)a1; (void)a2; (void)a3; (void)a4; (void)a5;
    return -1;
#endif
}

/* -------------------- hook structures -------------------- */

enum HookGate : uint32_t {
    GATE_NONE   = 0,
    GATE_TIMECL = 1u << 0,
    GATE_FILETS = 1u << 1,
};
enum SysPhase : uint8_t {
    PH_NONE  = 0,
    PH_ENTRY = 1,
    PH_LEAVE = 2,
    PH_BOTH  = 3,
};

struct SyscallSpec;

using SysEntryFn = void (*)(THREADID, CONTEXT*, SYSCALL_STANDARD, ThreadState*, const SyscallSpec&, long nr);
using SysExitFn  = void (*)(THREADID, CONTEXT*, SYSCALL_STANDARD, ThreadState*, const SyscallSpec&, long nr);

struct SyscallSpec {
    long      nr;              // syscall number or NR_ANY wildcard or -1 if absent
    uint8_t   phase;           // PH_ENTRY / PH_LEAVE
    uint8_t   require_success; // if 1 dispatcher skips handler when return < 0
    uint8_t   a0;              // generic arg index
    uint8_t   a1;              // generic arg index
    uint8_t   a2;              // generic arg index
    SysEntryFn on_entry;
    SysExitFn  on_exit;
    uint8_t   skip_if_inwrap_entry = 0; // if 1 dispatcher skips ENTRY handler when st->inwrap
    uint8_t   skip_if_inwrap_exit = 0;  // if 1 dispatcher skips EXIT handler when st->inwrap
};

struct HookEntry {
    const char* id;
    uint32_t gate;
    // RTN part (dynamic)
    AFUNPTR  wrapper;           // may be nullptr
    PROTO (*proto_maker)();     // may be nullptr
    int      rtn_argc;          // ignored if wrapper == nullptr
    const char* rtn_names[24];  // inline (no side arrays)
    uint8_t  rtn_count;
    // Syscall part (static)
    SyscallSpec sys[24];        // inline (no side arrays)
    uint8_t  sys_count;
    // cached proto
    PROTO proto;
};

static inline bool GateEnabled(uint32_t gate) {
    if ((gate & GATE_TIMECL) && !g_timecl_enable) return false;
    if ((gate & GATE_FILETS) && !g_filets_enabled) return false;
    return true;
}

static inline bool SysRetIsError(long ret) { return (ret < 0); }

/* -------------------- shared engines -------------------- */

/* Special wildcard for syscall dispatcher */
static const long NR_ANY = -2L;

/* ForcedNow (sec,nsec) based on raw syscalls */
struct NowSpec { INT64 sec; INT64 nsec; };

/* forward declarations */
static bool  HostNowTimespec(struct timespec* out);

static INT64 EnsureFreezeInitFromHostNow();
static INT64 ChooseEpoch_Time(INT64 real_epoch);
static INT64 ChooseEpoch_File(INT64 real_epoch);
static bool  ShouldForceClock(ADDRINT clk_id);

static NowSpec ForcedNowSpec();
static inline void ClampSecNsec(INT64& sec, INT64& nsec, const NowSpec& now);
static void AdjustStatBuf(ADDRINT st_ptr, const NowSpec& now);
static void AdjustStatxBuf(ADDRINT stx_ptr, uint32_t requested_mask, const NowSpec& now);
static void SysEntry_CacheStatPtr(THREADID, CONTEXT* ctx, SYSCALL_STANDARD std, ThreadState* st, const SyscallSpec& sp, long);
static void SysEntry_CacheStatxPtr(THREADID, CONTEXT* ctx, SYSCALL_STANDARD std, ThreadState* st, const SyscallSpec& sp, long);

/* -------------------- RTN replace helper -------------------- */

static void TryReplace(IMG img, const char* name, AFUNPTR repl, PROTO proto, int argc) {
    RTN rtn = RTN_FindByName(img, name);
    if (!RTN_Valid(rtn)) return;

    if (argc == 1) {
        RTN_ReplaceSignature(rtn, repl,
            IARG_PROTOTYPE, proto,
            IARG_THREAD_ID, IARG_CONTEXT, IARG_ORIG_FUNCPTR,
            IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
            IARG_END);
    } else if (argc == 2) {
        RTN_ReplaceSignature(rtn, repl,
            IARG_PROTOTYPE, proto,
            IARG_THREAD_ID, IARG_CONTEXT, IARG_ORIG_FUNCPTR,
            IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
            IARG_FUNCARG_ENTRYPOINT_VALUE, 1,
            IARG_END);
    } else if (argc == 3) {
        RTN_ReplaceSignature(rtn, repl,
            IARG_PROTOTYPE, proto,
            IARG_THREAD_ID, IARG_CONTEXT, IARG_ORIG_FUNCPTR,
            IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
            IARG_FUNCARG_ENTRYPOINT_VALUE, 1,
            IARG_FUNCARG_ENTRYPOINT_VALUE, 2,
            IARG_END);
    } else if (argc == 4) {
        RTN_ReplaceSignature(rtn, repl,
            IARG_PROTOTYPE, proto,
            IARG_THREAD_ID, IARG_CONTEXT, IARG_ORIG_FUNCPTR,
            IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
            IARG_FUNCARG_ENTRYPOINT_VALUE, 1,
            IARG_FUNCARG_ENTRYPOINT_VALUE, 2,
            IARG_FUNCARG_ENTRYPOINT_VALUE, 3,
            IARG_END);
    } else if (argc == 5) {
        RTN_ReplaceSignature(rtn, repl,
            IARG_PROTOTYPE, proto,
            IARG_THREAD_ID, IARG_CONTEXT, IARG_ORIG_FUNCPTR,
            IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
            IARG_FUNCARG_ENTRYPOINT_VALUE, 1,
            IARG_FUNCARG_ENTRYPOINT_VALUE, 2,
            IARG_FUNCARG_ENTRYPOINT_VALUE, 3,
            IARG_FUNCARG_ENTRYPOINT_VALUE, 4,
            IARG_END);
    } else {
        return;
    }

    if (g_debug) logf << "[pin][dbg] replaced RTN: " << name << "\n";
}

/* -------------------- ENTRY->EXIT cache (needed for static) -------------------- */

static inline void ClearPending(ThreadState* st) {
    if (!st) return;
    st->pending_stat_ptr = 0;
    st->pending_statx_ptr = 0;
    st->pending_statx_mask = 0;
}

static void SysEntry_ClearPending(THREADID, CONTEXT*, SYSCALL_STANDARD, ThreadState* st,
                                  const SyscallSpec&, long) {
    ClearPending(st);
}

static void SysExit_PatchFromPending(THREADID, CONTEXT* ctx, SYSCALL_STANDARD std, ThreadState* st,
                                     const SyscallSpec&, long) {
    if (!st) return;
    if (!st->pending_stat_ptr && !st->pending_statx_ptr) return;

    if (!g_filets_enabled || g_mode == MODE_PASS) {
        ClearPending(st);
        return;
    }

    long sret = (long)PIN_GetSyscallReturn(ctx, std);
    if (sret != 0) {
        // stat-like/statx return 0 on success
        if (g_debug) logf << "[pin][dbg] pending patch skipped (ret=" << sret << ")\n";
        ClearPending(st);
        return;
    }

    NowSpec now = ForcedNowSpec();

    if (st->pending_statx_ptr) {
        AdjustStatxBuf(st->pending_statx_ptr, st->pending_statx_mask, now);
        if (g_debug) logf << "[pin][dbg] syscall patched statx (entry-cached)\n";
        st->pending_statx_ptr = 0;
        st->pending_statx_mask = 0;
        st->pending_stat_ptr = 0;
        return;
    }

    if (st->pending_stat_ptr) {
        AdjustStatBuf(st->pending_stat_ptr, now);
        if (g_debug) logf << "[pin][dbg] syscall patched stat-like (entry-cached)\n";
        st->pending_stat_ptr = 0;
        return;
    }
}

static HookEntry Hook_SyscallCacheCore = {
    "syscall-cache-core",
    GATE_NONE,

    nullptr, nullptr, 0,
    { }, 0,

    {
        { NR_ANY, PH_ENTRY, 0, 0,0,0, &SysEntry_ClearPending, nullptr },
        { NR_ANY, PH_LEAVE, 0, 0,0,0, nullptr, &SysExit_PatchFromPending },
    }, 2,

    nullptr
};

/* -------------------- SYS/NR TIME -------------------- */

#ifndef SYS_time
# ifdef __NR_time
#  define SYS_time __NR_time
# endif
#endif

#ifdef SYS_time
# define NR_TIME ((long)SYS_time)
#else
# define NR_TIME (-1L)
#endif

static PROTO PM_Time1() {
    return PROTO_Allocate(PIN_PARG(ADDRINT), CALLINGSTD_DEFAULT, "time",
                          PIN_PARG(ADDRINT), PIN_PARG_END());
}

static ADDRINT Wrap_Time(THREADID tid, CONTEXT* ctx, AFUNPTR orig, ADDRINT tloc_ptr) {
    ThreadState* st = TS(tid);
    if (st && st->inwrap) {
        ADDRINT ret = 0;
        PIN_CallApplicationFunction(ctx, tid, CALLINGSTD_DEFAULT, orig, NULL,
            PIN_PARG(ADDRINT), &ret,
            PIN_PARG(ADDRINT), tloc_ptr,
            PIN_PARG_END());
        return ret;
    }
    ThreadGuard g(st);

    ADDRINT ret = 0;
    PIN_CallApplicationFunction(ctx, tid, CALLINGSTD_DEFAULT, orig, NULL,
        PIN_PARG(ADDRINT), &ret,
        PIN_PARG(ADDRINT), tloc_ptr,
        PIN_PARG_END());

    INT64 real = (INT64)ret;
    INT64 chosen = (g_timecl_enable && g_mode != MODE_PASS) ? ChooseEpoch_Time(real) : real;

    ret = (ADDRINT)chosen;
    if (tloc_ptr) {
        time_t v = (time_t)chosen;
        PIN_SafeCopy((void*)tloc_ptr, &v, sizeof(v));
    }
    if (g_debug) logf << "[pin][dbg] RTN time forced=" << chosen << "\n";
    return ret;
}

static void SysExit_Time(THREADID tid, CONTEXT* ctx, SYSCALL_STANDARD std, ThreadState* st,
                                   const SyscallSpec& sp, long nr) {
    (void)tid; (void)nr; (void)sp;
    if (!g_timecl_enable || g_mode == MODE_PASS) return;
    if (st && st->inwrap) return;

    long ret = (long)PIN_GetSyscallReturn(ctx, std);
    INT64 chosen = ChooseEpoch_Time((INT64)ret);

    PIN_SetSyscallReturn(ctx, std, (ADDRINT)chosen);

    // optional tloc pointer is arg0
    ADDRINT tloc_ptr = PIN_GetSyscallArgument(ctx, std, 0);
    if (tloc_ptr) {
        time_t v = (time_t)chosen;
        PIN_SafeCopy((void*)tloc_ptr, &v, sizeof(v));
    }

    if (g_debug) logf << "[pin][dbg] syscall time forced=" << chosen << "\n";
}

static HookEntry Hook_Time = {
    "time",
    GATE_TIMECL,

    AFUNPTR(Wrap_Time), &PM_Time1, 1,
    { "time", "__time" }, 2,

    {
        { NR_TIME, PH_LEAVE, 1, 0,0,0, nullptr, &SysExit_Time },
    }, 1,

    nullptr
};

/* -------------------- SYS/NR GETTIMEOFDAY -------------------- */

#ifndef SYS_gettimeofday
# ifdef __NR_gettimeofday
#  define SYS_gettimeofday __NR_gettimeofday
# endif
#endif

#ifdef SYS_gettimeofday
# define NR_GETTIMEOFDAY ((long)SYS_gettimeofday)
#else
# define NR_GETTIMEOFDAY (-1L)
#endif

static PROTO PM_GetTimeOfDay2() {
    return PROTO_Allocate(PIN_PARG(int), CALLINGSTD_DEFAULT, "gettimeofday",
                          PIN_PARG(ADDRINT), PIN_PARG(ADDRINT), PIN_PARG_END());
}

static int Wrap_GetTimeOfDay(THREADID tid, CONTEXT* ctx, AFUNPTR orig, ADDRINT tv_ptr, ADDRINT tz_ptr) {
    ThreadState* st = TS(tid);
    if (st && st->inwrap) {
        int rc = -1;
        PIN_CallApplicationFunction(ctx, tid, CALLINGSTD_DEFAULT, orig, NULL,
            PIN_PARG(int), &rc,
            PIN_PARG(ADDRINT), tv_ptr,
            PIN_PARG(ADDRINT), tz_ptr,
            PIN_PARG_END());
        return rc;
    }
    ThreadGuard g(st);

    int rc = -1;
    PIN_CallApplicationFunction(ctx, tid, CALLINGSTD_DEFAULT, orig, NULL,
        PIN_PARG(int), &rc,
        PIN_PARG(ADDRINT), tv_ptr,
        PIN_PARG(ADDRINT), tz_ptr,
        PIN_PARG_END());

    if (g_timecl_enable && rc == 0 && tv_ptr && g_mode != MODE_PASS) {
        struct timeval tv;
        if (PIN_SafeCopy(&tv, (void*)tv_ptr, sizeof(tv)) == sizeof(tv)) {
            INT64 chosen = ChooseEpoch_Time((INT64)tv.tv_sec);
            tv.tv_sec = (time_t)chosen;
            tv.tv_usec = 0;
            PIN_SafeCopy((void*)tv_ptr, &tv, sizeof(tv));
            if (g_debug) logf << "[pin][dbg] RTN gettimeofday forced=" << chosen << "\n";
        }
    }
    return rc;
}

static void SysExit_GetTimeOfDay(THREADID tid, CONTEXT* ctx, SYSCALL_STANDARD std, ThreadState* st,
                                     const SyscallSpec& sp, long nr) {
    (void)tid; (void)nr;
    if (!g_timecl_enable || g_mode == MODE_PASS) return;
    if (st && st->inwrap) return;

    ADDRINT tv_ptr = PIN_GetSyscallArgument(ctx, std, sp.a0);
    if (!tv_ptr) return;

    struct timeval tv;
    if (PIN_SafeCopy(&tv, (void*)tv_ptr, sizeof(tv)) != sizeof(tv)) return;

    INT64 chosen = ChooseEpoch_Time((INT64)tv.tv_sec);
    tv.tv_sec = (time_t)chosen;
    tv.tv_usec = 0;
    PIN_SafeCopy((void*)tv_ptr, &tv, sizeof(tv));

    if (g_debug) logf << "[pin][dbg] syscall gettimeofday forced=" << chosen << "\n";
}

static HookEntry Hook_GetTimeOfDay = {
    "gettimeofday",
    GATE_TIMECL,

    AFUNPTR(Wrap_GetTimeOfDay), &PM_GetTimeOfDay2, 2,
    { "gettimeofday", "__gettimeofday", "__vdso_gettimeofday" }, 3,

    {
        { NR_GETTIMEOFDAY, PH_LEAVE, 1, 0,0,0, nullptr, &SysExit_GetTimeOfDay },
    }, 1,

    nullptr
};

/* -------------------- SYS/NR CLOCK_GETTIME + clock_gettime64 fallback -------------------- */

#ifndef SYS_clock_gettime
# ifdef __NR_clock_gettime
#  define SYS_clock_gettime __NR_clock_gettime
# endif
#endif

/* clock_gettime64 fallback */
#if defined(SYS_clock_gettime64)
#define HAVE_SYS_CLOCK_GETTIME64 1
#elif defined(__NR_clock_gettime64)
#define SYS_clock_gettime64 __NR_clock_gettime64
#define HAVE_SYS_CLOCK_GETTIME64 1
#else
#define HAVE_SYS_CLOCK_GETTIME64 0
#endif

#ifdef SYS_clock_gettime
# define NR_CLOCK_GETTIME ((long)SYS_clock_gettime)
#else
# define NR_CLOCK_GETTIME (-1L)
#endif

#if HAVE_SYS_CLOCK_GETTIME64
# define NR_CLOCK_GETTIME64 ((long)SYS_clock_gettime64)
#else
# define NR_CLOCK_GETTIME64 (-1L)
#endif

static PROTO PM_ClockGetTime2() {
    return PROTO_Allocate(PIN_PARG(int), CALLINGSTD_DEFAULT, "clock_gettime",
                          PIN_PARG(ADDRINT), PIN_PARG(ADDRINT), PIN_PARG_END());
}

static int Wrap_ClockGetTime(THREADID tid, CONTEXT* ctx, AFUNPTR orig, ADDRINT clk_id, ADDRINT tp_ptr) {
    ThreadState* st = TS(tid);
    if (st && st->inwrap) {
        int rc = -1;
        PIN_CallApplicationFunction(ctx, tid, CALLINGSTD_DEFAULT, orig, NULL,
            PIN_PARG(int), &rc,
            PIN_PARG(ADDRINT), clk_id,
            PIN_PARG(ADDRINT), tp_ptr,
            PIN_PARG_END());
        return rc;
    }
    ThreadGuard g(st);

    int rc = -1;
    PIN_CallApplicationFunction(ctx, tid, CALLINGSTD_DEFAULT, orig, NULL,
        PIN_PARG(int), &rc,
        PIN_PARG(ADDRINT), clk_id,
        PIN_PARG(ADDRINT), tp_ptr,
        PIN_PARG_END());

    if (g_timecl_enable && rc == 0 && tp_ptr) {
        struct timespec ts;
        if (PIN_SafeCopy(&ts, (void*)tp_ptr, sizeof(ts)) == sizeof(ts)) {
            if (g_mode != MODE_PASS && ShouldForceClock(clk_id)) {
                INT64 chosen = ChooseEpoch_Time((INT64)ts.tv_sec);
                ts.tv_sec = (time_t)chosen;
                ts.tv_nsec = 0;
                PIN_SafeCopy((void*)tp_ptr, &ts, sizeof(ts));
                if (g_debug) logf << "[pin][dbg] RTN clock_gettime forced=" << chosen << "\n";
            }
        }
    }
    return rc;
}

static void SysExit_ClockGetTime(THREADID tid, CONTEXT* ctx, SYSCALL_STANDARD std, ThreadState* st,
                                     const SyscallSpec& sp, long nr) {
    (void)tid; (void)nr;
    if (!g_timecl_enable || g_mode == MODE_PASS) return;
    if (st && st->inwrap) return;

    ADDRINT clk    = PIN_GetSyscallArgument(ctx, std, sp.a0);
    ADDRINT ts_ptr = PIN_GetSyscallArgument(ctx, std, sp.a1);
    if (!ts_ptr) return;
    if (!ShouldForceClock(clk)) return;

    struct timespec ts;
    if (PIN_SafeCopy(&ts, (void*)ts_ptr, sizeof(ts)) != sizeof(ts)) return;

    INT64 chosen = ChooseEpoch_Time((INT64)ts.tv_sec);
    ts.tv_sec = (time_t)chosen;
    ts.tv_nsec = 0;
    PIN_SafeCopy((void*)ts_ptr, &ts, sizeof(ts));

    if (g_debug) logf << "[pin][dbg] syscall clock_gettime(nr=" << sp.nr << ") forced=" << chosen << "\n";
}

static HookEntry Hook_ClockGetTime = {
    "clock_gettime",
    GATE_TIMECL,

    AFUNPTR(Wrap_ClockGetTime), &PM_ClockGetTime2, 2,
    { "clock_gettime", "__clock_gettime", "__vdso_clock_gettime" }, 3,

    {
        { NR_CLOCK_GETTIME,   PH_LEAVE, 1, 0,1,0, nullptr, &SysExit_ClockGetTime },
        { NR_CLOCK_GETTIME64, PH_LEAVE, 1, 0,1,0, nullptr, &SysExit_ClockGetTime },
    }, 2,

    nullptr
};

/* -------------------- SYS/NR STAT/LSTAT/STAT64/LSTAT64/FSTAT -------------------- */

#ifndef SYS_stat
# ifdef __NR_stat
#  define SYS_stat __NR_stat
# endif
#endif
#ifndef SYS_lstat
# ifdef __NR_lstat
#  define SYS_lstat __NR_lstat
# endif
#endif
#ifndef SYS_stat64
# ifdef __NR_stat64
#  define SYS_stat64 __NR_stat64
# endif
#endif
#ifndef SYS_lstat64
# ifdef __NR_lstat64
#  define SYS_lstat64 __NR_lstat64
# endif
#endif
#ifndef SYS_fstat
# ifdef __NR_fstat
#  define SYS_fstat __NR_fstat
# endif
#endif

#ifdef SYS_stat
# define NR_STAT ((long)SYS_stat)
#else
# define NR_STAT (-1L)
#endif

#ifdef SYS_lstat
# define NR_LSTAT ((long)SYS_lstat)
#else
# define NR_LSTAT (-1L)
#endif

#ifdef SYS_stat64
# define NR_STAT64 ((long)SYS_stat64)
#else
# define NR_STAT64 (-1L)
#endif

#ifdef SYS_lstat64
# define NR_LSTAT64 ((long)SYS_lstat64)
#else
# define NR_LSTAT64 (-1L)
#endif

#ifdef SYS_fstat
# define NR_FSTAT ((long)SYS_fstat)
#else
# define NR_FSTAT (-1L)
#endif

static PROTO PM_Stat2() {
    return PROTO_Allocate(PIN_PARG(int), CALLINGSTD_DEFAULT, "stat2",
                          PIN_PARG(ADDRINT), PIN_PARG(ADDRINT), PIN_PARG_END());
}

/* generic stat-like: int f(x, struct stat*) */
static int Wrap_Stat2(THREADID tid, CONTEXT* ctx, AFUNPTR orig, ADDRINT a0, ADDRINT st_ptr) {
    ThreadState* st = TS(tid);
    if (st && st->inwrap) {
        int rc=-1;
        PIN_CallApplicationFunction(ctx, tid, CALLINGSTD_DEFAULT, orig, NULL,
            PIN_PARG(int), &rc,
            PIN_PARG(ADDRINT), a0,
            PIN_PARG(ADDRINT), st_ptr,
            PIN_PARG_END());
        return rc;
    }
    ThreadGuard g(st);

    int rc=-1;
    PIN_CallApplicationFunction(ctx, tid, CALLINGSTD_DEFAULT, orig, NULL,
        PIN_PARG(int), &rc,
        PIN_PARG(ADDRINT), a0,
        PIN_PARG(ADDRINT), st_ptr,
        PIN_PARG_END());

    if (rc == 0 && g_filets_enabled && g_mode != MODE_PASS) {
        NowSpec now = ForcedNowSpec();
        AdjustStatBuf(st_ptr, now);
        if (g_debug) logf << "[pin][dbg] RTN patched struct stat\n";
    }
    return rc;
}

static HookEntry Hook_Stat_Family = {
    "stat-family",
    GATE_FILETS,

    AFUNPTR(Wrap_Stat2), &PM_Stat2, 2,
    { "stat","lstat","fstat","stat64","lstat64","fstat64" }, 6,

    {
        // cache buffer pointer at ENTRY; patch happens in syscall-cache-core at EXIT
        { NR_STAT,    PH_ENTRY, 0, 1,0,0, &SysEntry_CacheStatPtr, nullptr, 1, 0 },
        { NR_LSTAT,   PH_ENTRY, 0, 1,0,0, &SysEntry_CacheStatPtr, nullptr, 1, 0 },
        { NR_STAT64,  PH_ENTRY, 0, 1,0,0, &SysEntry_CacheStatPtr, nullptr, 1, 0 },
        { NR_LSTAT64, PH_ENTRY, 0, 1,0,0, &SysEntry_CacheStatPtr, nullptr, 1, 0 },
        { NR_FSTAT,   PH_ENTRY, 0, 1,0,0, &SysEntry_CacheStatPtr, nullptr, 1, 0 },
    }, 5,

    nullptr
};

/* -------------------- SYS/NR NEWFSTATAT/FSTATAT/FSTATAT64 -------------------- */

#ifndef SYS_newfstatat
# ifdef __NR_newfstatat
#  define SYS_newfstatat __NR_newfstatat
# endif
#endif
#ifndef SYS_fstatat
# ifdef __NR_fstatat
#  define SYS_fstatat __NR_fstatat
# endif
#endif
#ifndef SYS_fstatat64
# ifdef __NR_fstatat64
#  define SYS_fstatat64 __NR_fstatat64
# endif
#endif

#ifdef SYS_newfstatat
# define NR_NEWFSTATAT ((long)SYS_newfstatat)
#else
# define NR_NEWFSTATAT (-1L)
#endif

#ifdef SYS_fstatat
# define NR_FSTATAT ((long)SYS_fstatat)
#else
# define NR_FSTATAT (-1L)
#endif

#ifdef SYS_fstatat64
# define NR_FSTATAT64 ((long)SYS_fstatat64)
#else
# define NR_FSTATAT64 (-1L)
#endif

static PROTO PM_FStatAt4() {
    return PROTO_Allocate(PIN_PARG(int), CALLINGSTD_DEFAULT, "fstatat",
                          PIN_PARG(ADDRINT), PIN_PARG(ADDRINT), PIN_PARG(ADDRINT), PIN_PARG(ADDRINT),
                          PIN_PARG_END());
}

/* fstatat-like: int f(dirfd, path, struct stat*, flags) */
static int Wrap_FStatAt(THREADID tid, CONTEXT* ctx, AFUNPTR orig,
                        ADDRINT dirfd, ADDRINT path_ptr, ADDRINT st_ptr, ADDRINT flags) {
    ThreadState* st = TS(tid);
    if (st && st->inwrap) {
        int rc=-1;
        PIN_CallApplicationFunction(ctx, tid, CALLINGSTD_DEFAULT, orig, NULL,
            PIN_PARG(int), &rc,
            PIN_PARG(ADDRINT), dirfd,
            PIN_PARG(ADDRINT), path_ptr,
            PIN_PARG(ADDRINT), st_ptr,
            PIN_PARG(ADDRINT), flags,
            PIN_PARG_END());
        return rc;
    }
    ThreadGuard g(st);

    int rc=-1;
    PIN_CallApplicationFunction(ctx, tid, CALLINGSTD_DEFAULT, orig, NULL,
        PIN_PARG(int), &rc,
        PIN_PARG(ADDRINT), dirfd,
        PIN_PARG(ADDRINT), path_ptr,
        PIN_PARG(ADDRINT), st_ptr,
        PIN_PARG(ADDRINT), flags,
        PIN_PARG_END());

    if (rc == 0 && g_filets_enabled && g_mode != MODE_PASS) {
        NowSpec now = ForcedNowSpec();
        AdjustStatBuf(st_ptr, now);
        if (g_debug) logf << "[pin][dbg] RTN patched struct stat (fstatat)\n";
    }
    return rc;
}

static HookEntry Hook_FStatAt_Family = {
    "fstatat-family",
    GATE_FILETS,

    AFUNPTR(Wrap_FStatAt), &PM_FStatAt4, 4,
    {
        "fstatat","newfstatat","fstatat64",
        "__fstatat64_time64","__fstatat_time64",
        "__GI___fstatat64_time64","__GI___fstatat_time64",
        "__libc_fstatat64","__GI___libc_fstatat64"
    }, 9,

    {
        // cache buf pointer (arg2) at ENTRY
        { NR_NEWFSTATAT, PH_ENTRY, 0, 2,0,0, &SysEntry_CacheStatPtr, nullptr, 1, 0 },
        { NR_FSTATAT,    PH_ENTRY, 0, 2,0,0, &SysEntry_CacheStatPtr, nullptr, 1, 0 },
        { NR_FSTATAT64,  PH_ENTRY, 0, 2,0,0, &SysEntry_CacheStatPtr, nullptr, 1, 0 },
    }, 3,

    nullptr
};

/* -------------------- SYS/NR STATX -------------------- */

#ifndef SYS_statx
# ifdef __NR_statx
#  define SYS_statx __NR_statx
# endif
#endif

#ifdef SYS_statx
# define NR_STATX ((long)SYS_statx)
#else
# define NR_STATX (-1L)
#endif

static PROTO PM_StatX5() {
    return PROTO_Allocate(PIN_PARG(int), CALLINGSTD_DEFAULT, "statx",
                          PIN_PARG(ADDRINT), PIN_PARG(ADDRINT), PIN_PARG(ADDRINT),
                          PIN_PARG(ADDRINT), PIN_PARG(ADDRINT), PIN_PARG_END());
}

/* statx-like: int f(dirfd, path, flags, mask, struct statx*) */
static int Wrap_StatX(THREADID tid, CONTEXT* ctx, AFUNPTR orig,
                          ADDRINT dirfd, ADDRINT path_ptr, ADDRINT flags, ADDRINT mask, ADDRINT stx_ptr) {
    ThreadState* st = TS(tid);
    if (st && st->inwrap) {
        int rc=-1;
        PIN_CallApplicationFunction(ctx, tid, CALLINGSTD_DEFAULT, orig, NULL,
            PIN_PARG(int), &rc,
            PIN_PARG(ADDRINT), dirfd,
            PIN_PARG(ADDRINT), path_ptr,
            PIN_PARG(ADDRINT), flags,
            PIN_PARG(ADDRINT), mask,
            PIN_PARG(ADDRINT), stx_ptr,
            PIN_PARG_END());
        return rc;
    }
    ThreadGuard g(st);

    int rc=-1;
    PIN_CallApplicationFunction(ctx, tid, CALLINGSTD_DEFAULT, orig, NULL,
        PIN_PARG(int), &rc,
        PIN_PARG(ADDRINT), dirfd,
        PIN_PARG(ADDRINT), path_ptr,
        PIN_PARG(ADDRINT), flags,
        PIN_PARG(ADDRINT), mask,
        PIN_PARG(ADDRINT), stx_ptr,
        PIN_PARG_END());

    if (rc == 0 && g_filets_enabled && g_mode != MODE_PASS) {
        NowSpec now = ForcedNowSpec();
        AdjustStatxBuf(stx_ptr, (uint32_t)mask, now);
        if (g_debug) logf << "[pin][dbg] RTN patched struct statx\n";
    }
    return rc;
}

static HookEntry Hook_StatX = {
    "statx",
    GATE_FILETS,

    AFUNPTR(Wrap_StatX), &PM_StatX5, 5,
    { "statx","__statx","__statx_time64","__GI___statx","__GI___statx_time64" }, 5,

    {
        // cache requested_mask (arg3) + buf (arg4) at ENTRY
        { NR_STATX, PH_ENTRY, 0, 3,4,0, &SysEntry_CacheStatxPtr, nullptr, 1, 0 },
    }, 1,

    nullptr
};

/* -------------------- GLIBC XSTAT -------------------- */

#ifdef __GLIBC__
static PROTO PM_XStat3() {
    return PROTO_Allocate(PIN_PARG(int), CALLINGSTD_DEFAULT, "__xstat",
                          PIN_PARG(ADDRINT), PIN_PARG(ADDRINT), PIN_PARG(ADDRINT), PIN_PARG_END());
}

/* __xstat(ver, path, st) and __lxstat(ver, path, st) */
static int Wrap_XStat3(THREADID tid, CONTEXT* ctx, AFUNPTR orig, ADDRINT ver, ADDRINT path_ptr, ADDRINT st_ptr) {
    ThreadState* st = TS(tid);
    if (st && st->inwrap) {
        int rc=-1;
        PIN_CallApplicationFunction(ctx, tid, CALLINGSTD_DEFAULT, orig, NULL,
            PIN_PARG(int), &rc,
            PIN_PARG(ADDRINT), ver,
            PIN_PARG(ADDRINT), path_ptr,
            PIN_PARG(ADDRINT), st_ptr,
            PIN_PARG_END());
        return rc;
    }
    ThreadGuard g(st);

    int rc=-1;
    PIN_CallApplicationFunction(ctx, tid, CALLINGSTD_DEFAULT, orig, NULL,
        PIN_PARG(int), &rc,
        PIN_PARG(ADDRINT), ver,
        PIN_PARG(ADDRINT), path_ptr,
        PIN_PARG(ADDRINT), st_ptr,
        PIN_PARG_END());

    if (rc == 0 && g_filets_enabled && g_mode != MODE_PASS) {
        NowSpec now = ForcedNowSpec();
        AdjustStatBuf(st_ptr, now);
        if (g_debug) logf << "[pin][dbg] RTN patched struct stat (__xstat)\n";
    }
    return rc;
}

static HookEntry Hook_GlibC_XStat = {
    "glibc-xstat",
    GATE_FILETS,

    AFUNPTR(Wrap_XStat3), &PM_XStat3, 3,
    { "__xstat","__lxstat","__xstat64","__lxstat64","__GI___xstat","__GI___lxstat","__GI___xstat64","__GI___lxstat64" }, 8,

    { }, 0,

    nullptr
};

/* -------------------- GLIBC FXSTATAT -------------------- */

static PROTO PM_FXStatAt5() {
    return PROTO_Allocate(PIN_PARG(int), CALLINGSTD_DEFAULT, "__fxstatat",
                          PIN_PARG(ADDRINT), PIN_PARG(ADDRINT), PIN_PARG(ADDRINT), PIN_PARG(ADDRINT), PIN_PARG(ADDRINT),
                          PIN_PARG_END());
}

/* __fxstatat(ver, dirfd, path, st, flags) */
static int Wrap_FXStatAt5(THREADID tid, CONTEXT* ctx, AFUNPTR orig,
                          ADDRINT ver, ADDRINT dirfd, ADDRINT path_ptr, ADDRINT st_ptr, ADDRINT flags) {
    ThreadState* st = TS(tid);
    if (st && st->inwrap) {
        int rc=-1;
        PIN_CallApplicationFunction(ctx, tid, CALLINGSTD_DEFAULT, orig, NULL,
            PIN_PARG(int), &rc,
            PIN_PARG(ADDRINT), ver,
            PIN_PARG(ADDRINT), dirfd,
            PIN_PARG(ADDRINT), path_ptr,
            PIN_PARG(ADDRINT), st_ptr,
            PIN_PARG(ADDRINT), flags,
            PIN_PARG_END());
        return rc;
    }
    ThreadGuard g(st);

    int rc=-1;
    PIN_CallApplicationFunction(ctx, tid, CALLINGSTD_DEFAULT, orig, NULL,
        PIN_PARG(int), &rc,
        PIN_PARG(ADDRINT), ver,
        PIN_PARG(ADDRINT), dirfd,
        PIN_PARG(ADDRINT), path_ptr,
        PIN_PARG(ADDRINT), st_ptr,
        PIN_PARG(ADDRINT), flags,
        PIN_PARG_END());

    if (rc == 0 && g_filets_enabled && g_mode != MODE_PASS) {
        NowSpec now = ForcedNowSpec();
        AdjustStatBuf(st_ptr, now);
        if (g_debug) logf << "[pin][dbg] RTN patched struct stat (__fxstatat)\n";
    }
    return rc;
}

static HookEntry Hook_GlibC_FXStatAt = {
    "glibc-fxstatat",
    GATE_FILETS,

    AFUNPTR(Wrap_FXStatAt5), &PM_FXStatAt5, 5,
    { "__fxstatat","__fxstatat64","__fxstatat64_time64","__GI___fxstatat","__GI___fxstatat64","__GI___fxstatat64_time64" }, 6,

    { }, 0,

    nullptr
};
#endif

/* -------------------- file timestamp WRITE-side mapping -------------------- */

/* -------------------- SYS/NR UTIMENSAT -------------------- */

#ifndef SYS_utimensat
# ifdef __NR_utimensat
#  define SYS_utimensat __NR_utimensat
# endif
#endif

#ifdef SYS_utimensat
# define NR_UTIMENSAT ((long)SYS_utimensat)
#else
# define NR_UTIMENSAT (-1L)
#endif

static void SysEntry_UTimeNsAt(THREADID tid, CONTEXT* ctx, SYSCALL_STANDARD std, ThreadState* st,
                              const SyscallSpec& sp, long nr) {
    (void)tid; (void)nr;
    if (!st) return;

    if (!g_filets_enabled || g_mode == MODE_PASS) return;

    ADDRINT times_ptr = PIN_GetSyscallArgument(ctx, std, sp.a0);
    NowSpec now = ForcedNowSpec();

    if (times_ptr == 0) {
        // Kernel semantics: times == NULL means "set both timestamps to *real* current time".
        // View-time is offset by +g_offset_epoch in MODE_OFFSET, so (view - offset) be must written
        // to keep write->read consistent under the hook: disk + offset == application view.
        st->tsbuf[0].tv_sec  = (time_t)now.sec;  st->tsbuf[0].tv_nsec = (long)now.nsec;
        st->tsbuf[1].tv_sec  = (time_t)now.sec;  st->tsbuf[1].tv_nsec = (long)now.nsec;

        if (g_mode == MODE_OFFSET) {
            st->tsbuf[0].tv_sec = (time_t)((INT64)st->tsbuf[0].tv_sec - g_offset_epoch);
            st->tsbuf[1].tv_sec = (time_t)((INT64)st->tsbuf[1].tv_sec - g_offset_epoch);
        }

        PIN_SetSyscallArgument(ctx, std, sp.a0, (ADDRINT)&st->tsbuf[0]);
        if (g_debug) logf << "[pin][dbg] syscall utimensat entry: times=NULL -> forced now\n";
        return;
    }

    struct timespec in[2];
    if (PIN_SafeCopy(&in, (void*)times_ptr, sizeof(in)) != sizeof(in)) return;

    for (int i = 0; i < 2; i++) {
#ifdef UTIME_NOW
        if (in[i].tv_nsec == UTIME_NOW) {
            // UTIME_NOW means "set to *real* current time".
            // Same trick as above for MODE_OFFSET: write (view - offset) to disk.
            st->tsbuf[i].tv_sec  = (time_t)now.sec;
            st->tsbuf[i].tv_nsec = (long)now.nsec;

            if (g_mode == MODE_OFFSET) {
                st->tsbuf[i].tv_sec = (time_t)((INT64)st->tsbuf[i].tv_sec - g_offset_epoch);
            }
            continue;
        }
        if (in[i].tv_nsec == UTIME_OMIT) {
            st->tsbuf[i] = in[i];
            continue;
        }
#endif
        // For explicit timestamps: in[i].tv_sec is in the application's "view time" domain.
        // - For MODE_OFFSET, (view - offset) must be written to disk so that a hooked read returns the original view.
        // - For MODE_STATIC/MODE_FREEZE, the chosen epoch is just forced in a deliberate manner with no additional logic.
        INT64 sec  = (INT64)in[i].tv_sec;
        INT64 nsec = (INT64)in[i].tv_nsec;

        if (g_mode == MODE_OFFSET) {
            // view -> disk
            sec -= g_offset_epoch;
        } else {
            // pass through the normal file-time mapping for static/freeze
            sec = ChooseEpoch_File(sec);
        }

        if (g_mode == MODE_STATIC || g_mode == MODE_FREEZE) nsec = 0;

        // Clamp must compare against "forced now" in view time.
        // Convert to disk domain in MODE_OFFSET.
        NowSpec clamp_now = now;
        if (g_mode == MODE_OFFSET) clamp_now.sec -= g_offset_epoch;

        ClampSecNsec(sec, nsec, clamp_now);

        st->tsbuf[i].tv_sec  = (time_t)sec;
        st->tsbuf[i].tv_nsec = (long)nsec;
    }

    PIN_SetSyscallArgument(ctx, std, sp.a0, (ADDRINT)&st->tsbuf[0]);
    if (g_debug) logf << "[pin][dbg] syscall utimensat entry: rewritten times[]\n";
}


static HookEntry Hook_UTimeNsAt = {
    "utimensat",
    GATE_FILETS,

    nullptr, nullptr, 0,
    { }, 0,

    {
        { NR_UTIMENSAT, PH_ENTRY, 1, 2,0,0, &SysEntry_UTimeNsAt, nullptr },
    }, 1,

    nullptr
};

/* -------------------- timecl engine -------------------- */

static bool HostNowTimespec(struct timespec* out) {
    if (!out) return false;

#if defined(__linux__)
    if (NR_CLOCK_GETTIME >= 0) {
        long rc = RawSyscall(NR_CLOCK_GETTIME, (long)CLOCK_REALTIME, (long)out, 0,0,0,0);
        if (rc == 0) return true;
    }

    if (NR_GETTIMEOFDAY >= 0) {
        struct timeval tv;
        long rc = RawSyscall(NR_GETTIMEOFDAY, (long)&tv, 0,0,0,0,0);
        if (rc == 0) {
            out->tv_sec = tv.tv_sec;
            out->tv_nsec = (long)tv.tv_usec * 1000L;
            return true;
        }
    }

    if (NR_TIME >= 0) {
        long t = RawSyscall(NR_TIME, 0,0,0,0,0,0);
        if (t >= 0) {
            out->tv_sec = (time_t)t;
            out->tv_nsec = 0;
            return true;
        }
    }
#endif

    return false;
}

static INT64 EnsureFreezeInitFromHostNow() {
    if (g_mode != MODE_FREEZE) return 0;
    if (!g_freeze_init) {
        struct timespec ts;
        if (HostNowTimespec(&ts)) g_frozen_epoch = (INT64)ts.tv_sec;
        else g_frozen_epoch = 0;
        g_freeze_init = true;
    }
    return g_frozen_epoch;
}

static INT64 ChooseEpoch_Time(INT64 real_epoch) {
    if (g_mode == MODE_STATIC)  return g_static_epoch;
    if (g_mode == MODE_OFFSET) return real_epoch + g_offset_epoch;
    if (g_mode == MODE_FREEZE) {
        if (!g_freeze_init) { g_frozen_epoch = real_epoch; g_freeze_init = true; }
        return g_frozen_epoch;
    }
    return real_epoch;
}

static INT64 ChooseEpoch_File(INT64 real_epoch) {
    if (g_mode == MODE_STATIC)  return g_static_epoch;
    if (g_mode == MODE_OFFSET) return real_epoch + g_offset_epoch;
    if (g_mode == MODE_FREEZE) { EnsureFreezeInitFromHostNow(); return g_frozen_epoch; }
    return real_epoch;
}

static bool ShouldForceClock(ADDRINT clk_id) {
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

static NowSpec ForcedNowSpec() {
    if (g_mode == MODE_STATIC)  return NowSpec{ g_static_epoch, 0 };
    if (g_mode == MODE_FREEZE) return NowSpec{ EnsureFreezeInitFromHostNow(), 0 };

    struct timespec host;
    if (!HostNowTimespec(&host)) return NowSpec{0,0};

    if (g_mode == MODE_PASS) return NowSpec{ (INT64)host.tv_sec, (INT64)host.tv_nsec };

    INT64 mapped = ChooseEpoch_Time((INT64)host.tv_sec);
    return NowSpec{ mapped, (INT64)host.tv_nsec };
}

static inline void ClampSecNsec(INT64& sec, INT64& nsec, const NowSpec& now) {
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

/* -------------------- filets engine -------------------- */

/* cache stat pointer */
static void SysEntry_CacheStatPtr(THREADID, CONTEXT* ctx, SYSCALL_STANDARD std, ThreadState* st,
                                  const SyscallSpec& sp, long) {
    if (!st) return;
    if (!g_filets_enabled || g_mode == MODE_PASS) return;
    st->pending_stat_ptr = PIN_GetSyscallArgument(ctx, std, sp.a0);
    if (g_debug) logf << "[pin][dbg] cache stat* arg" << (int)sp.a0 << "=0x"
                      << std::hex << (ADDRINT)st->pending_stat_ptr << std::dec << "\n";
}

/* adjust stat buffer */
static void AdjustStatBuf(ADDRINT st_ptr, const NowSpec& now) {
    if (!st_ptr || g_mode == MODE_PASS) return;

    struct stat st;
    if (PIN_SafeCopy(&st, (void*)st_ptr, sizeof(st)) != sizeof(st)) return;

    auto adj_timespec = [&](struct timespec& ts) {
        INT64 sec  = ChooseEpoch_File((INT64)ts.tv_sec);
        INT64 nsec = (INT64)ts.tv_nsec;
        if (g_mode == MODE_STATIC || g_mode == MODE_FREEZE) nsec = 0;
        ClampSecNsec(sec, nsec, now);
        ts.tv_sec  = (time_t)sec;
        ts.tv_nsec = (long)nsec;
    };

    adj_timespec(st.st_atim);
    adj_timespec(st.st_mtim);
    adj_timespec(st.st_ctim);

    PIN_SafeCopy((void*)st_ptr, &st, sizeof(st));
}

/* statx fallback (no need for <linux/stat.h>) */
#ifdef __linux__
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
#endif /* __linux__ */

/* cache statx pointer */
static void SysEntry_CacheStatxPtr(THREADID, CONTEXT* ctx, SYSCALL_STANDARD std, ThreadState* st,
                                const SyscallSpec& sp, long) {
    if (!st) return;
    if (!g_filets_enabled || g_mode == MODE_PASS) return;
    st->pending_statx_mask = (uint32_t)PIN_GetSyscallArgument(ctx, std, sp.a0);
    st->pending_statx_ptr  = PIN_GetSyscallArgument(ctx, std, sp.a1);
    if (g_debug) logf << "[pin][dbg] cache statx mask=0x" << std::hex << st->pending_statx_mask
                      << " ptr=0x" << (ADDRINT)st->pending_statx_ptr << std::dec << "\n";
}

/* adjust statx buffer */
static void AdjustStatxBuf(ADDRINT stx_ptr, uint32_t requested_mask, const NowSpec& now) {
    if (!stx_ptr || g_mode == MODE_PASS) return;

    struct statx sx;
    if (PIN_SafeCopy(&sx, (void*)stx_ptr, sizeof(sx)) != sizeof(sx)) return;

    uint32_t patch_mask = sx.stx_mask & requested_mask;

    auto adj = [&](struct statx_timestamp& t) {
        INT64 sec  = ChooseEpoch_File((INT64)t.tv_sec);
        INT64 nsec = (INT64)t.tv_nsec;
        if (g_mode == MODE_STATIC || g_mode == MODE_FREEZE) nsec = 0;
        ClampSecNsec(sec, nsec, now);
        t.tv_sec  = (int64_t)sec;
        t.tv_nsec = (uint32_t)nsec;
    };

    if (patch_mask & STATX_ATIME) adj(sx.stx_atime);
    if (patch_mask & STATX_MTIME) adj(sx.stx_mtime);
    if (patch_mask & STATX_CTIME) adj(sx.stx_ctime);
#ifdef STATX_BTIME
    if (patch_mask & STATX_BTIME) adj(sx.stx_btime);
#endif

    PIN_SafeCopy((void*)stx_ptr, &sx, sizeof(sx));
}

/* -------------------- hooking table -------------------- */

static HookEntry* g_hooks[] = {
    &Hook_SyscallCacheCore,
    &Hook_Time,
    &Hook_GetTimeOfDay,
    &Hook_ClockGetTime,
    &Hook_Stat_Family,
    &Hook_FStatAt_Family,
    &Hook_StatX,
    &Hook_UTimeNsAt,
#ifdef __GLIBC__
    &Hook_GlibC_XStat,
    &Hook_GlibC_FXStatAt,
#endif
};

static const size_t g_hook_count = sizeof(g_hooks)/sizeof(g_hooks[0]);

/* -------------------- general hooking engine -------------------- */

static void BuildProtosFromTable() {  // RTN hooking
    for (size_t i = 0; i < g_hook_count; i++) {
        HookEntry* hi = g_hooks[i];
        if (hi->proto || !hi->proto_maker) continue;

        PROTO reuse = 0;
        for (size_t j = 0; j < i; j++) {
            HookEntry* hj = g_hooks[j];
            if (hj->proto_maker == hi->proto_maker && hj->proto) {
                reuse = hj->proto;
                break;
            }
        }
        hi->proto = reuse ? reuse : hi->proto_maker();
    }
}

static void FreeProtosFromTable() {  // RTN hooking
    for (size_t i = 0; i < g_hook_count; i++) {
        HookEntry* hi = g_hooks[i];
        PROTO p = hi->proto;
        if (!p) continue;

        bool seen = false;
        for (size_t j = 0; j < i; j++) {
            if (g_hooks[j]->proto == p) { seen = true; break; }
        }
        if (!seen) PROTO_Free(p);
    }
    for (size_t i = 0; i < g_hook_count; i++) g_hooks[i]->proto = 0;
}

static void ImageLoad(IMG img, void*) { // RTN hooking
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wcast-function-type"

    for (size_t i = 0; i < g_hook_count; i++) {
        HookEntry& h = *g_hooks[i];

        if (!GateEnabled(h.gate)) continue;
        if (!h.wrapper || !h.proto || h.rtn_count == 0) continue;

        for (uint8_t k = 0; k < h.rtn_count; k++) {
            const char* nm = h.rtn_names[k];
            if (!nm) continue;
            TryReplace(img, nm, h.wrapper, h.proto, h.rtn_argc);
        }
    }

#pragma GCC diagnostic pop
}

static void OnSyscallEntry(THREADID tid, CONTEXT* ctx, SYSCALL_STANDARD std, VOID*) { // SYSCALL hooking
    ThreadState* st = TS(tid);
    long nr = (long)PIN_GetSyscallNumber(ctx, std);

    for (size_t i = 0; i < g_hook_count; i++) {
        HookEntry& h = *g_hooks[i];
        if (!GateEnabled(h.gate)) continue;

        for (uint8_t j = 0; j < h.sys_count; j++) {
            const SyscallSpec& sp = h.sys[j];

            if (sp.nr < 0 && sp.nr != NR_ANY) continue;
            if (!(sp.phase & PH_ENTRY)) continue;
            if (!sp.on_entry) continue;

            if (sp.nr != NR_ANY && nr != sp.nr) continue;

            if (st && st->inwrap && sp.skip_if_inwrap_entry) continue;

            sp.on_entry(tid, ctx, std, st, sp, nr);
        }
    }
}

static void OnSyscallExit(THREADID tid, CONTEXT* ctx, SYSCALL_STANDARD std, VOID*) { // SYSCALL hooking
    ThreadState* st = TS(tid);

    long nr  = (long)PIN_GetSyscallNumber(ctx, std);
    long ret = (long)PIN_GetSyscallReturn(ctx, std);

    for (size_t i = 0; i < g_hook_count; i++) {
        HookEntry& h = *g_hooks[i];
        if (!GateEnabled(h.gate)) continue;

        for (uint8_t j = 0; j < h.sys_count; j++) {
            const SyscallSpec& sp = h.sys[j];

            if (sp.nr < 0 && sp.nr != NR_ANY) continue;
            if (!(sp.phase & PH_LEAVE)) continue;
            if (!sp.on_exit) continue;

            if (sp.nr != NR_ANY && nr != sp.nr) continue;

            if (sp.require_success && SysRetIsError(ret)) continue;

            if (st && st->inwrap && sp.skip_if_inwrap_exit) continue;

            sp.on_exit(tid, ctx, std, st, sp, nr);
        }
    }
}

/* -------------------- entry point -------------------- */

int main(int argc, char* argv[]) {
    PIN_InitSymbols();
    if (PIN_Init(argc, argv)) return 1;

    logf.open(KnobLog.Value().c_str(), std::ios::out | std::ios::app);

    g_mode = ParseMode(KnobMode.Value());
    if (KnobFreeze.Value()) g_mode = MODE_FREEZE;

    g_static_epoch = 0;
    g_offset_epoch = 0;

    const INT64 epochv = KnobEpoch.Value();
    if (g_mode == MODE_STATIC) {
        g_static_epoch = epochv;
    } else if (g_mode == MODE_OFFSET) {
        g_offset_epoch = epochv;
    }

    g_all_clocks     = KnobAllClocks.Value();
    g_timecl_enable    = KnobTimeCL.Value();
    g_filets_enabled = KnobFileTS.Value();
    g_filets_clamp   = KnobClamp.Value();
    g_clamp_nsec     = KnobClampNSec.Value();

    g_tls_key = PIN_CreateThreadDataKey(nullptr);
    PIN_AddThreadStartFunction(ThreadStart, nullptr);
    PIN_AddThreadFiniFunction(ThreadFini, nullptr);

    BuildProtosFromTable();

    IMG_AddInstrumentFunction(ImageLoad, nullptr);
    PIN_AddSyscallEntryFunction(OnSyscallEntry, nullptr);
    PIN_AddSyscallExitFunction(OnSyscallExit, nullptr);

    logf << "[pin] start mode=" << ModeName(g_mode)
         << " epoch=" << g_static_epoch
         << " offset=" << g_offset_epoch
         << " time=" << (g_timecl_enable ? 1 : 0)
         << " filets=" << (g_filets_enabled ? 1 : 0)
         << " clamp=" << (g_filets_clamp ? 1 : 0)
         << " clampnsec=" << (g_clamp_nsec ? 1 : 0)
         << " debug=" << (g_debug ? 1 : 0)
         << "\n";

    PIN_StartProgram();

    // never reached
    FreeProtosFromTable();
    return 0;
}
