#TIME-WIZARD
Linux Time Clocks + File Timestamps Hooking Collection

#OVERVIEW

This repository contains multiple implementations of the same idea:

1. Force the "time seen by a process" (time clocks):
time(), gettimeofday(), clock_gettime(), and related paths

2. Force the "timestamps seen by a process" (file timestamps):
stat*, fstatat*, statx, utimensat, etc.

All versions aim to be behaviorally consistent (same modes, same mapping rules,
same clamp logic, same patch rules), but are implemented using different Linux
hooking technologies. The different versions were written progressively as
different tools or kernel features became practical or available, and as new
edge-cases appeared (static binaries, syscall-only paths, vDSO, ABI variants).

#KEY CONCEPTS

#DYNAMIC vs STATIC INTERCEPTION

A. Dynamic hooking (user-space symbols)

You intercept libc (or other shared library) functions like:
clock_gettime(), gettimeofday(), time(), stat(), statx(), ...

This is what LD_PRELOAD is good at, and also what DBI tools can do.

Pros:
- Easy to deploy for dynamically-linked programs
- Good coverage of "normal" libc usage
- Can patch returned structs at the function boundary

Cons:
- Does not cover fully static binaries
- Can be bypassed by direct syscalls or by vDSO paths

B. Static and syscall-level hooking

You intercept the kernel syscall boundary (SYS_* / _NR*) instead of libc.

This is what ptrace (strace-style) and seccomp user-notification do well.

Pros:
- Covers static binaries and direct syscall users
- Closer to the "kernel truth"

Cons:
- If the program uses vDSO (no syscall), you see nothing
- Often higher overhead (ptrace) or more complexity (seccomp emulation)

#LIBC vs SYSCALL vs VDSO

Time is a good example because a program can obtain time through different paths:

A. App -> libc -> syscall
Example: libc clock_gettime() ultimately does a SYS_clock_gettime syscall.

B. App -> vDSO (NO syscall)
Linux can map a vDSO (Virtual Dynamic Shared Object) into the process.
Certain time functions can be served entirely from user-space with no
kernel syscall. In that case, syscall-level interceptors (ptrace/seccomp)
will NOT see anything.

C. App -> direct syscall
Static binaries or low-level code may do syscall(SYS_...) directly,
bypassing libc wrappers.

#PARAMETERS (COMMON BEHAVIOR ACROSS IMPLEMENTATIONS)

All implementations share the same conceptual modes and options:

- pass:
do not modify time (optionally log only)

- static:
return a fixed epoch (e.g., epoch=1)

- offset:
return real_time + offset_seconds

- freeze:
freeze time at the first observed wall-clock value,
(some variants allow an explicit epoch fallback)

- epoch:
Epoch value or offset in seconds depending on the mode

- timecl:
patch time clocks value in returned structs

- allclocks:
Also force non-wall clocks (e.g., CLOCK_MONOTONIC, CLOCK_BOOTTIME),
not just real-time clocks.

- filets:
patch timestamps fields in returned structs

- clamp:
if file timestamp > forced_now then clamp to forced_now

- clampnsec:
strict clamp comparing (sec,nsec) as pairs

WHY MULTIPLE IMPLEMENTATIONS

The same behavior can be achieved with several different technologies,
each with trade-offs:

- LD_PRELOAD:
best for dynamic binaries; simple to use; symbol-level

- ptrace (PTRACE_SEIZE / PTRACE_SYSCALL):
syscall-level; covers static binaries; heavy overhead; misses vDSO-only

- Intel Pin:
DBI; can hook functions and syscalls; very powerful; external dependency

- DynamoRIO:
DBI; similar power to Pin; open-source; different engineering trade-offs

- seccomp user notification (SECCOMP_RET_USER_NOTIF):
syscall-level policy + userspace supervisor; no preload needed
but cannot see vDSO-only time reads (no syscall)

TEMPLATE PHILOSOPHY (ADDING A NEW HOOK)

All backends are structured so that adding a new intercepted function/syscall
follows the same pattern:

- Identify the syscall numbers and/or symbol names (SYS_, _NR, aliases)

- Implement the wrapper/handler

- Time mapping using the shared mode engine

- Patch output structures safely (do not write more than copied)

- Clamp logic (sec-only or (sec,nsec))

- Register it in the global hook list / table

- Keep behavior consistent across all backends

#LIMITATIONS

- vDSO-only time reads are invisible to syscall-level backends (ptrace/seccomp)

- Forcing non-wall clocks (allclocks) can break software assumptions

- ptrace requires privileges and can be slow

- seccomp user notification needs a recent kernel and careful emulation

#INSTRUCTIONS

- Look at the build/compile script to see exactly how to compile each backend

- Look at the test script to see how to run and compare them

- The test script also relies on two small helper binaries, mini_date and mini_file

- They must be compiled statically to validate syscall-level / static-binary hooking paths

#SAFETY / DISCLAIMER

These tools intentionally alter a process perception of time. This can break:

- Timeouts, scheduling, TLS/cert validation, logs, caches

- Software mixing CLOCK_REALTIME and CLOCK_MONOTONIC

- Programs that assume monotonicity or real-world time continuity

- Use in controlled environments (testing, reproducibility, RE, sandboxing).

#LICENSE

Copyright (c) 2013 Jonathan-Christofer Demay (jcdemay@gmail.com)

Do whatever the fuck you want with this code. I can't stop you anyway.
You can use it, copy it, modify it, distribute it, and/or sell it.
No conditions. No strings attached. Just don't blame me.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
THE SOFTWARE.
