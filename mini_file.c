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

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <sys/stat.h>

#ifdef __linux__
#include <linux/stat.h>
#include <sys/syscall.h>
#include <stdint.h>
#endif

static void print_ts(const char *label, time_t sec, long nsec) {
    struct tm tm_local;
    char buf[128];

    if (!localtime_r(&sec, &tm_local)) {
        fprintf(stderr, "%s: localtime_r failed\n", label);
        return;
    }
    if (strftime(buf, sizeof(buf), "%Y-%m-%d %H:%M:%S %Z", &tm_local) == 0) {
        fprintf(stderr, "%s: strftime failed\n", label);
        return;
    }
    printf("%s: %s (epoch=%lld) nsec=%ld\n", label, buf, (long long) sec, nsec);
}

static void dump_stat(const char *tag, const struct stat *st) {
    printf("=== %s ===\n", tag);
    print_ts("  atime", st->st_atim.tv_sec, st->st_atim.tv_nsec);
    print_ts("  mtime", st->st_mtim.tv_sec, st->st_mtim.tv_nsec);
    print_ts("  ctime", st->st_ctim.tv_sec, st->st_ctim.tv_nsec);
    printf("  size=%lld mode=%o ino=%lld\n", (long long) st->st_size, (unsigned) st->st_mode, (long long) st->st_ino);
}

#ifdef __linux__
static void print_statx_ts(const char *label, struct statx_timestamp t) {
    print_ts(label, (time_t) t.tv_sec, (long) t.tv_nsec);
}

static void dump_statx(const char *tag, const struct statx *sx) {
    printf("=== %s ===\n", tag);
    if (sx->stx_mask & STATX_ATIME)
        print_statx_ts("  atime", sx->stx_atime);
    if (sx->stx_mask & STATX_MTIME)
        print_statx_ts("  mtime", sx->stx_mtime);
    if (sx->stx_mask & STATX_CTIME)
        print_statx_ts("  ctime", sx->stx_ctime);
#ifdef STATX_BTIME
    if (sx->stx_mask & STATX_BTIME)
        print_statx_ts("  btime", sx->stx_btime);
#endif
    printf("  size=%lld mode=%o ino=%lld mask=0x%x\n",
           (long long) sx->stx_size, (unsigned) sx->stx_mode, (long long) sx->stx_ino, sx->stx_mask);
}
#endif

int main(void) {
    const char *path = "/bin/ls";

    printf("=== mini_filets (READ-ONLY metadata) ===\n");
    printf("Target: %s\n\n", path);

    /* 1) stat */
    {
        struct stat st;
        errno = 0;
        if (stat(path, &st) != 0) {
            fprintf(stderr, "stat failed: %s\n", strerror(errno));
        } else {
            dump_stat("stat(path)", &st);
        }
        puts("");
    }

    /* 2) lstat */
    {
        struct stat st;
        errno = 0;
        if (lstat(path, &st) != 0) {
            fprintf(stderr, "lstat failed: %s\n", strerror(errno));
        } else {
            dump_stat("lstat(path)", &st);
        }
        puts("");
    }

    /* 3) open + fstat */
    {
        int fd = open(path, O_RDONLY | O_CLOEXEC);
        if (fd < 0) {
            fprintf(stderr, "open failed: %s\n", strerror(errno));
        } else {
            struct stat st;
            errno = 0;
            if (fstat(fd, &st) != 0) {
                fprintf(stderr, "fstat failed: %s\n", strerror(errno));
            } else {
                dump_stat("open(path)+fstat(fd)", &st);
            }
            close(fd);
        }
        puts("");
    }

    /* 4) fstatat (dirfd = AT_FDCWD) */
    {
        struct stat st;
        errno = 0;
        if (fstatat(AT_FDCWD, path, &st, 0) != 0) {
            fprintf(stderr, "fstatat failed: %s\n", strerror(errno));
        } else {
            dump_stat("fstatat(AT_FDCWD, path, 0)", &st);
        }
        puts("");
    }

    /* 5) fstatat nofollow (just to hit alternate path) */
    {
        struct stat st;
        errno = 0;
        if (fstatat(AT_FDCWD, path, &st, AT_SYMLINK_NOFOLLOW) != 0) {
            fprintf(stderr, "fstatat(nofollow) failed: %s\n", strerror(errno));
        } else {
            dump_stat("fstatat(AT_FDCWD, path, AT_SYMLINK_NOFOLLOW)", &st);
        }
        puts("");
    }

#ifdef __linux__
    /* 6) statx via libc */
    {
        struct statx sx;
        memset(&sx, 0, sizeof(sx));
        errno = 0;

        if (statx(AT_FDCWD, path, 0, STATX_BASIC_STATS | STATX_BTIME, &sx) != 0) {
            fprintf(stderr, "statx failed: %s\n", strerror(errno));
        } else {
            dump_statx("statx(AT_FDCWD, path)", &sx);
        }
    }
#endif

    return 0;
}
