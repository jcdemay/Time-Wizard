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

#include <stdio.h>
#include <time.h>
#include <sys/time.h>
#include <errno.h>
#include <string.h>

static void print_tm(const char *label, time_t t) {
    struct tm tm_local;
    char buf[128];

    if (!localtime_r(&t, &tm_local)) {
        fprintf(stderr, "%s: localtime_r failed\n", label);
        return;
    }
    if (strftime(buf, sizeof(buf), "%a %b %e %T %Z %Y", &tm_local) == 0) {
        fprintf(stderr, "%s: strftime failed\n", label);
        return;
    }
    printf("%s: %s (epoch=%lld)\n", label, buf, (long long) t);
}

int main(void) {
    printf("=== mini_date (calls time/gettimeofday/clock_gettime) ===\n");

    // 1. time(time_t*)
    errno = 0;
    time_t t = time(NULL);
    if (t == (time_t) - 1) {
        fprintf(stderr, "time() failed: %s\n", strerror(errno));
    } else {
        print_tm("time()", t);
    }

    // 2. gettimeofday(timeval*, timezone*)
    struct timeval tv;
    errno = 0;
    if (gettimeofday(&tv, NULL) != 0) {
        fprintf(stderr, "gettimeofday() failed: %s\n", strerror(errno));
    } else {
        print_tm("gettimeofday()", (time_t) tv.tv_sec);
        printf("gettimeofday(): tv_usec=%ld\n", (long) tv.tv_usec);
    }

    // 3. clock_gettime(CLOCK_REALTIME, timespec*)
    struct timespec ts;
    errno = 0;
    if (clock_gettime(CLOCK_REALTIME, &ts) != 0) {
        fprintf(stderr, "clock_gettime(CLOCK_REALTIME) failed: %s\n", strerror(errno));
    } else {
        print_tm("clock_gettime(CLOCK_REALTIME)", (time_t) ts.tv_sec);
        printf("clock_gettime(CLOCK_REALTIME): tv_nsec=%ld\n", (long) ts.tv_nsec);
    }

    // 4. clock_gettime(CLOCK_MONOTONIC, timespec*)
#ifdef CLOCK_MONOTONIC
    errno = 0;
    if (clock_gettime(CLOCK_MONOTONIC, &ts) == 0) {
        printf("clock_gettime(CLOCK_MONOTONIC): sec=%lld nsec=%ld\n", (long long) ts.tv_sec, (long) ts.tv_nsec);
    }
#endif

    return 0;
}
