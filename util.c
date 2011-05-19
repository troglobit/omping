/*
 * Copyright (c) 2010-2011, Red Hat, Inc.
 *
 * Permission to use, copy, modify, and/or distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND RED HAT, INC. DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL RED HAT, INC. BE LIABLE
 * FOR ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION
 * OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN
 * CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

/*
 * Author: Jan Friesse <jfriesse@redhat.com>
 */

#include <sys/types.h>

#include <sys/time.h>

#include <netinet/in.h>
#include <arpa/inet.h>

#include <err.h>
#include <limits.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#ifdef __CYGWIN__
#include <windows.h>
#endif

#include "logging.h"
#include "util.h"

/*
 * Function prototypes
 */
#ifdef __CYGWIN__
static int	util_cygwin_gettimeofday(struct timeval *tv, struct timezone *tz);
#endif

static void	util_gen_id(char *id, size_t len, const struct ai_item *ai_item,
    const struct sockaddr_storage *sas);

static void	util_gen_id_add_sas(char *id, size_t len, size_t *pos,
    const struct sockaddr_storage *sas);

/*
 * Functions implementation
 */

#ifdef __CYGWIN__
/*
 * cygwin version of gettimeofday but with microseconds precision. Uses windows Performance
 * Counters to achieve precision if possible, otherwise cygwin gettimeofday implementation
 * is used.
 * Return 0 on success, otherwise -1.
 */
int
util_cygwin_gettimeofday(struct timeval *tv, struct timezone *tz)
{
	/* Frequency of performance counter */
	static LARGE_INTEGER freq;
	/* Offset of starting pc */
	static LARGE_INTEGER perf_count_offset;
	/* Actual pc */
	static LARGE_INTEGER perf_count;
	/* Microsenconds base time */
	static uint64_t us_base = 0;
	/* Function was not called yet */
	static int initialized = 0;
	/* If not used pf, fallback to gettimeofday implementation */
	static BOOL use_pf = 0;
	/* Tmp timeval */
	struct timeval tv2;
	/* Diff between offset pc and actual pc */
	int64_t perf_diff;
	/* Actual time in microseconds */
	uint64_t us;
	/* Time in microseconds returned by gettimeofday */
	uint64_t us_ref;

	if (!initialized) {
		initialized = 1;
		use_pf = QueryPerformanceFrequency(&freq);
		if (use_pf) {
			QueryPerformanceCounter(&perf_count_offset);
			gettimeofday(&tv2, tz);
			us_base = tv2.tv_sec * (uint64_t)1000000 + tv2.tv_usec;
		}
	}

	if (use_pf) {
		QueryPerformanceCounter(&perf_count);
	} else {
		return (gettimeofday(tv, tz));
	}

	perf_diff = perf_count.QuadPart - perf_count_offset.QuadPart;
	us = ((double)perf_diff / (double)freq.QuadPart) * 1000000.0 + us_base;

	gettimeofday(&tv2, tz);
	us_ref = tv2.tv_sec * (uint64_t)1000000 + tv2.tv_usec;

	if (util_u64_absdiff(us, us_ref) > (uint64_t)1000000) {
		us_base = us = us_ref;
		perf_count_offset.QuadPart = perf_count.QuadPart;
	}

	tv->tv_sec = us / (uint64_t)1000000;
	tv->tv_usec = us % (uint64_t)1000000;

	return (0);
}
#endif /* __CYGWIN__ */

/*
 * Returns absolute value of n
 */
double
util_fabs(double n)
{

	return (n < 0 ? -n : n);
}

/*
 * generate random ID from current pid, random data from random(3) and optionally addresses ai_item
 * and sas. ID is stored in id with maximum length len.
 */
static void
util_gen_id(char *id, size_t len, const struct ai_item *ai_item,
    const struct sockaddr_storage *sas)
{
	pid_t pid;
	size_t pos;

	/*
	 * First fill item with some random data
	 */
	for (pos = 0; pos < len; pos++) {
#if defined(__FreeBSD__) || defined(__OPENBSD__)
		id[pos] = (unsigned char)arc4random_uniform(UCHAR_MAX);
#else
		id[pos] = (unsigned char)random();
#endif
	}

	pos = 0;

	if (pos + sizeof(pid) < len) {
		/*
		 * Add PID
		 */
		pid = getpid();
		memcpy(id, &pid, sizeof(pid));

		pos += sizeof(pid);
	}

	/*
	 * Add sas from ai_item
	 */
	if (ai_item != NULL) {
		util_gen_id_add_sas(id, len, &pos, &ai_item->sas);
	}

	if (sas != NULL) {
		util_gen_id_add_sas(id, len, &pos, sas);
	}
}

/*
 * Add IP address from sas to id with length len to position pos. Also adjust pos to position after
 * added item.
 */
static void
util_gen_id_add_sas(char *id, size_t len, size_t *pos, const struct sockaddr_storage *sas)
{
	void *addr_pointer;
	size_t addr_len;

	switch (sas->ss_family) {
	case AF_INET:
		addr_pointer = &(((struct sockaddr_in *)sas)->sin_addr.s_addr);
		addr_len = sizeof(struct in_addr);
		break;
	case AF_INET6:
		addr_pointer = &(((struct sockaddr_in6 *)sas)->sin6_addr.s6_addr);
		addr_len = sizeof(struct in6_addr);
		break;
	default:
		DEBUG_PRINTF("Unknown ss family %d", sas->ss_family);
		errx(1, "Unknown ss family %d", sas->ss_family);
	}

	if (*pos + addr_len < len) {
		memcpy(id + *pos, addr_pointer, addr_len);
		*pos += addr_len;
	}
}

/*
 * Generate client id. Client id has length CLIENTID_LEN and takes only local address.
 */
void
util_gen_cid(char *client_id, const struct ai_item *local_addr)
{
	util_gen_id(client_id, CLIENTID_LEN, local_addr, NULL);

	DEBUG2_HEXDUMP("generated CID: ", client_id, CLIENTID_LEN);
}

/*
 * Generate session id. Session id has length SESSIONID_LEN and takes local and remote addresses.
 */
void
util_gen_sid(char *session_id)
{
	util_gen_id(session_id, SESSIONID_LEN, NULL, NULL);

	DEBUG2_HEXDUMP("generated SESID: ", session_id, SESSIONID_LEN);
}

/*
 * Return current time stamp saved in timeval structure.
 */
struct timeval
util_get_time(void)
{
	struct timeval tv;

#ifdef __CYGWIN__
	util_cygwin_gettimeofday(&tv, NULL);
#else
	gettimeofday(&tv, NULL);
#endif

	return (tv);
}

/*
 * Initialize random number generator.
 */
void
util_random_init(const struct sockaddr_storage *local_addr)
{
	unsigned int seed;
	unsigned int i;

	seed = time(NULL) + getpid();

	for (i = 0; i < af_sas_len(local_addr); i++) {
		seed += ((uint8_t *)local_addr)[i];
	}

	srandom(seed);
}

/*
 * Returns abs(t1 - t2) in miliseconds.
 */
uint64_t
util_time_absdiff(struct timeval t1, struct timeval t2)
{
	uint64_t u64t1, u64t2, tmp;

	u64t1 = t1.tv_usec / 1000 + t1.tv_sec * 1000;
	u64t2 = t2.tv_usec / 1000 + t2.tv_sec * 1000;

	if (u64t2 > u64t1) {
		tmp = u64t1;
		u64t1 = u64t2;
		u64t2 = tmp;
	}

	return (u64t1 - u64t2);
}

/*
 * Return abs value of (t2 - t1) in ms double precission.
 */
double
util_time_double_absdiff(struct timeval t1, struct timeval t2)
{
	return (util_time_double_absdiff_us(t1, t2) / 1000.0);
}

/*
 * Return abs value of (t2 - t1) in ns (nano seconds) double precission.
 */
double
util_time_double_absdiff_ns(struct timeval t1, struct timeval t2)
{
	return (util_time_double_absdiff_us(t1, t2) * 1000.0);
}

/*
 * Return abs value of (t2 - t1) in us (micro seconds) double precission.
 */
double
util_time_double_absdiff_us(struct timeval t1, struct timeval t2)
{
	double dt1, dt2, tmp;

	dt1 = t1.tv_usec + t1.tv_sec * UTIL_NSINMS;
	dt2 = t2.tv_usec + t2.tv_sec * UTIL_NSINMS;

	if (dt2 > dt1) {
		tmp = dt1;
		dt1 = dt2;
		dt2 = tmp;
	}

	return (dt1 - dt2);
}

/*
 * Return standard deviation based on m2 value and number of items n. Value is rounded to 0.001.
 */
double
util_ov_std_dev(double m2, uint64_t n)
{
	return (util_u64sqrt((uint64_t)util_ov_variance(m2, n)));
}

/*
 * On-line algorithm for compute variance.
 * Based on Donald E. Knuth (1998). The Art of Computer Programming, volume 2: p. 232.
 * function updats mean and m2. x is new value and n is absolute number of all items.
 */
void
util_ov_update(double *mean, double *m2, double x, uint64_t n)
{
	double delta;

	delta = x - *mean;
	*mean = *mean + delta / n;
	*m2 = *m2 + delta * (x - *mean);
}

/*
 * Return variance based on m2 value and number of items n.
 */
double
util_ov_variance(double m2, uint64_t n)
{
	return ((n > 1) ? (m2 / (n - 1)) : 0.0);
}

/*
 * Return number of miliseconds from timeval structure
 */
uint64_t
util_tv_to_ms(struct timeval t1)
{
	uint64_t u64;

	u64 = t1.tv_usec / 1000 + t1.tv_sec * 1000;

	return (u64);
}

/*
 * Return absolute difference between two unsigned 64-bit integers
 */
uint64_t
util_u64_absdiff(uint64_t u1, uint64_t u2)
{
	uint64_t tmpu;

	if (u1 > u2) {
		tmpu = u1;
		u1 = u2;
		u2 = tmpu;
	}

	return (u2 - u1);
}

/*
 * Return sqrt of 64bit unsigned int n
 */
uint32_t
util_u64sqrt(uint64_t n)
{
	double x, x2;

	if (n == 0) {
		return (0);
	}

	x = n;

	while (util_fabs((x2 = (x + n / x) / 2) - x) >= 0.5) {
		x = x2;
	}

	return ((uint32_t)x2);
}
