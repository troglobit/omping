/*
 * Copyright (c) 2010, Red Hat, Inc.
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

#include "logging.h"
#include "util.h"

void	util_gen_id(char *id, size_t len, const struct ai_item *ai_item,
    const struct sockaddr_storage *sas);

void	util_gen_id_add_sas(char *id, size_t len, size_t *pos, const struct sockaddr_storage *sas);

/*
 * Return abs value of (t2 - t1) in ms double precission.
 */
double
util_time_double_absdiff(struct timeval t1, struct timeval t2)
{
        double dt1, dt2, tmp;

        dt1 = t1.tv_usec + t1.tv_sec * 1000000;
        dt2 = t2.tv_usec + t2.tv_sec * 1000000;

        if (dt2 > dt1) {
                tmp = dt1;
                dt1 = dt2;
                dt2 = tmp;
        }

        return (dt1 - dt2) / 1000.0;
}

/*
 * generate random ID from current pid, random data from random(3) and optionally addresses ai_item
 * and sas. ID is stored in id with maximum length len.
 */
void
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
void
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

	gettimeofday(&tv, NULL);

	return (tv);
}

/*
 * Initialize random number generator.
 */
void
util_random_init(const struct sockaddr_storage *local_addr)
{
	unsigned int seed;
	int i;

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
