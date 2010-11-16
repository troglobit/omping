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

#ifndef _UTIL_H_
#define _UTIL_H_

#ifdef __cplusplus
extern "C" {
#endif

#include "addrfunc.h"

/*
 * Definitions
 */

/* (4 bytes of pid) + (16 bytes of IPV6 addr) + 4 bytes of random data */
enum { CLIENTID_LEN = (4 + 16 + 4) };

/* (4 bytes of pid) + 12 bytes of random data */
enum { SESSIONID_LEN = (4 + 12) };

/*
 * Functions
 */
extern double		util_time_double_absdiff(struct timeval t1, struct timeval t2);
extern void		util_gen_cid(char *client_id, const struct ai_item *local_addr);
extern void		util_gen_sid(char *session_id);
extern struct timeval	util_get_time(void);
extern void		util_random_init(const struct sockaddr_storage *local_addr);
extern uint64_t		util_time_absdiff(struct timeval t1, struct timeval t2);

#ifdef __cplusplus
}
#endif

#endif /* _UTIL_H_ */
