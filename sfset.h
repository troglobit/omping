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

#ifndef _SFSET_H_
#define _SFSET_H_

#ifdef __cplusplus
extern "C" {
#endif

enum sf_cast_type {
	SF_CT_UNI,
	SF_CT_MULTI,
	SF_CT_BROAD,
};

extern int	sfset_buf_size(int sock, int snd_buf, int buf_size, int *new_buf_size,
    int force_buf_size);

extern int	sfset_broadcast(int sock, int enable);
extern int	sfset_ipv6only(const struct sockaddr *sa, int sock);
extern int	sfset_mcast_if(const struct sockaddr *local_addr, int sock,
    const char *local_ifname);

extern int	sfset_mcast_loop(const struct sockaddr *mcast_addr, int sock, int enable);
extern int	sfset_recvttl(const struct sockaddr *sa, int sock);
extern int	sfset_reuse(int sock);
extern int	sfset_timestamp(int sock);
extern int	sfset_ttl(const struct sockaddr *sa, enum sf_cast_type cast_type, int sock,
    uint8_t ttl);

#ifdef __cplusplus
}
#endif

#endif /* _SFSET_H_ */
