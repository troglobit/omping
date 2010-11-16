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

#ifndef _SOCKFUNC_H_
#define _SOCKFUNC_H_

#ifdef __cplusplus
extern "C" {
#endif

#ifdef __cplusplus
}
#endif

extern int	sf_bind_socket(const struct sockaddr *bind_addr, int sock);

extern int	sf_create_multicast_socket(const struct sockaddr *mcast_addr,
    const struct sockaddr *local_addr, const char *local_ifname, uint8_t ttl);

extern int	sf_create_udp_socket(const struct sockaddr *sa);

extern int	sf_create_unicast_socket(const struct sockaddr *local_addr, uint8_t ttl,
    int mcast_send, const char *local_ifname);

extern int	sf_mcast_join_group(const struct sockaddr *mcast_addr,
    const struct sockaddr *local_addr, const char *local_ifname, int sock);

extern int	sf_set_socket_mcast_if(const struct sockaddr *local_addr, int sock,
    const char *local_ifname);

extern int	sf_set_socket_mcast_loop(const struct sockaddr *mcast_addr, int sock, int enable);
extern int	sf_set_socket_recvttl(const struct sockaddr *sa, int sock);
extern int	sf_set_socket_reuse(int sock);
extern int	sf_set_socket_ttl(const struct sockaddr *sa, int mcast, int sock, uint8_t ttl);

#endif /* _SOCKFUNC_H_ */
