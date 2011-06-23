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

#ifndef _CLIPRINT_H_
#define _CLIPRINT_H_

#include "rhfunc.h"
#include "sockfunc.h"

#ifdef __cplusplus
extern "C" {
#endif

extern void	cliprint_client_state(const char *host_name, int host_name_len,
    enum sf_transport_method transport_method, const struct sockaddr_storage *mcast_addr,
    const struct sockaddr_storage *remote_addr, enum rh_client_state state,
    enum rh_client_stop_reason stop_reason);

extern void	cliprint_final_remote_version(const struct rh_list *remote_hosts,
    int host_name_len);

extern void	cliprint_final_stats(const struct rh_list *remote_hosts, int host_name_len,
    enum sf_transport_method transport_method);

extern void	cliprint_nl(void);

extern void	cliprint_packet_stats(const char *host_name, int host_name_len, uint32_t seq,
    int is_dup, size_t msg_len, int dist_set, uint8_t dist, int rtt_set, double rtt,
    double avg_rtt, int loss, enum sf_cast_type cast_type, int cont_stat);

extern void	cliprint_usage(void);
extern void	cliprint_version(void);

#ifdef __cplusplus
}
#endif

#endif /* _CLIPRINT_H_ */
