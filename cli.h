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

#ifndef _CLI_H_
#define _CLI_H_

#include "addrfunc.h"
#include "omping.h"
#include "sockfunc.h"

#ifdef __cplusplus
extern "C" {
#endif

extern int	cli_parse(struct ai_list *ai_list, int argc, char * const argv[],
    char **local_ifname, int *ip_ver, struct ai_item *local_addr, int *wait_time,
    enum sf_transport_method *transport_method, struct ai_item *mcast_addr,
    uint16_t *port, uint8_t *ttl, int *single_addr, int *quiet, int *cont_stat,
    int *timeout_time, int *wait_for_finish_time, int *dup_buf_items, int *rate_limit_time,
    int *sndbuf_size, int *rcvbuf_size, uint64_t *send_count_queries, int *auto_exit,
    enum omping_op_mode *op_mode);

#ifdef __cplusplus
}
#endif

#endif /* _CLI_H_ */
