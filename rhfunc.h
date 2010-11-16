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

#ifndef _RHFUNC_H_
#define _RHFUNC_H_

#include <sys/types.h>

#include <sys/queue.h>
#include <sys/socket.h>

#include <ifaddrs.h>
#include <netdb.h>

#include "addrfunc.h"
#include "util.h"

#ifdef __cplusplus
extern "C" {
#endif

enum rh_client_state {
	RH_CS_INITIAL,
	RH_CS_QUERY,
	RH_CS_STOP
};

enum rh_server_state {
	RH_SS_INITIAL,
	RH_SS_ANSWER,
};

/*
 * Remote host info item, client info part
 */
struct rh_item_ci {
	enum rh_client_state state;
	char client_id[CLIENTID_LEN];
	struct timeval last_init_ts;
	char *ses_id;
	double rtt_max[2];
	double rtt_min[2];
	double rtt_sum[2];
	size_t ses_id_len;
	uint32_t seq_num;
	uint32_t no_err_msgs;
	uint32_t no_received[2];
};

/*
 * Remote host info item, server info part
 */
struct rh_item_si {
	enum rh_server_state state;
	char ses_id[SESSIONID_LEN];
};

/*
 * Remote host info item. This is intended to use with TAILQ list.
 */
struct rh_item {
	struct ai_item *addr;
	struct rh_item_ci client_info;
	struct rh_item_si server_info;
	TAILQ_ENTRY(rh_item) entries;
};

/*
 * Typedef of TAILQ head of list of rh_item(s)
 */
TAILQ_HEAD(rh_list, rh_item);

extern struct rh_item	*rh_list_add_item(struct rh_list *rh_list, struct ai_item *addr);
extern void		 rh_list_create(struct rh_list *rh_list, struct ai_list *remote_addrs);
extern struct rh_item	*rh_list_find(struct rh_list *rh_list, const struct sockaddr *sa);
extern void		 rh_list_free(struct rh_list *rh_list);

extern void		 rh_list_gen_cid(struct rh_list *rh_list,
    const struct ai_item *local_addr);

extern int		 rh_list_hn_max_len(struct rh_list *rh_list);


#ifdef __cplusplus
}
#endif

#endif /* _RHFUNC_H_ */
