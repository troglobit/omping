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

#ifndef _RHFUNC_H_
#define _RHFUNC_H_

#include <sys/types.h>

#include <sys/queue.h>
#include <sys/socket.h>

#include <ifaddrs.h>
#include <netdb.h>

#include "addrfunc.h"
#include "gcra.h"
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
	RH_SS_FINISHING,
};

enum rh_client_stop_reason {
	RH_CSR_NONE,
	RH_CSR_SERVER,
	RH_CSR_TO_SEND_EXHAUSTED,
	RH_CSR_SEND_MAXIMUM,
	RH_CSR_REMOTE_VERSION_RECEIVED,
};

enum rh_list_finish_state {
	RH_LFS_CLIENT,
	RH_LFS_SERVER,
	RH_LFS_BOTH,
};

/*
 * Remote host info item, client info part
 */
struct rh_item_ci {
	enum		rh_client_state state;
	char		client_id[CLIENTID_LEN];
	struct timeval	last_init_ts;
	struct timeval	last_query_ts;
	char		*server_info;
	char		*ses_id;
	uint32_t	*dup_buffer[2];
	size_t		server_info_len;
	size_t		ses_id_len;
	double		avg_rtt[2];
	double		m2_rtt[2];
	double		rtt_max[2];
	double		rtt_min[2];
	uint64_t	no_err_msgs;
	uint64_t	no_dups[2];
	uint64_t	no_received[2];
	uint64_t	no_sent;
	uint32_t	first_mcast_seq;
	uint32_t	lru_seq_num; /* Last Received Unicast seq number */
	uint32_t	seq_num;
	int		dup_buf_items;
	int		seq_num_overflow;
};

/*
 * Remote host info item, server info part
 */
struct rh_item_si {
	enum			rh_server_state state;
	char			ses_id[SESSIONID_LEN];
	struct gcra_item	gcra;
	struct timeval		last_init_ts;
};

/*
 * Remote host info item. This is intended to use with TAILQ list.
 */
struct rh_item {
	struct ai_item	*addr;
	struct rh_item_ci client_info;
	struct rh_item_si server_info;
	TAILQ_ENTRY(rh_item) entries;
};

/*
 * Typedef of TAILQ head of list of rh_item(s)
 */
TAILQ_HEAD(rh_list, rh_item);

extern struct rh_item	*rh_list_add_item(struct rh_list *rh_list, struct ai_item *addr,
    int dup_buf_items, int rate_limit_time);

extern void		 rh_list_create(struct rh_list *rh_list, struct ai_list *remote_addrs,
    int dup_buf_items, int rate_limit_time);

extern struct rh_item	*rh_list_find(struct rh_list *rh_list, const struct sockaddr *sa);
extern void		 rh_list_free(struct rh_list *rh_list);

extern void		 rh_list_gen_cid(struct rh_list *rh_list,
    const struct ai_item *local_addr);

extern int		 rh_list_hn_max_len(struct rh_list *rh_list);

extern unsigned int	 rh_list_length(const struct rh_list *rh_list);

extern void		 rh_list_put_to_finish_state(struct rh_list *rh_list,
    enum rh_list_finish_state fs);

#ifdef __cplusplus
}
#endif

#endif /* _RHFUNC_H_ */
