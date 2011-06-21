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

#include <sys/socket.h>

#include <net/if.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include <err.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>

#include "rhfunc.h"
#include "omping.h"

/*
 * Add item to remote host list. Addr pointer is stored in rh_item. On fail, function returns NULL,
 * otherwise newly allocated rh_item is returned. dup_buf_items is number of items to be stored in
 * duplicate buffers. rate_limit_time is maximum time between two received packets.
 */
struct rh_item *
rh_list_add_item(struct rh_list *rh_list, struct ai_item *addr, int dup_buf_items,
    int rate_limit_time)
{
	struct rh_item *rh_item;
	struct rh_item_ci *ci;
	int i;

	rh_item = (struct rh_item *)malloc(sizeof(struct rh_item));
	if (rh_item == NULL) {
		return (NULL);
	}

	memset(rh_item, 0, sizeof(struct rh_item));

	rh_item->addr = addr;
	ci = &rh_item->client_info;

	if (dup_buf_items > 0) {
		ci->dup_buf_items = dup_buf_items;

		for (i = 0; i < 2; i++) {
			ci->dup_buffer[i] = (uint32_t *)malloc(dup_buf_items * sizeof(uint32_t));

			if (ci->dup_buffer[i] == NULL) {
				goto malloc_error;
			}

			memset(ci->dup_buffer[i], 0, dup_buf_items * sizeof(uint32_t));
		}
	}

	if (rate_limit_time > 0) {
		gcra_init(&rh_item->server_info.gcra, rate_limit_time, GCRA_BURST);
	}

	TAILQ_INSERT_TAIL(rh_list, rh_item, entries);

	return (rh_item);

malloc_error:
	for (i = 0; i < 2; i++) {
		free(rh_item->client_info.dup_buffer[i]);
	}
	free(rh_item);

	return (NULL);
}

/*
 * Create list of rh_items. It's also possible to pass ai_list to include every address from list to
 * newly allocated rh_list. dup_buf_items is number of items to be stored in duplicate buffers.
 * rate_limit_time is maximum time between two received packets.
 */
void
rh_list_create(struct rh_list *rh_list, struct ai_list *remote_addrs, int dup_buf_items,
    int rate_limit_time)
{
	struct ai_item *addr;
	struct rh_item *rh_item;

	TAILQ_INIT(rh_list);

	if (remote_addrs != NULL) {
		TAILQ_FOREACH(addr, remote_addrs, entries) {
			rh_item = rh_list_add_item(rh_list, addr, dup_buf_items, rate_limit_time);
			if (rh_item == NULL) {
				errx(1, "Can't alloc memory");
			}
		}
	}
}

/*
 * Find remote host with addr sa in list. rh_item pointer is returned on success otherwise NULL is
 * returned.
 */
struct rh_item *
rh_list_find(struct rh_list *rh_list, const struct sockaddr *sa)
{
	struct rh_item *rh_item;

	TAILQ_FOREACH(rh_item, rh_list, entries) {
		if (af_sockaddr_eq((const struct sockaddr *)&rh_item->addr->sas, sa))
			return (rh_item);
	}

	return (NULL);
}

/*
 * Free list from memory.
 */
void
rh_list_free(struct rh_list *rh_list)
{
	struct rh_item *rh_item;
	struct rh_item *rh_item_next;
	int i;

	rh_item = TAILQ_FIRST(rh_list);

	while (rh_item != NULL) {
		rh_item_next = TAILQ_NEXT(rh_item, entries);

		free(rh_item->client_info.server_info);
		free(rh_item->client_info.ses_id);

		for (i = 0; i < 2; i++) {
			free(rh_item->client_info.dup_buffer[i]);
		}

		free(rh_item);

		rh_item = rh_item_next;
	}

	TAILQ_INIT(rh_list);
}

/*
 * Generate CID for all items in rh_list
 */
void
rh_list_gen_cid(struct rh_list *rh_list, const struct ai_item *local_addr)
{
	struct rh_item *rh_item;

	TAILQ_FOREACH(rh_item, rh_list, entries) {
		util_gen_cid(rh_item->client_info.client_id, local_addr);
	}
}

/*
 * Return length of longest host name from rh_list list.
 */
int
rh_list_hn_max_len(struct rh_list *rh_list)
{
	struct rh_item *rh_item;
	size_t max_len;

	max_len = 0;
	TAILQ_FOREACH(rh_item, rh_list, entries) {
		if (strlen(rh_item->addr->host_name) > max_len) {
			max_len = strlen(rh_item->addr->host_name);
		}
	}

	return (max_len > INT_MAX ? INT_MAX : (int)max_len);
}

/*
 * Return number of items in rh_list.
 */
unsigned int
rh_list_length(const struct rh_list *rh_list)
{
	struct rh_item *rh_item;
	unsigned int res;

	res = 0;

	TAILQ_FOREACH(rh_item, rh_list, entries) {
		res++;
	}

	return (res);
}

/*
 * Move all items in rh_list to finish state. fs is which part of remote host is put to finish
 * state. This may mean, that server state is put to RH_SS_FINISHING and/or client state is moved
 * to RH_CS_STOP
 */
void
rh_list_put_to_finish_state(struct rh_list *rh_list, enum rh_list_finish_state fs)
{
	struct rh_item *rh_item;

	TAILQ_FOREACH(rh_item, rh_list, entries) {
		if (fs == RH_LFS_SERVER || fs == RH_LFS_BOTH) {
			rh_item->server_info.state = RH_SS_FINISHING;
		}
		if (fs == RH_LFS_CLIENT || fs == RH_LFS_BOTH) {
			rh_item->client_info.state = RH_CS_STOP;
		}
	}
}
