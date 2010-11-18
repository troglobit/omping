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

/*
 * Add item to remote host list. Addr pointer is stored in rh_item. On fail, function returns NULL,
 * otherwise newly allocated rh_item is returned.
 */
struct rh_item *
rh_list_add_item(struct rh_list *rh_list, struct ai_item *addr)
{
	struct rh_item *rh_item;

	rh_item = (struct rh_item *)malloc(sizeof(struct rh_item));
	if (rh_item == NULL) {
		return (NULL);
	}

	memset(rh_item, 0, sizeof(struct rh_item));

	rh_item->addr = addr;

	TAILQ_INSERT_TAIL(rh_list, rh_item, entries);

	return (rh_item);
}

/*
 * Create list of rh_items. It's also possible to pass ai_list to include every address from list to
 * newly allocated rh_list.
 */
void
rh_list_create(struct rh_list *rh_list, struct ai_list *remote_addrs)
{
	struct ai_item *addr;
	struct rh_item *rh_item;

	TAILQ_INIT(rh_list);

	if (remote_addrs != NULL) {
		TAILQ_FOREACH(addr, remote_addrs, entries) {
			rh_item = rh_list_add_item(rh_list, addr);
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

        while (!TAILQ_EMPTY(rh_list)) {
             rh_item = TAILQ_FIRST(rh_list);
             TAILQ_REMOVE(rh_list, rh_item, entries);
             free(rh_item->client_info.ses_id);
             free(rh_item);
     }
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
