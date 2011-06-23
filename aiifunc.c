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
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>

#include "addrfunc.h"
#include "aiifunc.h"
#include "logging.h"

/*
 * Free content of aii_list. List must have sas field active (not ai field)
 */
void
aii_list_free(struct aii_list *aii_list)
{
	struct ai_item *ai_item;
	struct ai_item *ai_item_next;

	ai_item = TAILQ_FIRST(aii_list);

	while (ai_item != NULL) {
		ai_item_next = TAILQ_NEXT(ai_item, entries);

		free(ai_item->host_name);
		free(ai_item);

		ai_item = ai_item_next;
	}

	TAILQ_INIT(aii_list);
}

/*
 * Tries to find local address in aii_list with given ip_ver. if_flags may be set to bit mask with
 * IFF_MULTICAST and/or IFF_BROADCAST and only network interface with that flags will be accepted.
 * Returns 0 on success, otherwise -1.
 * It also changes ifa_list (result of getaddrs), ifa_local (local addr) and ai_item (addrinfo item
 * which matches ifa_local).
 */
int
aii_find_local(const struct aii_list *aii_list, int *ip_ver, struct ifaddrs **ifa_list,
    struct ifaddrs **ifa_local, struct ai_item **ai_item, unsigned int if_flags)
{
	struct addrinfo *ai_i;
	struct ai_item *aip;
	struct ifaddrs *ifa, *ifa_i;
	char sa_str[LOGGING_SA_TO_STR_LEN];
	char sa_str2[LOGGING_SA_TO_STR_LEN];
	int ipv4_fallback;
	int res;

	*ifa_local = NULL;
	ipv4_fallback = 0;

	if (getifaddrs(&ifa) == -1) {
		err(1, "getifaddrs");
	}

	TAILQ_FOREACH(aip, aii_list, entries) {
		for (ai_i = aip->ai; ai_i != NULL; ai_i = ai_i->ai_next) {
			if (af_ai_is_dup(aip->ai, ai_i)) {
				logging_sa_to_str(ai_i->ai_addr, sa_str, sizeof(sa_str));
				DEBUG2_PRINTF("Found duplicate addr %s", sa_str);
				continue ;
			}

			for (ifa_i = ifa; ifa_i != NULL; ifa_i = ifa_i->ifa_next) {
				if (ifa_i->ifa_addr == NULL ||
				    (ifa_i->ifa_addr->sa_family != AF_INET &&
				    ifa_i->ifa_addr->sa_family != AF_INET6)) {
					continue ;
				}

				logging_sa_to_str(ifa_i->ifa_addr, sa_str, sizeof(sa_str));
				logging_sa_to_str(ai_i->ai_addr, sa_str2, sizeof(sa_str2));
				DEBUG2_PRINTF("Comparing %s(%s) with %s", sa_str, ifa_i->ifa_name,
				    sa_str2);

				if (af_sockaddr_eq(ifa_i->ifa_addr, ai_i->ai_addr)) {
					res = af_is_supported_local_ifa(ifa_i, *ip_ver, if_flags);

					if (res == 1 || res == 2) {
						if (*ifa_local != NULL && ipv4_fallback == 0)
							goto multiple_match_error;

						*ifa_list = ifa;
						*ifa_local = ifa_i;
						*ai_item = aip;

						if (*ip_ver == 0) {
							/*
							 * Device supports ipv6
							 */
							*ip_ver = 6;
							DEBUG2_PRINTF("Supports ipv6");
						}

						if (res == 2) {
							/*
							 * Set this item as ipv4 fallback
							 */
							ipv4_fallback++;
							DEBUG2_PRINTF("Supports ipv4 - fallback");
						}
					}
				}
			}
		}
	}

	if (*ip_ver == 0 && *ifa_local != NULL) {
		if (ipv4_fallback > 1)
			goto multiple_match_error;

		*ip_ver = 4;
	}

	if (*ifa_local != NULL) {
		return (0);
	}

	DEBUG_PRINTF("Can't find local addr");
	return (-1);

multiple_match_error:
	errx(1, "Multiple local interfaces match parameters.");
	return (-1);
}

/*
 * Test if addrinfo a1 is included in aii_list list. Return 1 if a1 is included, otherwise 0.
 */
int
aii_is_ai_in_list(const struct addrinfo *a1, const struct aii_list *aii_list)
{
	struct ai_item *aip;

	TAILQ_FOREACH(aip, aii_list, entries) {
		if (af_ai_deep_eq(a1, aip->ai))
			return (1);
	}

	return (0);
}
