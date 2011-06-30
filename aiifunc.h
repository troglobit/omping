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

#ifndef _AIIFUNC_H_
#define _AIIFUNC_H_

#include <sys/types.h>

#include <sys/queue.h>
#include <sys/socket.h>

#include <net/if.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include <ifaddrs.h>
#include <netdb.h>

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Address info item. This is intended to use with TAILQ list.
 */
struct ai_item {
	union {
		struct addrinfo *ai;
		struct sockaddr_storage sas;
	};
	char		*host_name;
	TAILQ_ENTRY(ai_item) entries;
};

/*
 * Typedef of TAILQ head of list of ai_item(s)
 */
TAILQ_HEAD(aii_list, ai_item);

extern void		 aii_list_free(struct aii_list *aii_list);

extern void		 aii_list_ai_to_sa(struct aii_list *aii_list, int ip_ver);

extern int		 aii_find_local(const struct aii_list *aii_list, int *ip_ver,
    struct ifaddrs **ifa_list, struct ifaddrs **ifa_local, struct ai_item **ai_item,
    unsigned int if_flags);

extern void		 aii_ifa_local_to_ai(struct aii_list *aii_list, struct ai_item *ai_local,
    const struct ifaddrs *ifa_local, int ip_ver, struct ai_item *local_addr, int *single_addr);

extern int		 aii_ipbc_to_ai(struct ai_item *ipbc_addr, const char *ipbc_addr_s,
    const char *port_s, const struct ifaddrs *ifa_local);

extern int		 aii_is_ai_in_list(const struct addrinfo *a1,
    const struct aii_list *aii_list);

extern void		 aii_mcast_to_ai(int ip_ver, struct ai_item *mcast_addr,
    const char *mcast_addr_s, const char *port_s);

extern int		 aii_parse_remote_addrs(struct aii_list *aii_list, int argc,
    char * const argv[], const char *port, int ip_ver);

extern int		 aii_return_ip_ver(struct aii_list *aii_list, int ip_ver,
    const char *mcast_addr, const char *port);

#ifdef __cplusplus
}
#endif

#endif /* _AIIFUNC_H_ */
