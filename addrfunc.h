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

#ifndef _ADDRFUNC_H_
#define _ADDRFUNC_H_

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
 * Cast s to sockaddr storage pointer. Used mainly with sockaddr_storage
 */
#define AF_CAST_SA(s)		((struct sockaddr *)s)

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
TAILQ_HEAD(ai_list, ai_item);

extern int		 af_ai_eq(const struct addrinfo *a1, const struct addrinfo *a2);
extern int		 af_ai_deep_eq(const struct addrinfo *a1, const struct addrinfo *a2);
extern int		 af_ai_deep_is_loopback(const struct addrinfo *a1);
extern int		 af_ai_deep_supported_ipv(const struct addrinfo *ai_addr);
extern int		 af_ai_is_dup(const struct addrinfo *ai_list, const struct addrinfo *ai);
extern int		 af_ai_is_loopback(const struct addrinfo *ai);
extern void		 af_ai_list_free(struct ai_list *ai_list);
extern int		 af_ai_supported_ipv(const struct addrinfo *ai_addr);

extern int		 af_copy_addr(const struct sockaddr_storage *a1,
    const struct sockaddr_storage *a2, int addr_source, int port_source,
    struct sockaddr_storage *res);

extern void		 af_copy_sa_to_sas(struct sockaddr_storage *sas,
    const struct sockaddr *sa);

extern void		 af_create_any_addr(struct sockaddr *sa, int sa_family, uint16_t port);

extern int		 af_find_local_ai(const struct ai_list *ai_list, int *ip_ver,
    struct ifaddrs **ifa_list, struct ifaddrs **ifa_local, struct ai_item **ai_item,
    unsigned int if_flags);

extern struct addrinfo	*af_host_to_ai(const char *host_name, const char *port, int ip_ver);
extern int		 af_is_ai_in_list(const struct addrinfo *a1, const struct ai_list *ai_list);
extern int		 af_is_sa_mcast(const struct sockaddr *addr);

extern int		 af_is_supported_local_ifa(const struct ifaddrs *ifa, int ip_ver,
    unsigned int if_flags);

extern socklen_t	 af_sa_len(const struct sockaddr *sa);
extern uint16_t		 af_sa_port(const struct sockaddr *addr);
extern void		 af_sa_set_port(struct sockaddr *addr, uint16_t port);
extern int		 af_sa_supported_ipv(const struct sockaddr *sa);
extern void		 af_sa_to_any_addr(struct sockaddr *dest, const struct sockaddr *src);
extern char		*af_sa_to_str(const struct sockaddr *sa, char dst[INET6_ADDRSTRLEN]);
extern socklen_t	 af_sas_len(const struct sockaddr_storage *sas);
extern int		 af_sockaddr_eq(const struct sockaddr *sa1, const struct sockaddr *sa2);

#ifdef __cplusplus
}
#endif

#endif /* _ADDRFUNC_H_ */
