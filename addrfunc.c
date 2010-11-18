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
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>

#include "addrfunc.h"
#include "logging.h"

/*
 * Compares two addrinfo structures. Family, socktype, protocol and sockaddr are
 * compared. This one don't goes to deep, so compares really only one struct not
 * list of them.
 */
int
af_ai_eq(const struct addrinfo *a1, const struct addrinfo *a2) {
	return ((a1->ai_family == a2->ai_family) &&
	    (a1->ai_socktype == a2->ai_socktype) &&
	    (a1->ai_protocol == a2->ai_protocol) &&
	    af_sockaddr_eq(a1->ai_addr, a2->ai_addr));
}

/*
 * Deep compare of two addrinfo structures. Internally calls addrinfo_eq
 * function to compare one struct. It returns 1, if at least one addr from a1
 * matches with at least on addr from a2.
 */
int
af_ai_deep_eq(const struct addrinfo *a1, const struct addrinfo *a2)
{
	const struct addrinfo *a1_i, *a2_i;

	for (a1_i = a1; a1_i != NULL; a1_i = a1_i->ai_next) {
		for (a2_i = a2; a2_i != NULL; a2_i = a2_i->ai_next) {
			if (af_ai_eq(a1_i, a2_i)) {
				return (1);
			}
		}
	}

	return (0);
}

/*
 * Test if given list of addrinfo ai is loopback address or not. Returns > 0 if
 * addrinfo list ai is loopback, otherwise 0. This one goes to deep.
 */
int
af_ai_deep_is_loopback(const struct addrinfo *a1)
{
	const struct addrinfo *a1_i;

	for (a1_i = a1; a1_i != NULL; a1_i = a1_i->ai_next) {
		if (af_ai_is_loopback(a1_i)) {
			return (1);
		}
	}

	return (0);
}

/* Deeply test what IP versions are supported on given ai_addr. Can return 4 (only ipv4 is
 * supported), 6 (only ipv6 is supported), 0 (both ipv4 and ipv6 are supported) and -1 (nether ipv4
 * or ipv6 are supported)
 */
int
af_ai_deep_supported_ipv(const struct addrinfo *ai_addr)
{
	const struct addrinfo *ai_iter;
	int ip4, ip6;

	ip4 = 0;
	ip6 = 0;

	for (ai_iter = ai_addr; ai_iter != NULL; ai_iter = ai_iter->ai_next) {
		switch (af_ai_supported_ipv(ai_iter)) {
		case 4:
			ip4 = 1;
			break;
		case 6:
			ip6 = 1;
			break;
		case 0:
			DEBUG_PRINTF("internal program error.");
			err(1, "Internal program error");
			break;
		}
	}

	if (ip4 && ip6)
		return (0);
	if (ip6)
		return (6);
	if (ip4)
		return (4);

	return (-1);
}

/*
 * Test if given addrinfo ai is loopback address or not. Returns > 0 if
 * addrinfo ai is loopback, otherwise 0. This one don't goes to deep,
 * so compares really only one struct not list of them.
 */
int
af_ai_is_loopback(const struct addrinfo *ai)
{
	int res;

	switch (ai->ai_family) {
	case PF_INET:
		res = ntohl(((struct sockaddr_in *)(ai->ai_addr))->sin_addr.s_addr) >> 24 == 0x7f;
		break;
	case PF_INET6:
		res = IN6_IS_ADDR_LOOPBACK(&((struct sockaddr_in6 *)(ai->ai_addr))->sin6_addr);
		break;
	default:
		DEBUG_PRINTF("Unknown ai family %d", ai->ai_family);
		errx(1, "Unknown ai family %d", ai->ai_family);
	}

	return (res);
}

/*
 * Free content of ai_list. List must have sas field active (not ai field)
 */
void
af_ai_list_free(struct ai_list *ai_list)
{
	struct ai_item *ai_item;

	while (!TAILQ_EMPTY(ai_list)) {
             ai_item = TAILQ_FIRST(ai_list);
             TAILQ_REMOVE(ai_list, ai_item, entries);
             free(ai_item->host_name);
             free(ai_item);
     }
}

/* Return supported ip version. This function doesn't go deeply to structure. It can return 4 (ipv4
 * is supported), 6 (ipv6 is supported) or 0 (nether ipv4 or ipv6 are supported).
 */
int
af_ai_supported_ipv(const struct addrinfo *ai_addr)
{
	int ipv;

	ipv = 0;

	switch (ai_addr->ai_family) {
	case PF_INET:
		ipv = 4;
		break;
	case PF_INET6:
		ipv = 6;
		break;
	}

	return (ipv);
}

/*
 * Make result address from two addresses a1 and a2. addr_source is primary source of address (for
 * ipv6 also scope, ...) and can be 1 or 2. port_source address is for copy of port number. Result
 * is stored in res.
 * Function can return -1 on fail (addr_source or port_number is not 1 or 2), otherwise 0.
 */
int
af_copy_addr(const struct sockaddr_storage *a1, const struct sockaddr_storage *a2, int addr_source,
    int port_source, struct sockaddr_storage *res)
{
	const struct sockaddr_storage *sas;

	if (addr_source != 1 && addr_source != 2) {
		return (-1);
	}

	if (port_source != 1 && port_source != 2) {
		return (-1);
	}

	sas = (addr_source == 1 ? a1 : a2);
	memcpy(res, sas, sizeof(struct sockaddr_storage));

	if (addr_source == port_source) {
		return (0);
	}

	sas = (port_source == 1 ? a1 : a2);

	switch (sas->ss_family) {
	case AF_INET:
		((struct sockaddr_in *)res)->sin_port = ((struct sockaddr_in *)sas)->sin_port;
		break;
	case AF_INET6:
		((struct sockaddr_in6 *)res)->sin6_port = ((struct sockaddr_in6 *)sas)->sin6_port;
		break;
	default:
		DEBUG_PRINTF("Unknown sas family %d", sas->ss_family);
		errx(1, "Unknown sas family %d", sas->ss_family);

	}

	return (0);
}

/*
 * Tries to find local address in ai_list with given ip_ver. Returns 0 on success, otherwise -1.
 * It also changes ifa_list (result of getaddrs), ifa_local (local addr) and ai_item (addrinfo item
 * which matches ifa_local).
 */
int
af_find_local_ai(const struct ai_list *ai_list, int *ip_ver, struct ifaddrs **ifa_list,
    struct ifaddrs **ifa_local, struct ai_item **ai_item)
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

	TAILQ_FOREACH(aip, ai_list, entries) {
		for (ai_i = aip->ai; ai_i != NULL; ai_i = ai_i->ai_next) {
			for (ifa_i = ifa; ifa_i != NULL; ifa_i = ifa_i->ifa_next) {
				if (ifa_i->ifa_addr->sa_family != AF_INET &&
				    ifa_i->ifa_addr->sa_family != AF_INET6) {
					continue ;
				}

				logging_sa_to_str(ifa_i->ifa_addr, sa_str, sizeof(sa_str));
				logging_sa_to_str(ai_i->ai_addr, sa_str2, sizeof(sa_str2));
				DEBUG2_PRINTF("Comparing %s(%s) with %s", sa_str, ifa_i->ifa_name,
				    sa_str2);

				if (af_sockaddr_eq(ifa_i->ifa_addr, ai_i->ai_addr)) {
					res = af_is_supported_local_ifa(ifa_i, *ip_ver);

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
 * Convert host_name and port with ip ver (4 or 6) to addrinfo.
 * Wrapper on getaddrinfo
 */
struct addrinfo *
af_host_to_ai(const char *host_name, const char *port, int ip_ver)
{
	struct addrinfo ai_hints, *ai_res0, *ai_i;
	int error;
	char ai_s[LOGGING_SA_TO_STR_LEN];

	memset(&ai_hints, 0, sizeof(ai_hints));
	switch (ip_ver) {
	case 0:
		ai_hints.ai_family = PF_UNSPEC;
		break;
	case 4:
		ai_hints.ai_family = PF_INET;
		break;
	case 6:
		ai_hints.ai_family = PF_INET6;
		break;
	default:
		errx(1, "Unknown PF Family");
		/* NOTREACHED */
	}

	ai_hints.ai_socktype = SOCK_DGRAM;
	ai_hints.ai_protocol = IPPROTO_UDP;
	ai_hints.ai_flags = AI_PASSIVE;

	DEBUG_PRINTF("getaddrinfo for \"%s\" port %s ip_ver %d", host_name,
	    port, ip_ver);
	error = getaddrinfo(host_name, port, &ai_hints, &ai_res0);
	if (error != 0) {
		errx(1, "Can't get addr info for %s: %s", host_name, gai_strerror(error));
	}

	if (logging_get_verbose() >= LOGGING_LEVEL_DEBUG2) {
		for (ai_i = ai_res0; ai_i != NULL; ai_i = ai_i->ai_next) {
			logging_ai_to_str(ai_i, ai_s, sizeof(ai_s));
			DEBUG2_PRINTF("%s", ai_s);
		}
	}

	return (ai_res0);
}

/*
 * Test if addrinfo a1 is included in ai_list list. Return 1 if a1 is included, otherwise 0.
 */
int
af_is_ai_in_list(const struct addrinfo *a1, const struct ai_list *ai_list)
{
	struct ai_item *aip;

	TAILQ_FOREACH(aip, ai_list, entries) {
		if (af_ai_deep_eq(a1, aip->ai))
			return (1);
	}

	return (0);
}

/*
 * Test if ifa is supported device.
 * Such device must:
 * - not be loopback
 * - be up
 * - support multicast
 * - support given ip_ver
 * Function returns 0, if device doesn't fulfill requirements. 1, if device supports all
 * requirements and 2, if device support requirements and ip_ver is set to 0 but device supports
 * ipv4.
 */
int
af_is_supported_local_ifa(const struct ifaddrs *ifa, int ip_ver)
{
	char ai_s[LOGGING_SA_TO_STR_LEN];

	logging_sa_to_str(ifa->ifa_addr, ai_s, sizeof(ai_s));

	if (ifa->ifa_flags & IFF_LOOPBACK) {
		DEBUG2_PRINTF("%s with addr %s is loopback", ifa->ifa_name, ai_s);

		return (0);
	}

	if (!(ifa->ifa_flags & IFF_UP)) {
		DEBUG2_PRINTF("%s with addr %s is not up", ifa->ifa_name, ai_s);

		return (0);
	}

	if (!(ifa->ifa_flags & IFF_MULTICAST)) {
		DEBUG2_PRINTF("%s with addr %s doesn't support mcast", ifa->ifa_name, ai_s);

		return (0);
	}

	if (ip_ver != 0 && af_sa_supported_ipv(ifa->ifa_addr) != ip_ver) {
		DEBUG2_PRINTF("%s doesn't support requested ipv%d", ai_s, ip_ver);

		return (0);
	}


	if (ip_ver == 0 && af_sa_supported_ipv(ifa->ifa_addr) == 4) {
		DEBUG2_PRINTF("%s doesn't support ipv6. Saving ipv4 as fallback", ai_s);

		return (2);
	}

	DEBUG_PRINTF("Found local addr %s as device %s", ai_s, ifa->ifa_name);
	return (1);
}

/*
 * Return length of sockaddr structure.
 */
socklen_t
af_sa_len(const struct sockaddr *sa)
{
	socklen_t res;

	switch (sa->sa_family) {
	case AF_INET:
		res = sizeof(struct sockaddr_in);
		break;
	case AF_INET6:
		res = sizeof(struct sockaddr_in6);
		break;
	default:
		DEBUG_PRINTF("Internal program error");
		errx(1,"Internal program error");
		break;
	}

	return (res);
}

/*
 * Return supported ip version. This function doesn't go deeply to structure. It can return 4 (ipv4
 * is supported), 6 (ipv6 is supported) or 0 (nether ipv4 or ipv6 are supported).
 */
int
af_sa_supported_ipv(const struct sockaddr *sa)
{
	int ipv;

	ipv = 0;

	switch (sa->sa_family) {
	case AF_INET:
		ipv = 4;
		break;
	case AF_INET6:
		ipv = 6;
		break;
	}

	return (ipv);
}

/*
 * Convert sockaddr address to string. Returned value is dst or NULL on fail.
 */
char *
af_sa_to_str(const struct sockaddr *sa, char dst[INET6_ADDRSTRLEN])
{

	dst[0] = 0;

	switch (sa->sa_family) {
	case PF_INET:
		inet_ntop(sa->sa_family, &((struct sockaddr_in *)(sa))->sin_addr, dst,
		    INET6_ADDRSTRLEN);
		break;
	case PF_INET6:
		inet_ntop(sa->sa_family, &((struct sockaddr_in6 *)(sa))->sin6_addr, dst,
		    INET6_ADDRSTRLEN);
		break;
	default:
		return (NULL);
	}

	return (dst);
}

/*
 * Return length of sockaddr_storage structure.
 */
socklen_t
af_sas_len(const struct sockaddr_storage *sas)
{
	return (af_sa_len((const struct sockaddr *)sas));
}

/*
 * Compares two sockaddr structures. Only family and addr is compared. If
 * sockaddr differs 0 is returned, otherwise not 0.
 */
int
af_sockaddr_eq(const struct sockaddr *sa1, const struct sockaddr *sa2)
{
	int res;

	res = 0;

	if (sa1->sa_family == sa2->sa_family) {
		switch (sa1->sa_family) {
		case AF_INET:
			res = (((struct sockaddr_in *)sa1)->sin_addr.s_addr ==
			    ((struct sockaddr_in *)sa2)->sin_addr.s_addr);
			break;
		case AF_INET6:
			res = IN6_ARE_ADDR_EQUAL(
			    &((struct sockaddr_in6 *)sa1)->sin6_addr,
			    &((struct sockaddr_in6 *)sa2)->sin6_addr);
			break;
		default:
			err(1, "Unknown sockaddr family");
			break;
		}
	}

	return (res);
}
