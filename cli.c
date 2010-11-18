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

#include <netinet/in.h>
#include <arpa/inet.h>

#define __STDC_LIMIT_MACROS

#include <err.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "addrfunc.h"
#include "omping.h"
#include "cli.h"
#include "logging.h"

static void	conv_list_addrs(struct ai_list *ai_list, int ip_ver);
static void	conv_local_addr(struct ai_list *ai_list, struct ai_item *ai_local,
    const struct ifaddrs *ifa_local, int ip_ver, struct ai_item *local_addr);
static void	conv_params_mcast(int ip_ver, struct ai_item *mcast_addr, const char *mcast_addr_s,
    const char *port_s);
static uint16_t	conv_port(const struct sockaddr_storage *mcast_addr);
static int	parse_remote_addrs(int argc, char * const argv[], const char *port, int ip_ver,
    struct ai_list *ai_list);
static int	return_ip_ver(int ip_ver, const char *mcast_addr, const char *port,
    struct ai_list *ai_list);
static void	show_version(void);
static void	usage();

/*
 * Parse command line.
 * argc and argv are passed from main function. local_ifname will be allocated and filled by name
 * of local ethernet interface. ip_ver will be filled by forced ip version or will
 * be 0. mcast_addr will be filled by requested mcast address or will be NULL. Port will be filled
 * by requested port (string value) or will be NULL. ai_list will be initialized and requested
 * hostnames will be stored there. ttl is pointer where user set TTL or default TTL will be stored.
 */
int
cli_parse(struct ai_list *ai_list, int argc, char * const argv[], char **local_ifname, int *ip_ver,
    struct ai_item *local_addr, int *wait_time, struct ai_item *mcast_addr, uint16_t *port,
    uint8_t *ttl)
{
	struct ai_item *ai_item;
	struct ifaddrs *ifa_list, *ifa_local;
	char *ep;
	char *mcast_addr_s;
	const char *port_s;
	double numd;
	int ch;
	int force;
	int num;

	*ip_ver = 0;
	mcast_addr_s = NULL;
	*local_ifname = NULL;
	*wait_time = DEFAULT_WAIT_TIME;
	*ttl = DEFAULT_TTL;
	port_s = DEFAULT_PORT_S;
	force = 0;

	logging_set_verbose(0);

	while ((ch = getopt(argc, argv, "46FVvi:m:p:t:")) != -1) {
		switch (ch) {
		case '4':
			*ip_ver = 4;
			break;
		case '6':
			*ip_ver = 6;
			break;
		case 'F':
			force++;
			break;
		case 'V':
			show_version();
			exit(0);
			break;
		case 'v':
			logging_set_verbose(logging_get_verbose() + 1);
			break;
		case 'm':
			mcast_addr_s = optarg;
			break;
		case 'p':
			port_s = optarg;
                        break;
		case 't':
			num = strtol(optarg, &ep, 10);
			if (num <= 0 || num > UINT8_MAX || *ep != '\0') {
				warnx("illegal number, -t argument -- %s", optarg);
				goto error_usage_exit;
			}
			*ttl = num;
			break;
		case 'i':
			numd = strtod(optarg, &ep);
			if (numd < 0 || *ep != '\0') {
				warnx("illegal number, -i argument -- %s", optarg);
				goto error_usage_exit;
			}
			*wait_time = numd * 1000.0;
			break;
		case '?':
			goto error_usage_exit;
			/* NOTREACHED */
			break;

		}
	}

	argc -= optind;
	argv += optind;

	/*
	 * Param checking
	 */
	if (force < 1) {
		if (*wait_time < DEFAULT_WAIT_TIME) {
			warnx("illegal nmber, -i argument %u ms < %u ms. Use -F to force.",
			    *wait_time, DEFAULT_WAIT_TIME);
			goto error_usage_exit;
		}

		if (*ttl < DEFAULT_TTL) {
			warnx("illegal nmber, -t argument %u < %u. Use -F to force.",
			    *ttl, DEFAULT_TTL);
			goto error_usage_exit;
		}
	}

	if (force < 2) {
		if (*wait_time == 0) {
			warnx("illegal nmber, -i argument %u ms < 1 ms. Use -FF to force.",
			    *wait_time);
			goto error_usage_exit;
		}
	}

	TAILQ_INIT(ai_list);

	parse_remote_addrs(argc, argv, port_s, *ip_ver, ai_list);
	*ip_ver = return_ip_ver(*ip_ver, mcast_addr_s, port_s, ai_list);

	if (af_find_local_ai(ai_list, ip_ver, &ifa_list, &ifa_local, &ai_item) < 0) {
		errx(1, "Can't find local address in arguments");
	}

	/*
	 * First, we convert mcast addr to something useful
	 */
	conv_params_mcast(*ip_ver, mcast_addr, mcast_addr_s, port_s);

	/*
	 * Assign port from mcast_addr
	 */
	*port = conv_port(&mcast_addr->sas);

	/*
	 * Change ai_list to struct of sockaddr_storage(s)
	 */
	conv_list_addrs(ai_list, *ip_ver);

	/*
	 * Find local addr and copy that. Also remove that from list
	 */
	conv_local_addr(ai_list, ai_item, ifa_local, *ip_ver, local_addr);

	/*
	 * Store local ifname
	 */
	*local_ifname = strdup(ifa_local->ifa_name);
	if (*local_ifname == NULL) {
		errx(1, "Can't alloc memory");
	}

	freeifaddrs(ifa_list);

	return (0);

error_usage_exit:
	usage();
	exit(1);
	/* NOTREACHED */
	return (-1);
}

/*
 * Convert list of addrs of addrinfo to list of addrs of sockaddr_storage. This function will also
 * correctly free addrinfo(s) in list.
 */
static void
conv_list_addrs(struct ai_list *ai_list, int ip_ver)
{
	struct sockaddr_storage tmp_sas;
	struct addrinfo *ai_i;
	struct ai_item *ai_item_i;
	char *hn;

	TAILQ_FOREACH(ai_item_i, ai_list, entries) {
		hn = (char *)malloc(strlen(ai_item_i->host_name) + 1);
		if (hn == NULL) {
			errx(1, "Can't alloc memory");
		}

		memcpy(hn, ai_item_i->host_name, strlen(ai_item_i->host_name) + 1);
		ai_item_i->host_name = hn;

		for (ai_i = ai_item_i->ai; ai_i != NULL; ai_i = ai_i->ai_next) {
			if (af_ai_supported_ipv(ai_i) == ip_ver) {
				memset(&tmp_sas, 0, sizeof(tmp_sas));

				memcpy(&tmp_sas, ai_i->ai_addr, ai_i->ai_addrlen);

				freeaddrinfo(ai_item_i->ai);

				memcpy(&ai_item_i->sas, &tmp_sas, sizeof(tmp_sas));
				break;
			}
		}
	}
}

/*
 * Convert ifa_local addr to local_addr. ai_local is freed and removed from list.
 */
static void
conv_local_addr(struct ai_list *ai_list, struct ai_item *ai_local,
    const struct ifaddrs *ifa_local, int ip_ver, struct ai_item *local_addr)
{
	size_t addr_len;
	uint16_t port;

	switch (ifa_local->ifa_addr->sa_family) {
	case AF_INET:
		addr_len = sizeof(struct sockaddr_in);
		port = ((struct sockaddr_in *)&ai_local->sas)->sin_port;
		break;
	case AF_INET6:
		addr_len = sizeof(struct sockaddr_in6);
		port = ((struct sockaddr_in6 *)&ai_local->sas)->sin6_port;
		break;
	default:
		DEBUG_PRINTF("Internal program error");
		err(1, "Internal program error");
		break;
	}

	memcpy(&local_addr->sas, ifa_local->ifa_addr, addr_len);
	local_addr->host_name = ai_local->host_name;

	switch (ifa_local->ifa_addr->sa_family) {
	case AF_INET:
		((struct sockaddr_in *)&local_addr->sas)->sin_port = port;
		break;
	case AF_INET6:
		((struct sockaddr_in6 *)&local_addr->sas)->sin6_port = port;
		break;
	default:
		DEBUG_PRINTF("Internal program error");
		err(1, "Internal program error");
		break;
	}

	TAILQ_REMOVE(ai_list, ai_local, entries);

	free(ai_local);
}

static int
af_is_addr_mcast(const struct sockaddr_storage *addr)
{

	switch (addr->ss_family) {
	case AF_INET:
		return IN_MULTICAST(ntohl(((struct sockaddr_in *)addr)->sin_addr.s_addr));
		break;
	case AF_INET6:
		return IN6_IS_ADDR_MULTICAST(&((struct sockaddr_in6 *)addr)->sin6_addr);
		break;
	}

	return (0);
}

/*
 * Convert mcast_addr_s to mcast_addr ai_item
 */
static void
conv_params_mcast(int ip_ver, struct ai_item *mcast_addr, const char *mcast_addr_s,
    const char *port_s)
{
	struct addrinfo *ai_res, *ai_i;

	if (mcast_addr_s == NULL) {
		switch (ip_ver) {
		case 4:
			mcast_addr_s = DEFAULT_MCAST4_ADDR;
			break;
		case 6:
			mcast_addr_s = DEFAULT_MCAST6_ADDR;
			break;
		default:
			DEBUG_PRINTF("Internal program error");
			err(1, "Internal program error");
			break;
		}
	}

	mcast_addr->host_name = (char *)malloc(strlen(mcast_addr_s) + 1);
	if (mcast_addr->host_name == NULL) {
		errx(1, "Can't alloc memory");
	}
	memcpy(mcast_addr->host_name, mcast_addr_s, strlen(mcast_addr_s) + 1);

	ai_res = af_host_to_ai(mcast_addr_s, port_s, ip_ver);

	for (ai_i = ai_res; ai_i != NULL; ai_i = ai_i->ai_next) {
		if (af_ai_supported_ipv(ai_i) == ip_ver) {
			memcpy(&mcast_addr->sas, ai_i->ai_addr, ai_i->ai_addrlen);
			break;
		}
	}

	if (ai_i == NULL) {
		DEBUG_PRINTF("Internal program error");
		err(1, "Internal program error");
	}

	freeaddrinfo(ai_res);

	/*
	 * Test if addr is really multicast
	 */
	if (!af_is_addr_mcast(&mcast_addr->sas)) {
		errx(1, "Given address %s is not valid multicast address", mcast_addr_s);
	}
}

/*
 * Return port number in network order from mcast_addr
 */
static uint16_t
conv_port(const struct sockaddr_storage *mcast_addr)
{
	uint16_t port;

	switch (mcast_addr->ss_family) {
	case AF_INET:
		port = (((struct sockaddr_in *)mcast_addr)->sin_port);
		break;
	case AF_INET6:
		port = (((struct sockaddr_in6 *)mcast_addr)->sin6_port);
		break;
	default:
		DEBUG_PRINTF("Internal program error");
		err(1, "Internal program error");
		break;
	}

	return (port);
}

/*
 * Parse remote addresses. Return list of addresses taken from cli
 */
static int
parse_remote_addrs(int argc, char * const argv[], const char *port, int ip_ver,
    struct ai_list *ai_list)
{
	struct addrinfo *ai_res;
	struct ai_item *ai_item;
	int no_ai;
	int i;

	no_ai = 0;

	for (i = 0; i < argc; i++) {
		ai_res = af_host_to_ai(argv[i], port, ip_ver);
		if (!af_is_ai_in_list(ai_res, ai_list)) {
			if (af_ai_deep_is_loopback(ai_res)) {
				errx(1,"Address %s looks like loopback. Loopback ping is not "
				    "supported", argv[i]);
			}

			ai_item = (struct ai_item *)malloc(sizeof(struct ai_item));
			if (ai_item == NULL) {
				errx(1, "Can't alloc memory");
			}

			memset(ai_item, 0, sizeof(struct ai_item));
			ai_item->ai = ai_res;
			ai_item->host_name = argv[i];

			TAILQ_INSERT_TAIL(ai_list, ai_item, entries);
			DEBUG_PRINTF("new address \"%s\" added to list (position %d)", argv[i],
			    no_ai);
			no_ai++;
		} else {
			freeaddrinfo(ai_res);
		}
	}

	if (no_ai < 1) {
		warnx("at least one remote addresses should be specified");
		usage();
		exit(1);
	}

	return (no_ai);
}

/*
 * Return ip version to use. Algorithm is following:
 * - If user forced ip version, we will return that one.
 * - If user entered mcast addr, we will look, what it supports
 *   - if only one version is supported, we will return that version
 * - otherwise walk addresses and find out, what they support
 *   - test if every addresses support all versions.
 *     - If not, test that version for every other addresses
 *       - if all of them support that version -> return that version
 *       - if not -> return error
 *     - otherwise return 0 (item in find_local_addrinfo will be used but preferably ipv6)
 */
static int
return_ip_ver(int ip_ver, const char *mcast_addr, const char *port, struct ai_list *ai_list)
{
	struct addrinfo *ai_res;
	struct ai_item *aip;
	int mcast_ipver;
	int ipver_res, ipver_res2;

	if (ip_ver != 0) {
		DEBUG_PRINTF("user forced forced ip_ver is %d, using that", ip_ver);
		return (ip_ver);
	}

	if (mcast_addr != NULL) {
		ai_res = af_host_to_ai(mcast_addr, port, ip_ver);
		mcast_ipver = af_ai_deep_supported_ipv(ai_res);

		DEBUG2_PRINTF("mcast_ipver for %s is %d", mcast_addr, mcast_ipver);

		freeaddrinfo(ai_res);

		if (mcast_ipver == -1) {
			errx(1, "Mcast address %s doesn't support ipv4 or ipv6", mcast_addr);
		}

		if (mcast_ipver != 0) {
			DEBUG_PRINTF("mcast address for %s supports only ipv%d, using that",
			    mcast_addr, mcast_ipver);

			/*
			 * Walk thru all addresses to find out, what it supports
			 */
			TAILQ_FOREACH(aip, ai_list, entries) {
				ipver_res = af_ai_deep_supported_ipv(aip->ai);
				DEBUG2_PRINTF("ipver for %s is %d", aip->host_name, ipver_res);

				if (ipver_res == -1) {
					errx(1, "Host %s doesn't support ipv4 or ipv6",
					    aip->host_name);
				}

				if (ipver_res != 0 && ipver_res != mcast_ipver) {
					errx(1, "Multicast address is ipv%d but host %s supports"
					    " only ipv%d", mcast_ipver, aip->host_name, ipver_res);
				}
			}

			return (mcast_ipver);
		}
	}

	ipver_res = 0;

	/*
	 * Walk thru all addresses to find out, what it supports
	 */
	TAILQ_FOREACH(aip, ai_list, entries) {
		ipver_res = af_ai_deep_supported_ipv(aip->ai);
		DEBUG2_PRINTF("ipver for %s is %d", aip->host_name, ipver_res);

		if (ipver_res == -1) {
			errx(1, "Host %s doesn't support ipv4 or ipv6", aip->host_name);
		}

		if (ipver_res != 0) {
			break;
		}
	}

	if (ipver_res == 0) {
		/*
		 * Every address support every version
		 */
		DEBUG_PRINTF("Every address support all IP versions");
		return (0);
	}

	if (ipver_res != 0) {
		/*
		 * Host supports only one version.
		 * Test availability for that version on all hosts
		 */
		TAILQ_FOREACH(aip, ai_list, entries) {
			ipver_res2 = af_ai_deep_supported_ipv(aip->ai);
			DEBUG2_PRINTF("ipver for %s is %d", aip->host_name, ipver_res2);

			if (ipver_res2 == -1) {
				errx(1, "Host %s doesn't support ipv4 or ipv6", aip->host_name);
			}

			if (ipver_res2 != 0 && ipver_res2 != ipver_res) {
				/*
				 * Host doesn't support ip version of other members
				 */
				errx(1, "Host %s doesn't support IP version %d", aip->host_name,
				    ipver_res);
			}
		}
	}

	DEBUG_PRINTF("Every address support ipv%d", ipver_res);

	return (ipver_res);
}

/*
 * Show application version
 */
static void
show_version(void)
{

	printf("%s version %s\n", PROGRAM_NAME, PROGRAM_VERSION);
}

/*
 * Display application ussage
 */
static void
usage()
{

	printf("usage: %s [-46FVv] [-i interval] [-m mcast_addr] [-p port]\n", PROGRAM_NAME);
	printf("              [-t ttl] remote_addr...\n");
}
