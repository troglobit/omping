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

#define __STDC_LIMIT_MACROS

#include <sys/types.h>

#include <netinet/in.h>
#include <arpa/inet.h>

#include <err.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "addrfunc.h"
#include "omping.h"
#include "cli.h"
#include "cliprint.h"
#include "logging.h"

/*
 * Function prototypes
 */
static void	conv_local_addr(struct aii_list *aii_list, struct ai_item *ai_local,
    const struct ifaddrs *ifa_local, int ip_ver, struct ai_item *local_addr, int *single_addr);

/*
 * Parse command line.
 * argc and argv are passed from main function. local_ifname will be allocated and filled by name
 * of local ethernet interface. ip_ver will be filled by forced ip version or will
 * be 0. mcast_addr will be filled by requested mcast address or will be NULL. Port will be filled
 * by requested port (string value) or will be NULL. aii_list will be initialized and requested
 * hostnames will be stored there. ttl is pointer where user set TTL or default TTL will be stored.
 * single_addr is boolean set if only one remote address is entered. quiet is flag for quiet mode.
 * cont_stat is flag for enable continuous statistic. timeout_time is number of miliseconds after
 * which client exits regardless to number of received/sent packets. wait_for_finish_time is number
 * of miliseconds to wait before exit to allow other nodes not to screw up final statistics.
 * dup_buf_items is number of items which should be stored in duplicate packet detection buffer.
 * Default is MIN_DUP_BUF_ITEMS for intervals > 1, or DUP_BUF_SECS value divided by ping interval
 * in seconds or 0, which is used for disabling duplicate detection. rate_limit_time is maximum
 * time between two received packets. sndbuf_size is size of socket buffer to allocate for sending
 * packets. rcvbuf_size is size of socket buffer to allocate for receiving packets. Both
 * sndbuf_size and rcvbuf_size are set to 0 if user doesn't supply option. send_count_queries is by
 * default set to 0, but may be overwritten by user and it means that after sending that number of
 * queries, client is put to stop state. auto_exit is boolean variable which is enabled by default
 * and can be disabled by -E option. If auto_exit is enabled, loop will end if every client is in
 * STOP state.
 */
int
cli_parse(struct aii_list *aii_list, int argc, char * const argv[], char **local_ifname,
    int *ip_ver, struct ai_item *local_addr, int *wait_time,
    enum sf_transport_method *transport_method, struct ai_item *mcast_addr, uint16_t *port,
    uint8_t *ttl, int *single_addr, int *quiet, int *cont_stat, int *timeout_time,
    int *wait_for_finish_time, int *dup_buf_items, int *rate_limit_time, int *sndbuf_size,
    int *rcvbuf_size, uint64_t *send_count_queries,int *auto_exit, enum omping_op_mode *op_mode)
{
	struct ai_item *ai_item;
	struct ifaddrs *ifa_list, *ifa_local;
	char *ep;
	char *mcast_addr_s;
	const char *port_s;
	double numd;
	int ch;
	int force;
	int no_ai;
	int num;
	int res;
	int rate_limit_time_set;
	int show_ver;
	int wait_for_finish_time_set;
	unsigned int ifa_flags;

	*auto_exit = 1;
	*cont_stat = 0;
	*dup_buf_items = MIN_DUP_BUF_ITEMS;
	*ip_ver = 0;
	*local_ifname = NULL;
	mcast_addr_s = NULL;
	*op_mode = OMPING_OP_MODE_NORMAL;
	*quiet = 0;
	*send_count_queries = 0;
	*sndbuf_size = 0;
	*single_addr = 0;
	*rate_limit_time = 0;
	*rcvbuf_size = 0;
	*timeout_time = 0;
	*ttl = DEFAULT_TTL;
	*transport_method = SF_TM_ASM;
	*wait_time = DEFAULT_WAIT_TIME;
	*wait_for_finish_time = 0;

	force = 0;
	ifa_flags = IFF_MULTICAST;
	port_s = DEFAULT_PORT_S;
	rate_limit_time_set = 0;
	show_ver = 0;
	wait_for_finish_time_set = 0;

	logging_set_verbose(0);

	while ((ch = getopt(argc, argv, "46CDEFqVvc:i:M:m:O:p:R:r:S:T:t:w:")) != -1) {
		switch (ch) {
		case '4':
			*ip_ver = 4;
			break;
		case '6':
			*ip_ver = 6;
			break;
		case 'C':
			(*cont_stat)++;
			break;
		case 'D':
			*dup_buf_items = 0;
			break;
		case 'E':
			*auto_exit = 0;
			break;
		case 'F':
			force++;
			break;
		case 'q':
			(*quiet)++;
			break;
		case 'V':
			show_ver++;
			break;
		case 'v':
			logging_set_verbose(logging_get_verbose() + 1);
			break;
		case 'c':
			numd = strtod(optarg, &ep);
			if (numd < 1 || *ep != '\0' || numd >= ((uint64_t)~0)) {
				warnx("illegal number, -c argument -- %s", optarg);
				goto error_usage_exit;
			}
			*send_count_queries= (uint64_t)numd;
			break;
		case 'i':
			numd = strtod(optarg, &ep);
			if (numd < 0 || *ep != '\0' || numd * 1000 > INT32_MAX) {
				warnx("illegal number, -i argument -- %s", optarg);
				goto error_usage_exit;
			}
			*wait_time = (int)(numd * 1000.0);
			break;
		case 'M':
			if (strcmp(optarg, "asm") == 0) {
				*transport_method = SF_TM_ASM;
				ifa_flags = IFF_MULTICAST;
			} else if (strcmp(optarg, "ssm") == 0 && sf_is_ssm_supported()) {
				*transport_method = SF_TM_SSM;
				ifa_flags = IFF_MULTICAST;
			} else if (strcmp(optarg, "ipbc") == 0 && sf_is_ipbc_supported()) {
				*transport_method = SF_TM_IPBC;
				ifa_flags = IFF_BROADCAST;
			} else {
				warnx("illegal parameter, -M argument -- %s", optarg);
				goto error_usage_exit;
			}
			break;
		case 'm':
			mcast_addr_s = optarg;
			break;
		case 'O':
			if (strcmp(optarg, "normal") == 0) {
				*op_mode = OMPING_OP_MODE_NORMAL;
			/*
			 * Temporarily disabled
			 *
			} else if (strcmp(optarg, "server") == 0) {
				*op_mode = OMPING_OP_MODE_SERVER;
			*/
			} else if (strcmp(optarg, "client") == 0) {
				*op_mode = OMPING_OP_MODE_CLIENT;
			} else {
				warnx("illegal parameter, -O argument -- %s", optarg);
				goto error_usage_exit;
			}
			break;
		case 'p':
			port_s = optarg;
			break;
		case 'R':
			numd = strtod(optarg, &ep);
			if (numd < MIN_RCVBUF_SIZE || *ep != '\0' || numd > INT32_MAX) {
				warnx("illegal number, -R argument -- %s", optarg);
				goto error_usage_exit;
			}
			*rcvbuf_size = (int)numd;
			break;
		case 'r':
			numd = strtod(optarg, &ep);
			if (numd < 0 || *ep != '\0' || numd * 1000 > INT32_MAX) {
				warnx("illegal number, -r argument -- %s", optarg);
				goto error_usage_exit;
			}
			*rate_limit_time = (int)(numd * 1000.0);
			rate_limit_time_set = 1;
			break;
		case 'S':
			numd = strtod(optarg, &ep);
			if (numd < MIN_SNDBUF_SIZE || *ep != '\0' || numd > INT32_MAX) {
				warnx("illegal number, -S argument -- %s", optarg);
				goto error_usage_exit;
			}
			*sndbuf_size = (int)numd;
			break;
		case 't':
			num = strtol(optarg, &ep, 10);
			if (num <= 0 || num > ((uint8_t)~0) || *ep != '\0') {
				warnx("illegal number, -t argument -- %s", optarg);
				goto error_usage_exit;
			}
			*ttl = num;
			break;
		case 'T':
			numd = strtod(optarg, &ep);
			if (numd < 0 || *ep != '\0' || numd * 1000 > INT32_MAX) {
				warnx("illegal number, -T argument -- %s", optarg);
				goto error_usage_exit;
			}
			*timeout_time = (int)(numd * 1000.0);
			break;
		case 'w':
			numd = strtod(optarg, &ep);
			if ((numd < 0 && numd != -1) || *ep != '\0' || numd * 1000 > INT32_MAX) {
				warnx("illegal number, -w argument -- %s", optarg);
				goto error_usage_exit;
			}
			wait_for_finish_time_set = 1;
			*wait_for_finish_time = (int)(numd * 1000.0);
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
	if (show_ver == 1) {
		cliprint_version();
		exit(0);
	}

	if (show_ver > 1) {
		if (*op_mode != OMPING_OP_MODE_NORMAL) {
			warnx("op_mode must be set to normal for remote version display.");
			goto error_usage_exit;
		}

		*op_mode = OMPING_OP_MODE_SHOW_VERSION;
	}

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

	if (*transport_method == SF_TM_IPBC) {
		if (*ip_ver == 6) {
			warnx("illegal transport method, -M argument ipbc is mutually exclusive "
			    "with -6 option");
			goto error_usage_exit;
		}

		*ip_ver = 4;
	}

	/*
	 * Computed params
	 */
	if (!wait_for_finish_time_set) {
		*wait_for_finish_time = *wait_time * DEFAULT_WFF_TIME_MUL;
		if (*wait_for_finish_time < DEFAULT_WAIT_TIME) {
			*wait_for_finish_time = DEFAULT_WAIT_TIME;
		}
	}

	if (*wait_time == 0) {
		*dup_buf_items = 0;
	} else {
		/*
		 * + 1 is for eliminate trucate errors
		 */
		*dup_buf_items = ((DUP_BUF_SECS * 1000) / *wait_time) + 1;

		if (*dup_buf_items < MIN_DUP_BUF_ITEMS) {
			*dup_buf_items = MIN_DUP_BUF_ITEMS;
		}
	}

	if (!rate_limit_time_set) {
		*rate_limit_time = *wait_time;

	}

	TAILQ_INIT(aii_list);

	no_ai = aii_parse_remote_addrs(aii_list, argc, argv, port_s, *ip_ver);
	if (no_ai < 1) {
		warnx("at least one remote addresses should be specified");
		goto error_usage_exit;
	}

	*ip_ver = aii_return_ip_ver(aii_list, *ip_ver, mcast_addr_s, port_s);

	if (aii_find_local(aii_list, ip_ver, &ifa_list, &ifa_local, &ai_item, ifa_flags) < 0) {
		errx(1, "Can't find local address in arguments");
	}

	/*
	 * Change aii_list to struct of sockaddr_storage(s)
	 */
	aii_list_ai_to_sa(aii_list, *ip_ver);

	/*
	 * Find local addr and copy that. Also remove that from list
	 */
	conv_local_addr(aii_list, ai_item, ifa_local, *ip_ver, local_addr, single_addr);

	/*
	 * Store local ifname
	 */
	*local_ifname = strdup(ifa_local->ifa_name);
	if (*local_ifname == NULL) {
		errx(1, "Can't alloc memory");
	}

	switch (*transport_method) {
	case SF_TM_ASM:
	case SF_TM_SSM:
		/*
		 * Convert mcast addr to something useful
		 */
		aii_mcast_to_ai(*ip_ver, mcast_addr, mcast_addr_s, port_s);
		break;
	case SF_TM_IPBC:
		/*
		 * Convert broadcast addr to something useful
		 */
		res = aii_ipbc_to_ai(mcast_addr, mcast_addr_s, port_s, ifa_local);
		if (res == -1) {
			warnx("illegal broadcast address, -M argument doesn't match with local"
			    " broadcast address");
			goto error_usage_exit;
		}
		break;
	}

	/*
	 * Assign port from mcast_addr
	 */
	*port = af_sa_port(AF_CAST_SA(&mcast_addr->sas));

	freeifaddrs(ifa_list);

	return (0);

error_usage_exit:
	cliprint_usage();
	exit(1);
	/* NOTREACHED */
	return (-1);
}

/*
 * Convert ifa_local addr to local_addr. If only one remote_host is entered, single_addr is set, if
 * not then ai_local is freed and removed from list.
 */
static void
conv_local_addr(struct aii_list *aii_list, struct ai_item *ai_local,
    const struct ifaddrs *ifa_local, int ip_ver, struct ai_item *local_addr, int *single_addr)
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
	local_addr->host_name = strdup(ai_local->host_name);
	if (local_addr->host_name == NULL) {
		err(1, "Can't alloc memory");
		/* NOTREACHED */
	}

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

	*single_addr = (TAILQ_NEXT(TAILQ_FIRST(aii_list), entries) == NULL);

	if (!*single_addr) {
		TAILQ_REMOVE(aii_list, ai_local, entries);

		free(ai_local->host_name);
		free(ai_local);
	}
}
