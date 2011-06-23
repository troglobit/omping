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

#define __STDC_FORMAT_MACROS
#include <inttypes.h>
#include <err.h>
#include <stdio.h>
#include <string.h>

#include "cliprint.h"
#include "logging.h"
#include "omping.h"

/*
 * Print status of client with host_name (maximum length of host_name_len). transport_method is
 * transport method to be used, mcast_addr is current multicast address to be used by client.
 * remote_addr is address of client and state is current state of client.
 */
void
cliprint_client_state(const char *host_name, int host_name_len,
    enum sf_transport_method transport_method, const struct sockaddr_storage *mcast_addr,
    const struct sockaddr_storage *remote_addr, enum rh_client_state state,
    enum rh_client_stop_reason stop_reason)
{
	char mcast_addr_str[INET6_ADDRSTRLEN];
	char rh_addr_str[INET6_ADDRSTRLEN];

	printf("%-*s : ", host_name_len, host_name);

	switch (state) {
	case RH_CS_INITIAL:
		printf("waiting for response msg");
		break;
	case RH_CS_QUERY:
		memset(mcast_addr_str, 0, sizeof(mcast_addr_str));
		memset(rh_addr_str, 0, sizeof(rh_addr_str));

		if (mcast_addr != NULL) {
			af_sa_to_str(AF_CAST_SA(mcast_addr), mcast_addr_str);
		}

		if (remote_addr != NULL) {
			af_sa_to_str(AF_CAST_SA(remote_addr), rh_addr_str);
		}

		switch (transport_method) {
		case SF_TM_ASM:
			printf("joined (S,G) = (*, %s), pinging", mcast_addr_str);
			break;
		case SF_TM_SSM:
			printf("joined (S,G) = (%s, %s), pinging", rh_addr_str, mcast_addr_str);
			break;
		case SF_TM_IPBC:
			printf("joined (S,G) = (*, %s), pinging", mcast_addr_str);
			break;
		}
		break;
	case RH_CS_STOP:
		switch (stop_reason) {
		case RH_CSR_NONE:
			DEBUG_PRINTF("internal program error.");
			errx(1, "Internal program error");
			break;
		case RH_CSR_SERVER:
			printf("server told us to stop");
			break;
		case RH_CSR_SEND_MAXIMUM:
			printf("maximum number of query messages exhausted");
			break;
		case RH_CSR_TO_SEND_EXHAUSTED:
			printf("given amount of query messages was sent");
			break;
		case RH_CSR_REMOTE_VERSION_RECEIVED:
			printf("remote version received");
			break;
		}
		break;
	}
	printf("\n");
}

/*
 * Print final remote versions. remote_hosts is list with all remote hosts and host_name_len is
 * maximal length of host name in list.
 */
void
cliprint_final_remote_version(const struct rh_list *remote_hosts, int host_name_len)
{
	struct rh_item *rh_item;
	struct rh_item_ci *ci;
	size_t i;
	unsigned char ch;

	printf("\n");

	TAILQ_FOREACH(rh_item, remote_hosts, entries) {
			ci = &rh_item->client_info;

			printf("%-*s : ", host_name_len, rh_item->addr->host_name);

			if (ci->server_info_len == 0) {
				printf("response message not received\n");
			} else {
				for (i = 0; i < ci->server_info_len; i++) {
					ch = ci->server_info[i];

				if (ch >= ' ' && ch < 0x7f && ch != '\\') {
					fputc(ch, stdout);
				} else {
					if (ch == '\\') {
						printf("\\\\");
					} else {
						printf("\\x%02X", ch);
					}
				}
			}

			printf("\n");
		}
	}
}

/*
 * Print final statistics. remote_hosts is list with all remote hosts and host_name_len is maximal
 * length of host name in list. transport_method is transport method (SF_TM_ASM/SSM/IPBC) from
 * omping instance.
 */
void
cliprint_final_stats(const struct rh_list *remote_hosts, int host_name_len,
    enum sf_transport_method transport_method)
{
	const char *cast_str;
	struct rh_item *rh_item;
	struct rh_item_ci *ci;
	enum sf_cast_type cast_type;
	double avg_rtt;
	int i;
	int loss;
	int loss_adj;
	uint64_t received;
	uint64_t sent;

	printf("\n");

	loss_adj = 0;

	TAILQ_FOREACH(rh_item, remote_hosts, entries) {
		for (i = 0; i < 2; i++) {
			if (i == 0) {
				cast_type = SF_CT_UNI;
			} else {
				switch (transport_method) {
				case SF_TM_ASM:
				case SF_TM_SSM:
					cast_type = SF_CT_MULTI;
					break;
				case SF_TM_IPBC:
					cast_type = SF_CT_BROAD;
					break;
				default:
					DEBUG_PRINTF("Internal error - unknown transport method");
					errx(1, "Internal error - unknown transport method");
					/* NOTREACHED */
				}
			}

			cast_str = sf_cast_type_to_str(cast_type);
			ci = &rh_item->client_info;

			received = ci->no_received[i];
			sent = ci->no_sent;

			printf("%-*s : ", host_name_len, rh_item->addr->host_name);

			if (received == 0 && i == 0) {
				printf("response message never received\n");
				break;
			}

			if (i != 0) {
				loss_adj = util_packet_loss_percent(sent - ci->first_mcast_seq + 1,
				    received);
			}

			loss = util_packet_loss_percent(sent, received);

			if (received == 0) {
				avg_rtt = 0;
			} else {
				avg_rtt = ci->avg_rtt[i] / UTIL_NSINMS;
			}

			printf("%5scast, ", cast_str);

			printf("xmt/rcv/%%loss = ");
			printf("%"PRIu64"/%"PRIu64, sent, received);

			if (ci->no_dups[i] > 0) {
				printf("+%"PRIu64, ci->no_dups[i]);
			}

			printf("/%d%%", loss);
			if (i != 0 && ci->first_mcast_seq > 1) {
				printf(" (seq>=%"PRIu32" %d%%)", ci->first_mcast_seq, loss_adj);
			}

			printf(", min/avg/max/std-dev = ");
			printf("%.3f/%.3f/%.3f/%.3f", ci->rtt_min[i] / UTIL_NSINMS, avg_rtt,
			    ci->rtt_max[i] / UTIL_NSINMS,
			    util_ov_std_dev(ci->m2_rtt[i], ci->no_received[i]) / UTIL_NSINMS);
			printf("\n");
		}
	}
}

/*
 * Display newline
 */
void
cliprint_nl(void)
{

	printf("\n");
}

/*
 * Print packet statistics. host_name is remote host name with maximal host_name_len length. seq is
 * sequence number of packet, is_dup is boolean with information if packet is duplicate or not,
 * msg_len is length of message, dist_set is boolean variable with information if dist is set or
 * not. dist is distance of packet (how TTL was changed). rtt_set is boolean variable with
 * information if rtt (current round trip time) and avg_rtt (average round trip time) is set and
 * computed or not. loss is number of lost packets. cast_type is type of packet received
 * (unicast/multicast/broadcast). cont_stat is boolean variable saying, if to display
 * continuous statistic or not.
 */
void
cliprint_packet_stats(const char *host_name, int host_name_len, uint32_t seq, int is_dup,
    size_t msg_len, int dist_set, uint8_t dist, int rtt_set, double rtt, double avg_rtt, int loss,
    enum sf_cast_type cast_type, int cont_stat)
{
	const char *cast_str;

	cast_str = sf_cast_type_to_str(cast_type);

	printf("%-*s : ", host_name_len, host_name);
	printf("%5scast, ", cast_str);
	printf("seq=%"PRIu32, seq);

	if (is_dup) {
		printf(" (dup)");
	}

	printf(", ");
	printf("size=%zu bytes", msg_len);

	if (dist_set) {
		printf(", dist=%"PRIu8, dist);
	}

	if (rtt_set) {
		printf(", time=%.3fms", rtt);
	}

	if (cont_stat) {
		printf(" (");

		if (rtt_set) {
			printf("%.3f avg, ", avg_rtt);
		}

		printf("%d%% loss)", loss);
	}

	printf("\n");
}

/*
 * Display application ussage
 */
void
cliprint_usage(void)
{

	printf("usage: %s [-46CDEFqVv] [-c count] [-i interval] [-M transport_method]\n",
	    PROGRAM_NAME);
	printf("%14s[-m mcast_addr] [-O op_mode] [-p port] [-R rcvbuf] [-r rate_limit]\n", "");
	printf("%14s[-S sndbuf] [-T timeout] [-t ttl] [-w wait_time] remote_addr...\n", "");
}

/*
 * Show application version
 */
void
cliprint_version(void)
{

	printf("%s version %s\n", PROGRAM_NAME, PROGRAM_VERSION);
}
