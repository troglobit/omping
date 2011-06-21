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
#define __STDC_LIMIT_MACROS
#include <inttypes.h>
#include <err.h>
#include <signal.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "addrfunc.h"
#include "cli.h"
#include "logging.h"
#include "msg.h"
#include "msgsend.h"
#include "omping.h"
#include "rhfunc.h"
#include "rsfunc.h"
#include "sockfunc.h"
#include "tlv.h"
#include "util.h"

#define MAX_EXIT_REQUESTS	2

/*
 * Structure with internal omping data
 */
struct omping_instance {
	struct ai_item	local_addr;
	struct ai_item	mcast_addr;
	struct rh_list	remote_hosts;
	struct ai_list	remote_addrs;
	enum omping_op_mode op_mode;
	enum sf_transport_method transport_method;
	char		*local_ifname;
	uint64_t	send_count_queries;
	int		auto_exit;
	int		cont_stat;
	int		dup_buf_items;
	int		hn_max_len;
	int		ip_ver;
	int		mcast_socket;
	int		quiet;
	int		rate_limit_time;
	int		rcvbuf_size;
	int		single_addr;
	int		sndbuf_size;
	int		timeout_time;
	int		ucast_socket;
	int		wait_for_finish_time;
	int		wait_time;
	unsigned int	rh_no_active;
	uint16_t	port;
	uint8_t		ttl;
};

/*
 * User requested exit of application (usually with SIGINT)
 */
static int exit_requested;

/*
 * User requested to display overall statistics (SIGINT/SIGUSR1)
 */
static int display_stats_requested;

/*
 * Function prototypes
 */
static int	get_packet_loss_percent(uint64_t packet_sent, uint64_t packet_received);

static int	omping_check_msg_common(const struct msg_decoded *msg_decoded);

static void	omping_client_move_to_stop(struct omping_instance *instance,
    struct rh_item *ri, enum rh_client_stop_reason stop_reason);

static void	omping_instance_create(struct omping_instance *instance, int argc,
    char *argv[]);

static void	omping_instance_free(struct omping_instance *instance);

static int	omping_poll_receive_loop(struct omping_instance *instance, int timeout_time);

static int	omping_poll_timeout(struct omping_instance *instance, struct timeval *old_tstamp,
    int timeout_time);

static int	omping_process_msg(struct omping_instance *instance, const char *msg,
    size_t msg_len, const struct sockaddr_storage *from, uint8_t ttl, enum sf_cast_type cast_type,
    struct timeval rp_timestamp);

static int	omping_process_answer_msg(struct omping_instance *instance, const char *msg,
    size_t msg_len, const struct msg_decoded *msg_decoded, const struct sockaddr_storage *from,
    uint8_t ttl, enum sf_cast_type cast_type, struct timeval rp_timestamp);

static int	omping_process_init_msg(struct omping_instance *instance, const char *msg,
    size_t msg_len, const struct msg_decoded *msg_decoded, const struct sockaddr_storage *from,
    struct timeval rp_timestamp);

static int	omping_process_query_msg(struct omping_instance *instance, const char *msg,
    size_t msg_len, const struct msg_decoded *msg_decoded, const struct sockaddr_storage *from,
    struct timeval rp_timestamp);

static int	omping_process_response_msg(struct omping_instance *instance, const char *msg,
    size_t msg_len, const struct msg_decoded *msg_decoded, const struct sockaddr_storage *from);

static int	omping_send_client_query(struct omping_instance *instance, struct rh_item *ri,
    int increase);

static int	omping_send_client_msgs(struct omping_instance *instance);

static void	omping_send_receive_loop(struct omping_instance *instance, int timeout_time,
    int final_stats, int allow_auto_exit);

static void	print_client_state(const char *host_name, int host_name_len,
    enum sf_transport_method transport_method, const struct sockaddr_storage *mcast_addr,
    const struct sockaddr_storage *remote_addr, enum rh_client_state state,
    enum rh_client_stop_reason stop_reason);

static void	print_final_remote_version(const struct rh_list *remote_hosts, int host_name_len);

static void	print_final_stats(const struct rh_list *remote_hosts, int host_name_len,
    enum sf_transport_method transport_method);

static void	print_packet_stats(const char *host_name, int host_name_len, uint32_t seq,
    int is_dup, size_t msg_len, int dist_set, uint8_t dist, int rtt_set, double rtt,
    double avg_rtt, int loss, enum sf_cast_type cast_type, int cont_stat);

static void	siginfo_handler(int sig);
static void	sigint_handler(int sig);

static void	register_signal_handlers(void);

/*
 * Functions implementation
 */

/*
 * Entry point of omping
 */
int
main(int argc, char *argv[])
{
	struct omping_instance instance;
	int allow_auto_exit;
	int final_stats;
	int wait_for_finish_time;

	omping_instance_create(&instance, argc, argv);

	register_signal_handlers();

	if (instance.op_mode == OMPING_OP_MODE_SERVER) {
		final_stats = allow_auto_exit = 0;
	} else {
		final_stats = allow_auto_exit = 1;
	}

	omping_send_receive_loop(&instance, instance.timeout_time, final_stats, allow_auto_exit);

	if (!instance.single_addr && instance.wait_for_finish_time != 0 &&
	    instance.op_mode != OMPING_OP_MODE_CLIENT) {
		exit_requested = 0;

		DEBUG_PRINTF("Moving all clients to stop state and server to finishing state");
		rh_list_put_to_finish_state(&instance.remote_hosts, RH_LFS_BOTH);

		if (instance.wait_for_finish_time == -1) {
			wait_for_finish_time = 0;
		} else {
			wait_for_finish_time = instance.wait_for_finish_time;
		}

		VERBOSE_PRINTF("Waiting for %d ms to inform other nodes about instance exit",
		    instance.wait_for_finish_time);

		omping_send_receive_loop(&instance, wait_for_finish_time, 0, 0);
	}

	omping_instance_free(&instance);

	return 0;
}

/*
 * Compute packet loss in percent from number of send and received packets
 */
static int
get_packet_loss_percent(uint64_t packet_sent, uint64_t packet_received)
{
	int loss;

	if (packet_received > packet_sent) {
		DEBUG_PRINTF("packet_received > packet_sent");
		loss = 0;
	} else {
		loss = (int)((1.0 - (double)packet_received / (double)packet_sent) * 100.0);
	}

	return (loss);
}

/*
 * Test basic message characteristics. Return 0 on success, and -1 on fail.
 */
static int
omping_check_msg_common(const struct msg_decoded *msg_decoded)
{
	if (msg_decoded->msg_type != MSG_TYPE_INIT && msg_decoded->msg_type != MSG_TYPE_RESPONSE &&
	    msg_decoded->msg_type != MSG_TYPE_QUERY && msg_decoded->msg_type != MSG_TYPE_ANSWER) {
		DEBUG_PRINTF("Unknown type %c (0x%X) of message", msg_decoded->msg_type,
		    msg_decoded->msg_type);

		return (-1);
	}

	if (msg_decoded->version != 2) {
		DEBUG_PRINTF("Message version %d is not supported", msg_decoded->version);

		return (-1);
	}

	return (0);
}

/*
 * Move client to stop state. Instance is omping instance, ri is pointer to remote host item from
 * remote hosts list and stop_reason is reason to stop.
 */
static void
omping_client_move_to_stop(struct omping_instance *instance, struct rh_item *ri,
    enum rh_client_stop_reason stop_reason)
{
	ri->client_info.state = RH_CS_STOP;
	instance->rh_no_active--;

	if (instance->quiet < 2) {
		print_client_state(ri->addr->host_name, instance->hn_max_len,
		    instance->transport_method, NULL, &ri->addr->sas,
		    RH_CS_STOP, stop_reason);
	}
}

/*
 * Create instance of omping. argc and argv are taken form main function. Result is stored in
 * instance parameter
 */
static void
omping_instance_create(struct omping_instance *instance, int argc, char *argv[])
{
	uint16_t bind_port;

	bind_port = 0;
	memset(instance, 0, sizeof(struct omping_instance));

	cli_parse(&instance->remote_addrs, argc, argv, &instance->local_ifname, &instance->ip_ver,
	    &instance->local_addr, &instance->wait_time, &instance->transport_method,
	    &instance->mcast_addr, &instance->port, &instance->ttl, &instance->single_addr,
	    &instance->quiet, &instance->cont_stat, &instance->timeout_time,
	    &instance->wait_for_finish_time, &instance->dup_buf_items, &instance->rate_limit_time,
	    &instance->sndbuf_size, &instance->rcvbuf_size, &instance->send_count_queries,
	    &instance->auto_exit, &instance->op_mode);

	rh_list_create(&instance->remote_hosts, &instance->remote_addrs, instance->dup_buf_items,
	    instance->rate_limit_time);

	instance->rh_no_active = rh_list_length(&instance->remote_hosts);

	instance->ucast_socket =
	    sf_create_unicast_socket(AF_CAST_SA(&instance->local_addr.sas), instance->ttl, 1,
	    instance->single_addr, instance->local_ifname, instance->transport_method, 1, 0,
	    instance->sndbuf_size, instance->rcvbuf_size,
	    (instance->op_mode == OMPING_OP_MODE_CLIENT ? &bind_port : NULL));

	if (instance->ucast_socket == -1) {
		err(1, "Can't create/bind unicast socket");
	}

	switch (instance->op_mode) {
	case OMPING_OP_MODE_SERVER:
		instance->mcast_socket = -1;
		rh_list_put_to_finish_state(&instance->remote_hosts, RH_LFS_CLIENT);
		break;
	case OMPING_OP_MODE_SHOW_VERSION:
		rh_list_put_to_finish_state(&instance->remote_hosts, RH_LFS_SERVER);
		break;
	case OMPING_OP_MODE_CLIENT:
		rh_list_put_to_finish_state(&instance->remote_hosts, RH_LFS_SERVER);
	case OMPING_OP_MODE_NORMAL:
		instance->mcast_socket =
		    sf_create_multicast_socket((struct sockaddr *)&instance->mcast_addr.sas,
			AF_CAST_SA(&instance->local_addr.sas), instance->local_ifname,
			instance->ttl, instance->single_addr, instance->transport_method,
			&instance->remote_addrs, 1, 0, instance->sndbuf_size,
			instance->rcvbuf_size,
			(instance->op_mode == OMPING_OP_MODE_CLIENT ? bind_port : 0));

		if (instance->mcast_socket == -1) {
			err(1, "Can't create/bind multicast socket");
		}
		break;
	}

	util_random_init(&instance->local_addr.sas);

	rh_list_gen_cid(&instance->remote_hosts, &instance->local_addr);

	instance->hn_max_len = rh_list_hn_max_len(&instance->remote_hosts);
}

/*
 * Free allocated memory of omping instance.
 */
static void
omping_instance_free(struct omping_instance *instance)
{
	af_ai_list_free(&instance->remote_addrs);
	rh_list_free(&instance->remote_hosts);

	free(instance->local_addr.host_name);
	free(instance->mcast_addr.host_name);
	free(instance->local_ifname);
}

/*
 * Loop for receiving messages for given time (instance->wait_time) and process them. Instance is
 * omping instance. timeout_time is maximum time to wait.
 * Function returns 0 on success, or -2 on EINTR.
 */
static int
omping_poll_receive_loop(struct omping_instance *instance, int timeout_time)
{
	char msg[MAX_MSG_SIZE];
	struct sockaddr_storage from;
	struct timeval old_tstamp;
	struct timeval rp_timestamp;
	enum sf_cast_type cast_type;
	int i;
	int poll_res;
	int receive_res;
	uint8_t ttl;
	int res;

	memset(&old_tstamp, 0, sizeof(old_tstamp));

	do {
		poll_res = omping_poll_timeout(instance, &old_tstamp, timeout_time);
		if (poll_res == -2) {
			return (-2);
			/* NOTREACHED */
		}

		for (i = 0; i < 2; i++) {
			receive_res = 0;

			if (i == 0 && poll_res & 1) {
				receive_res = rs_receive_msg(instance->ucast_socket, &from, msg,
				    sizeof(msg), &ttl, &rp_timestamp);
			}

			if (i == 1 && poll_res & 2) {
				receive_res = rs_receive_msg(instance->mcast_socket, &from, msg,
				    sizeof(msg), &ttl, &rp_timestamp);
			}

			switch (receive_res) {
			case -1:
				err(2, "Cannot receive message");
				/* NOTREACHED */
				break;
			case -2:
				return (-2);
				/* NOTREACHED */
				break;
			case -3:
				warn("Cannot receive message");
				break;
			case -4:
				VERBOSE_PRINTF("Received message too long");
				break;
			}

			if (receive_res > 0) {
				if (i == 0) {
					cast_type = SF_CT_UNI;
				} else {
					switch (instance->transport_method) {
					case SF_TM_ASM:
					case SF_TM_SSM:
						cast_type = SF_CT_MULTI;
						break;
					case SF_TM_IPBC:
						cast_type = SF_CT_BROAD;
						break;
					default:
						DEBUG_PRINTF("Internal error - unknown tm");
						errx(1, "Internal error - unknown tm");
						/* NOTREACHED */
					}
				}

				res = omping_process_msg(instance, msg, receive_res, &from, ttl,
				    cast_type, rp_timestamp);

				if (res == -2) {
					return (-2);
				}
			}
		}
	} while (poll_res > 0);

	return (0);
}

/*
 * Wait for messages on sockets. instance is omping_instance and old_tstamp is temporary variable
 * which must be set to zero on first call. Function handles EINTR for display statistics.
 * Function is wrapper on top of rs_poll_timeout, but handles -1 error code. Other return values
 * have same meaning. timeout_time is maximum time to wait
 */
static int
omping_poll_timeout(struct omping_instance *instance, struct timeval *old_tstamp, int timeout_time)
{
	int poll_res;

	do {
		poll_res = rs_poll_timeout(instance->ucast_socket, instance->mcast_socket,
		    timeout_time, old_tstamp);

		switch (poll_res) {
		case -1:
			err(2, "Cannot poll on sockets");
			/* NOTREACHED */
			break;
		case -2:
			if (display_stats_requested) {
				display_stats_requested = 0;

				if (instance->op_mode == OMPING_OP_MODE_SHOW_VERSION) {
					print_final_remote_version(&instance->remote_hosts,
					    instance->hn_max_len);
				} else {
					print_final_stats(&instance->remote_hosts,
					    instance->hn_max_len, instance->transport_method);
				}

				printf("\n");

				if (!exit_requested) {
					break;
				}
			}

			return (-2);
			/* NOTREACHED */
			break;
		}
	} while (poll_res < 0);

	return (poll_res);
}

/*
 * Process received message. Instance is omping instance, msg is received message with msg_len
 * length, from is source of message. ttl is packet Time-To-Live or 0, if that information was not
 * available. cast_type is type of packet received (unicast/multicast/broadcast). rp_timestamp
 * is receiving time of packet.
 * Function returns 0 on success or -2 on EINTR.
 */
static int
omping_process_msg(struct omping_instance *instance, const char *msg, size_t msg_len,
    const struct sockaddr_storage *from, uint8_t ttl, enum sf_cast_type cast_type,
    struct timeval rp_timestamp)
{
	char addr_str[INET6_ADDRSTRLEN];
	struct msg_decoded msg_decoded;
	const char *cast_str;
	struct rh_item *rh_item;
	int res;

	res = 0;

	msg_decode(msg, msg_len, &msg_decoded);

	cast_str = sf_cast_type_to_str(cast_type);

	af_sa_to_str((struct sockaddr *)from, addr_str);
	DEBUG_PRINTF("Received %scast message from %s type %c (0x%X), len %zu", cast_str, addr_str,
	    msg_decoded.msg_type, msg_decoded.msg_type, msg_len);

	if (omping_check_msg_common(&msg_decoded) == -1) {
		res = ms_stop(instance->ucast_socket, &instance->mcast_addr.sas, &msg_decoded,
		    from);
	} else {
		switch (msg_decoded.msg_type) {
		case MSG_TYPE_INIT:
			if (cast_type != SF_CT_UNI)
				goto error_unknown_mcast;

			if (instance->op_mode == OMPING_OP_MODE_CLIENT)
				goto error_unknown_msg_type;

			res = omping_process_init_msg(instance, msg, msg_len, &msg_decoded, from,
			    rp_timestamp);
			break;
		case MSG_TYPE_RESPONSE:
			if (cast_type != SF_CT_UNI)
				goto error_unknown_mcast;

			if (instance->op_mode == OMPING_OP_MODE_SERVER)
				goto error_unknown_msg_type;

			res = omping_process_response_msg(instance, msg, msg_len, &msg_decoded,
			    from);
			break;
		case MSG_TYPE_QUERY:
			if (cast_type != SF_CT_UNI)
				goto error_unknown_mcast;

			if (instance->op_mode == OMPING_OP_MODE_CLIENT)
				goto error_unknown_msg_type;

			res = omping_process_query_msg(instance, msg, msg_len, &msg_decoded, from,
			    rp_timestamp);
			break;
		case MSG_TYPE_ANSWER:
			if (instance->op_mode == OMPING_OP_MODE_SERVER && cast_type == SF_CT_UNI)
				goto error_unknown_msg_type;

			res = omping_process_answer_msg(instance, msg, msg_len, &msg_decoded, from,
			    ttl, cast_type, rp_timestamp);
			break;
		}
	}

	switch (res) {
	case -1:
		err(2, "Cannot send message");
		/* NOTREACHED */
		break;
	case -2:
		return (-2);
		/* NOTREACHED */
		break;
	case -3:
		warn("Send message error");
		rh_item = rh_list_find(&instance->remote_hosts, (const struct sockaddr *)from);
		if (rh_item == NULL) {
			DEBUG_PRINTF("Received message from unknown address");
		} else {
			rh_item->client_info.no_err_msgs++;
		}
		break;
	case -4:
		DEBUG_PRINTF("Cannot send message. Buffer too small");
		break;
	}

	return (0);

error_unknown_mcast:
	DEBUG_PRINTF("Received multicast message with invalid type %c (0x%X)",
	    msg_decoded.msg_type, msg_decoded.msg_type);

	return (0);

error_unknown_msg_type:
	DEBUG_PRINTF("Received message type %c (0x%X) which is not supported in given "
	    "operational mode", msg_decoded.msg_type, msg_decoded.msg_type);

	return (0);
}

/*
 * Function to test if packet is duplicate. ci is client item information, seq is sequential number
 * and cast_type is type of packet received (unicast/multicast/broadcast).
 * Function returns 0 if packet is not duplicate, otherwise 1.
 */
static int
is_dup_packet(const struct rh_item_ci *ci, uint32_t seq, enum sf_cast_type cast_type)
{
	int cast_index;
	int res;

	cast_index = (cast_type == SF_CT_UNI ? 0 : 1);

	if (ci->dup_buffer[cast_index][seq % ci->dup_buf_items] == seq) {
		res = 1;
	} else {
		ci->dup_buffer[cast_index][seq % ci->dup_buf_items] = seq;

		res = 0;
	}

	return (res);
}

/*
 * Process answer message. Instance is omping instance, msg is received message with msg_len length,
 * msg_decoded is decoded message, from is address of sender. ttl is Time-To-Live of packet. If ttl
 * is 0, it means that it was not possible to find out ttl. cast_type is type of packet received
 * (unicast/multicast/broadcast). rp_timestamp is receiving time of packet.
 * Function returns 0 on sucess, otherwise same error as rs_sendto or -4 if message cannot be
 * created (usually due to small message buffer), or -5 if message is invalid (not for us, message
 * without client_id, ...).
 */
static int
omping_process_answer_msg(struct omping_instance *instance, const char *msg, size_t msg_len,
    const struct msg_decoded *msg_decoded, const struct sockaddr_storage *from, uint8_t ttl,
    enum sf_cast_type cast_type, struct timeval rp_timestamp)
{
	struct rh_item *rh_item;
	double avg_rtt;
	double rtt;
	uint64_t received;
	uint64_t sent;
	int cast_index;
	int dist_set;
	int first_packet;
	int is_dup;
	int rtt_set;
	int loss;
	uint8_t dist;

	rh_item = rh_list_find(&instance->remote_hosts, (const struct sockaddr *)from);
	if (rh_item == NULL) {
		DEBUG_PRINTF("Received message from unknown address");
		return (-5);
	}

	if (msg_decoded->client_id == NULL) {
		DEBUG_PRINTF("Message doesn't contain client id");
		return (-5);
	}

	if (msg_decoded->client_id_len != CLIENTID_LEN ||
	    memcmp(msg_decoded->client_id, rh_item->client_info.client_id, CLIENTID_LEN) != 0) {
		DEBUG_PRINTF("Message doesn't contain our client id");
		return (-5);
	}

	if (!msg_decoded->seq_num_isset) {
		DEBUG_PRINTF("Message doesn't contain seq num");
		return (-5);
	}

	if (rh_item->client_info.state != RH_CS_QUERY) {
		DEBUG_PRINTF("Client is not in query state. Ignoring message");
		return (-5);
	}

	if (ttl > 0 && msg_decoded->ttl > 0) {
		dist_set = 1;
		dist =  msg_decoded->ttl - ttl;
	} else {
		dist_set = dist = 0;
	}

	if (msg_decoded->client_tstamp_isset) {
		rtt_set = 1;
		rtt = util_time_double_absdiff_ns(msg_decoded->client_tstamp, rp_timestamp);
	} else {
		rtt_set = 0;
		rtt = 0;
	}

	avg_rtt = 0;
	cast_index = (cast_type == SF_CT_UNI ? 0 : 1);
	is_dup = 0;

	if (instance->dup_buf_items > 0) {
		is_dup = is_dup_packet(&rh_item->client_info, msg_decoded->seq_num, cast_type);
	}

	if (is_dup) {
		if (rh_item->client_info.no_dups[cast_index] == ((uint64_t)~0)) {
			DEBUG_PRINTF("Number of received duplicates for %s exhausted.",
			    rh_item->addr->host_name);
		} else {
			rh_item->client_info.no_dups[cast_index]++;
		}

		received = rh_item->client_info.no_received[cast_index];
	} else {
		first_packet = (rh_item->client_info.no_received[cast_index] == 0);

		received = ++rh_item->client_info.no_received[cast_index];

		if (cast_index == 0) {
			rh_item->client_info.lru_seq_num = msg_decoded->seq_num;
		}

		if (cast_type != SF_CT_UNI && first_packet &&
		    !rh_item->client_info.seq_num_overflow) {
			rh_item->client_info.first_mcast_seq = msg_decoded->seq_num;
		}

		if (rtt_set) {
			util_ov_update(&rh_item->client_info.avg_rtt[cast_index],
			    &rh_item->client_info.m2_rtt[cast_index], rtt, received);

			if (first_packet) {
				rh_item->client_info.rtt_max[cast_index] = rtt;
				rh_item->client_info.rtt_min[cast_index] = rtt;
			} else {
				if (rtt > rh_item->client_info.rtt_max[cast_index]) {
					rh_item->client_info.rtt_max[cast_index] = rtt;
				}

				if (rtt < rh_item->client_info.rtt_min[cast_index]) {
					rh_item->client_info.rtt_min[cast_index] = rtt;
				}
			}
		}
	}

	if (instance->cont_stat) {
		sent = rh_item->client_info.no_sent;

		if (cast_type != SF_CT_UNI && rh_item->client_info.first_mcast_seq > 0) {
			sent = sent - rh_item->client_info.first_mcast_seq + 1;
		}
		loss = get_packet_loss_percent(sent, received);
		avg_rtt = rh_item->client_info.avg_rtt[cast_index] / UTIL_NSINMS;
	} else {
		loss = 0;
	}

	if (instance->quiet == 0) {
		print_packet_stats(rh_item->addr->host_name, instance->hn_max_len,
		    msg_decoded->seq_num, is_dup, msg_len, dist_set, dist, rtt_set,
		    rtt / UTIL_NSINMS, avg_rtt, loss, cast_type, instance->cont_stat);
	}

	return (0);
}

/*
 * Process init messge. instance is omping_instance, msg is received message with msg_len length,
 * msg_decoded is decoded message and from is sockaddr of sender. rp_timestamp is receiving time
 * of packet.
 * Function returns 0 on sucess, otherwise same error as rs_sendto or -4 if message cannot be
 * created (usually due to small message buffer)
 */
static int
omping_process_init_msg(struct omping_instance *instance, const char *msg, size_t msg_len,
    const struct msg_decoded *msg_decoded, const struct sockaddr_storage *from,
    struct timeval rp_timestamp)
{
	struct rh_item *rh_item;
	struct tlv_iterator tlv_iter;
	int pref_found;

	rh_item = rh_list_find(&instance->remote_hosts, (const struct sockaddr *)from);
	if (rh_item == NULL) {
		DEBUG_PRINTF("Received message from unknown address");

		return (ms_stop(instance->ucast_socket, &instance->mcast_addr.sas,
		    msg_decoded, from));
	}

	if (rh_item->server_info.state == RH_SS_FINISHING) {
		DEBUG_PRINTF("We are in finishing state. Sending request to stop.");

		return (ms_stop(instance->ucast_socket, &instance->mcast_addr.sas,
		    msg_decoded, from));
	}

	if (!msg_decoded->mcast_prefix_isset) {
		DEBUG_PRINTF("Mcast prefix is not set");

		return (ms_response(instance->ucast_socket, &instance->mcast_addr.sas,
		    msg_decoded, from, 0, 1, NULL, 0));
	}

	pref_found = 0;

	tlv_iter_init(msg, msg_len, &tlv_iter);
	while (tlv_iter_next(&tlv_iter) == 0) {
		if (tlv_iter_get_type(&tlv_iter) == TLV_OPT_TYPE_MCAST_PREFIX) {
			if (tlv_iter_pref_eq(&tlv_iter, &instance->mcast_addr.sas)) {
				pref_found = 1;

				break;
			}
		}
	}

	if (!pref_found) {
		DEBUG_PRINTF("Can't find required prefix");

		return (ms_response(instance->ucast_socket, &instance->mcast_addr.sas, msg_decoded,
		    from, 0, 1, NULL, 0));
	}

	if (util_time_absdiff(rh_item->server_info.last_init_ts, rp_timestamp) <
	    DEFAULT_WAIT_TIME) {
		DEBUG_PRINTF("Time diff between two init messages too short. Ignoring message.");
		return (0);
	}

	util_gen_sid(rh_item->server_info.ses_id);
	rh_item->server_info.state = RH_SS_ANSWER;
	rh_item->server_info.last_init_ts = rp_timestamp;

	return (ms_response(instance->ucast_socket, &instance->mcast_addr.sas, msg_decoded, from,
	    1, 0, rh_item->server_info.ses_id, SESSIONID_LEN));
}

/*
 * Process query msg. instance is omping instance, msg is received message with msg_len length,
 * msg_decoded is decoded message and from is sender of message. rp_timestamp is receiving time
 * of packet.
 * Function returns 0 on sucess, otherwise same error as rs_sendto or -4 if message cannot be
 * created (usually due to small message buffer)
 */
static int
omping_process_query_msg(struct omping_instance *instance, const char *msg, size_t msg_len,
    const struct msg_decoded *msg_decoded, const struct sockaddr_storage *from,
    struct timeval rp_timestamp)
{
	struct rh_item *rh_item;

	rh_item = rh_list_find(&instance->remote_hosts, (const struct sockaddr *)from);
	if (rh_item == NULL) {
		DEBUG_PRINTF("Received message from unknown address");

		return (ms_stop(instance->ucast_socket, &instance->mcast_addr.sas,
		    msg_decoded, from));
	}

	if (rh_item->server_info.state != RH_SS_ANSWER) {
		DEBUG_PRINTF("Server is not in answer state");

		return (ms_stop(instance->ucast_socket, &instance->mcast_addr.sas,
		    msg_decoded, from));
	}

	if (!msg_decoded->seq_num_isset || msg_decoded->mcast_grp == NULL) {
		DEBUG_PRINTF("Received message doesn't have mcast group set");

		return (ms_stop(instance->ucast_socket, &instance->mcast_addr.sas,
		    msg_decoded, from));
	}

	if (msg_decoded->ses_id_len != SESSIONID_LEN ||
	    memcmp(msg_decoded->ses_id, rh_item->server_info.ses_id, SESSIONID_LEN) != 0) {
		DEBUG_PRINTF("Received message session id isn't expected");

		return (ms_stop(instance->ucast_socket, &instance->mcast_addr.sas,
		    msg_decoded, from));
	}

	/*
	 * Rate limiting
	 */
	if (instance->rate_limit_time > 0) {
		if (gcra_rl(&rh_item->server_info.gcra, rp_timestamp) == 0) {
			DEBUG_PRINTF("Received message rate limited");
			return (0);
		}
	}

	/*
	 * Answer to query message
	 */
	return (ms_answer(instance->ucast_socket, &instance->mcast_addr.sas, msg, msg_len,
	    msg_decoded, from, instance->ttl, MS_ANSWER_BOTH));
}

/*
 * Process response message. Instance is omping instance, msg is received message with msg_len
 * length, msg_decoded is decoded message and from is address of sender.
 * Function returns 0 on sucess, otherwise same error as rs_sendto or -4 if message cannot be
 * created (usually due to small message buffer), or -5 if message is invalid (not for us, message
 * without client_id, ...).
 */
static int
omping_process_response_msg(struct omping_instance *instance, const char *msg, size_t msg_len,
    const struct msg_decoded *msg_decoded, const struct sockaddr_storage *from)
{
	struct rh_item *rh_item;
	enum rh_client_state old_cstate;
	const char *ci_ses_id;
	const char *msg_ses_id;
	int send_res;

	rh_item = rh_list_find(&instance->remote_hosts, (const struct sockaddr *)from);
	if (rh_item == NULL) {
		DEBUG_PRINTF("Received message from unknown address");

		return (-5);
	}

	if (rh_item->client_info.state == RH_CS_STOP) {
		DEBUG_PRINTF("Client is in stop state. Ignoring message.");

		return (-5);
	}

	if (msg_decoded->client_id == NULL) {
		DEBUG_PRINTF("Message doesn't contain client id");

		return (-5);
	}

	if (msg_decoded->client_id_len != CLIENTID_LEN ||
	    memcmp(msg_decoded->client_id, rh_item->client_info.client_id, CLIENTID_LEN) != 0) {
		DEBUG_PRINTF("Message doesn't contain our client id");

		return (-5);
	}

	if (instance->op_mode == OMPING_OP_MODE_SHOW_VERSION) {
		if (msg_decoded->server_info_len > 0) {
			rh_item->client_info.server_info_len = msg_decoded->server_info_len;

			free(rh_item->client_info.server_info);

			rh_item->client_info.server_info =
			    (char *)malloc(rh_item->client_info.server_info_len);

			if (rh_item->client_info.server_info == NULL) {
				errx(1, "Can't alloc memory");
			}

			memcpy(rh_item->client_info.server_info, msg_decoded->server_info,
			    rh_item->client_info.server_info_len);

			omping_client_move_to_stop(instance, rh_item,
			    RH_CSR_REMOTE_VERSION_RECEIVED);
		} else {
			DEBUG_PRINTF("Message doesn't contain server information");

			return (-5);
		}

		return (0);
	}

	if (msg_decoded->mcast_grp == NULL || msg_decoded->mcast_grp_len == 0) {
		DEBUG_PRINTF("Server doesn't send us multicast group");

		if (rh_item->client_info.state == RH_CS_QUERY) {
			DEBUG_PRINTF("Client was in query state. Put to initial state");

			rh_item->client_info.state = RH_CS_INITIAL;
			/*
			 * Technically, packet was sent and also received so no lost at all
			 */
			rh_item->client_info.no_sent--;

			util_gen_cid(rh_item->client_info.client_id, &instance->local_addr);
		} else {
			DEBUG_PRINTF("Client was not in query state. Put it to stop state");
			omping_client_move_to_stop(instance, rh_item, RH_CSR_SERVER);
		}

		return (-5);
	}

	if (!(tlv_mcast_grp_eq(&instance->mcast_addr.sas, msg_decoded->mcast_grp,
	    msg_decoded->mcast_grp_len))) {
		DEBUG_PRINTF("Server send us different multicast group then expected");

	}

	if (msg_decoded->ses_id == NULL) {
		DEBUG_PRINTF("Message doesn't contain session id");

		return (-5);
	}

	if (rh_item->client_info.ses_id_len == msg_decoded->ses_id_len) {
		ci_ses_id = rh_item->client_info.ses_id;
		msg_ses_id = msg_decoded->ses_id;

		if (memcmp(ci_ses_id, msg_ses_id, msg_decoded->ses_id_len) == 0) {
			DEBUG_PRINTF("Duplicate server response");

			return (-5);
		}
	}

	old_cstate = rh_item->client_info.state;
	rh_item->client_info.state = RH_CS_QUERY;
	rh_item->client_info.ses_id_len = msg_decoded->ses_id_len;

	free(rh_item->client_info.ses_id);

	rh_item->client_info.ses_id = (char *)malloc(rh_item->client_info.ses_id_len);
	if (rh_item->client_info.ses_id == NULL) {
		errx(1, "Can't alloc memory");
	}

	memcpy(rh_item->client_info.ses_id, msg_decoded->ses_id, rh_item->client_info.ses_id_len);

	if (old_cstate == RH_CS_INITIAL) {
		if (instance->quiet < 2) {
			print_client_state(rh_item->addr->host_name, instance->hn_max_len,
			    instance->transport_method, &instance->mcast_addr.sas,
			    &rh_item->addr->sas, RH_CS_QUERY, RH_CSR_NONE);
		}
	}

	send_res = omping_send_client_query(instance, rh_item, (old_cstate == RH_CS_INITIAL));

	return (send_res);
}

/*
 * Send client query message. instance is omping instance. ri is one item fro rh_list and it's
 * client to process. increase is boolean variable. If set, seq_num and no_sent packets are
 * increased.
 * Function return 0 on success, otherwise same error as rs_sendto or -4 if message cannot be
 * created (usually due to small message buffer)
 */
static int
omping_send_client_query(struct omping_instance *instance, struct rh_item *ri, int increase)
{
	struct rh_item_ci *ci;
	int send_res;

	ci = &ri->client_info;

	if (increase) {
		if (ci->no_sent + 1 == ((uint64_t)~0)) {
			omping_client_move_to_stop(instance, ri, RH_CSR_SEND_MAXIMUM);
			DEBUG_PRINTF("Maximum number of sent messages for %s exhausted. "
			    "Moving to stop state.", ri->addr->host_name);

			return (0);
		}

		if (instance->send_count_queries > 0 &&
		    ci->no_sent + 1 > instance->send_count_queries) {
			omping_client_move_to_stop(instance, ri, RH_CSR_TO_SEND_EXHAUSTED);
			DEBUG_PRINTF("Number of messages to be sent by %s exhausted. "
			    "Moving to stop state.", ri->addr->host_name);

			return (0);
		}

		ci->seq_num++;
		ci->no_sent++;

		if (ci->seq_num == 0) {
			ci->seq_num_overflow = 1;
			ci->seq_num++;
		}
	}

	send_res = ms_query(instance->ucast_socket, &ri->addr->sas, &instance->mcast_addr.sas,
	    ci->seq_num, ci->client_id, ci->ses_id, ci->ses_id_len);

	return (send_res);
}

/*
 * Send client init or request messages to all of remote hosts. instance is omping instance.
 * Function return 0 on success, or -2 on EINTR.
 */
static int
omping_send_client_msgs(struct omping_instance *instance)
{
	struct rh_item *remote_host;
	struct rh_item_ci *ci;
	int send_res;

	TAILQ_FOREACH(remote_host, &instance->remote_hosts, entries) {
		send_res = 0;
		ci = &remote_host->client_info;

		switch (ci->state) {
		case RH_CS_INITIAL:
			/*
			 * Initial message is send at most after DEFAULT_WAIT_TIME
			 */
			if (util_time_absdiff(ci->last_init_ts, util_get_time()) >
			    DEFAULT_WAIT_TIME) {
				if (instance->quiet < 2) {
					print_client_state(remote_host->addr->host_name,
					    instance->hn_max_len, instance->transport_method, NULL,
					    &remote_host->addr->sas, RH_CS_INITIAL, RH_CSR_NONE);
				}

				send_res = ms_init(instance->ucast_socket, &remote_host->addr->sas,
				    &instance->mcast_addr.sas, ci->client_id,
				    (instance->op_mode == OMPING_OP_MODE_SHOW_VERSION ? 1 : 0));

				ci->last_init_ts = util_get_time();
			}
			break;
		case RH_CS_QUERY:
			if (instance->wait_time == 0) {
				/*
				 * Handle wait time zero specifically. Send query if answer for
				 * previous query received or after 1ms.
				 */
				if (ci->lru_seq_num == ci->seq_num ||
				    util_time_absdiff(ci->last_query_ts, util_get_time()) >= 1) {
					send_res = omping_send_client_query(instance, remote_host,
					    1);

					ci->last_query_ts = util_get_time();
				}
			} else {
				send_res = omping_send_client_query(instance, remote_host, 1);
			}
			break;
		case RH_CS_STOP:
			/*
			 * Do nothing
			 */
			break;
		}

		switch (send_res) {
		case -1:
			err(2, "Cannot send message");
			/* NOTREACHED */
			break;
		case -2:
			return (-2);
			/* NOTREACHED */
			break;
		case -3:
			warn("Send message error");
			ci->no_err_msgs++;
			break;
		case -4:
			DEBUG_PRINTF("Cannot send message. Buffer too small");
			break;
		}
	}

	return (0);
}

/*
 * Main loop of omping. It is used for receiving and sending messages. On the end, it prints final
 * statistics. instance is omping instance. timeout_time is maximum amount of time to keep loop
 * running (after this time, loop is ended). final_stats is boolean flag which determines if final
 * statistics should be displayed or not. allow_auto_exit is boolean which if set, allows auto exit
 * if every client is in STOP state.
 */
static void
omping_send_receive_loop(struct omping_instance *instance, int timeout_time, int final_stats,
    int allow_auto_exit)
{
	struct timeval start_time;
	int clients_res;
	int loop_end;
	int poll_rec_res;
	int receive_timeout;
	uint64_t time_diff;

	if (timeout_time != 0) {
		start_time = util_get_time();
	}

	loop_end = 0;

	do {
		clients_res = omping_send_client_msgs(instance);
		if (clients_res != 0 && clients_res != -2) {
			err(3, "unknown value of clients_res %u", clients_res);
			/* NOTREACHED */
		}

		if (clients_res == -2) {
			if (exit_requested) {
				loop_end = 1;
			}

			continue;
		}

		if (timeout_time != 0) {
			time_diff = util_time_absdiff(start_time, util_get_time());

			if ((int)time_diff + instance->wait_time > timeout_time) {
				receive_timeout = timeout_time - time_diff;
			} else {
				receive_timeout = instance->wait_time;
			}
		} else {
			receive_timeout = instance->wait_time;
		}

		poll_rec_res = omping_poll_receive_loop(instance, receive_timeout);

		if (poll_rec_res != 0 && poll_rec_res != -2) {
			err(3, "unknown value of poll_rec_res %u", poll_rec_res);
			/* NOTREACHED */
		}

		if (exit_requested) {
			loop_end = 1;
		}

		if (timeout_time != 0 &&
		    (int)util_time_absdiff(start_time, util_get_time()) >= timeout_time) {
			loop_end = 1;
		}

		if (allow_auto_exit && instance->auto_exit && instance->rh_no_active == 0) {
			loop_end = 1;
		}
	} while (!loop_end);

	if (final_stats) {
		if (instance->op_mode == OMPING_OP_MODE_SHOW_VERSION) {
			print_final_remote_version(&instance->remote_hosts, instance->hn_max_len);
		} else {
			print_final_stats(&instance->remote_hosts, instance->hn_max_len,
			    instance->transport_method);
		}
	}
}

/*
 * Print status of client with host_name (maximum length of host_name_len). transport_method is
 * transport method to be used, mcast_addr is current multicast address to be used by client.
 * remote_addr is address of client and state is current state of client.
 */
static void
print_client_state(const char *host_name, int host_name_len,
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
static void
print_final_remote_version(const struct rh_list *remote_hosts, int host_name_len)
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
static void
print_final_stats(const struct rh_list *remote_hosts, int host_name_len,
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
				loss_adj = get_packet_loss_percent(sent - ci->first_mcast_seq + 1,
				    received);
			}

			loss = get_packet_loss_percent(sent, received);

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
 * Print packet statistics. host_name is remote host name with maximal host_name_len length. seq is
 * sequence number of packet, is_dup is boolean with information if packet is duplicate or not,
 * msg_len is length of message, dist_set is boolean variable with information if dist is set or
 * not. dist is distance of packet (how TTL was changed). rtt_set is boolean variable with
 * information if rtt (current round trip time) and avg_rtt (average round trip time) is set and
 * computed or not. loss is number of lost packets. cast_type is type of packet received
 * (unicast/multicast/broadcast). cont_stat is boolean variable saying, if to display
 * continuous statistic or not.
 */
static void
print_packet_stats(const char *host_name, int host_name_len, uint32_t seq, int is_dup,
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
 * Register global signal handlers for application. sigaction is used to allow *BSD behavior, where
 * recvmsg, sendto, ... can return EINTR, what signal (Linux) doesn't do (functions are restarted
 * automatically)
 */
static void
register_signal_handlers(void)
{
	struct sigaction act;

	act.sa_handler = sigint_handler;
	sigemptyset(&act.sa_mask);
	act.sa_flags = 0;

	sigaction(SIGINT, &act, NULL);

	act.sa_handler = siginfo_handler;
#ifdef SIGINFO
	sigaction(SIGINFO, &act, NULL);
#endif
	sigaction(SIGUSR1, &act, NULL);
}

/*
 * Handler for SIGINFO signal
 */
static void
siginfo_handler(int sig)
{
	display_stats_requested++;
}

/*
 * Handler for SIGINT signal
 */
static void
sigint_handler(int sig)
{
	exit_requested++;

	DEBUG2_PRINTF("Exit requested %d times", exit_requested);

	if (exit_requested > MAX_EXIT_REQUESTS) {
		signal(SIGINT, SIG_DFL);
		kill(getpid(), SIGINT);
	}
}
