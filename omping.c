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
#include "logging.h"
#include "cli.h"
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
	struct ai_item local_addr, mcast_addr;
	struct rh_list remote_hosts;
	struct ai_list remote_addrs;
	char *local_ifname;
	int hn_max_len;
	int ip_ver;
	int ucast_socket;
	int mcast_socket;
	int wait_time;
	uint16_t port;
	uint8_t ttl;
};

/*
 * User requested exit of application (usually with SIGINT)
 */
static int exit_requested;

/*
 * Function prototypes
 */
static int	omping_check_msg_common(const struct msg_decoded *msg_decoded);

static void	omping_instance_create(struct omping_instance *instance, int argc,
    char *argv[]);

static void	omping_instance_free(struct omping_instance *instance);

static int	omping_poll_receive_loop(struct omping_instance *instance);

static int	omping_process_msg(struct omping_instance *instance, const char *msg,
    size_t msg_len, const struct sockaddr_storage *from, uint8_t ttl, int ucast);

static int	omping_process_answer_msg(struct omping_instance *instance, const char *msg,
    size_t msg_len, const struct msg_decoded *msg_decoded, const struct sockaddr_storage *from,
    uint8_t ttl, int ucast);

static int	omping_process_init_msg(struct omping_instance *instance, const char *msg,
    size_t msg_len, const struct msg_decoded *msg_decoded, const struct sockaddr_storage *from);

static int	omping_process_query_msg(struct omping_instance *instance, const char *msg,
    size_t msg_len, const struct msg_decoded *msg_decoded, const struct sockaddr_storage *from);

static int	omping_process_response_msg(struct omping_instance *instance, const char *msg,
    size_t msg_len, const struct msg_decoded *msg_decoded, const struct sockaddr_storage *from);

static int	omping_send_client_msgs(struct omping_instance *instance);

static void	omping_send_receive_loop(struct omping_instance *instance);

static void	print_client_state(const char *host_name, int host_name_len,
    const struct sockaddr_storage *mcast_addr, enum rh_client_state state);

static void	print_final_stats(const struct rh_list *remote_hosts, int host_name_len);

static void	print_packet_stats(const char *host_name, int host_name_len, uint32_t seq,
    int is_dup, size_t msg_len, int dist_set, uint8_t dist, int rtt_set, double rtt, double avg_rtt,
    int loss, int ucast);

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

	omping_instance_create(&instance, argc, argv);

	register_signal_handlers();

	omping_send_receive_loop(&instance);

	omping_instance_free(&instance);

	return 0;
}

/*
 * Test basic message characteristics. Return 0 on success, and -1 on fail.
 */
static int
omping_check_msg_common(const struct msg_decoded *msg_decoded)
{
	if (msg_decoded->version != 2) {
		DEBUG_PRINTF("Message version %d is not supported", msg_decoded->version);

		return (-1);
	}

	if (msg_decoded->msg_type != MSG_TYPE_INIT && msg_decoded->msg_type != MSG_TYPE_RESPONSE &&
	    msg_decoded->msg_type != MSG_TYPE_QUERY && msg_decoded->msg_type != MSG_TYPE_ANSWER) {
		DEBUG_PRINTF("Unknown type %c (0x%X) of message", msg_decoded->msg_type,
		    msg_decoded->msg_type);

		return (-1);
	}

	return (0);
}

/*
 * Create instance of omping. argc and argv are taken form main function. Result is stored in
 * instance parameter
 */
static void
omping_instance_create(struct omping_instance *instance, int argc, char *argv[])
{
	memset(instance, 0, sizeof(struct omping_instance));

	cli_parse(&instance->remote_addrs, argc, argv, &instance->local_ifname, &instance->ip_ver,
	    &instance->local_addr, &instance->wait_time, &instance->mcast_addr, &instance->port,
	    &instance->ttl);

	rh_list_create(&instance->remote_hosts, &instance->remote_addrs);

	instance->ucast_socket =
	    sf_create_unicast_socket(AF_CAST_SA(&instance->local_addr.sas), instance->ttl, 1,
	    instance->local_ifname);

	if (instance->ucast_socket == -1) {
		err(1, "Can't create/bind unicast socket");
	}

	instance->mcast_socket =
	    sf_create_multicast_socket((struct sockaddr *)&instance->mcast_addr.sas,
		AF_CAST_SA(&instance->local_addr.sas), instance->local_ifname, instance->ttl);

	if (instance->mcast_socket == -1) {
		err(1, "Can't create/bind multicast socket");
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
 * omping instance.
 * Function returns 0 on success, or -2 on EINTR.
 */
static int
omping_poll_receive_loop(struct omping_instance *instance)
{
	char msg[MAX_MSG_SIZE];
	struct sockaddr_storage from;
	struct timeval old_tstamp;
	int i;
	int poll_res;
	int receive_res;
	uint8_t ttl;
	int res;

	memset(&old_tstamp, 0, sizeof(old_tstamp));

	do {
		poll_res = rs_poll_timeout(instance->ucast_socket, instance->mcast_socket,
		    instance->wait_time, &old_tstamp);

		switch (poll_res) {
		case -1:
			err(2, "Cannot poll on sockets");
			/* NOTREACHED */
			break;
		case -2:
			return (-2);
			/* NOTREACHED */
			break;
		}

		for (i = 0; i < 2; i++) {
			receive_res = 0;

			if (i == 0 && poll_res & 1) {
				receive_res = rs_receive_msg(instance->ucast_socket, &from, msg,
				    sizeof(msg), &ttl);
			}

			if (i == 1 && poll_res & 2) {
				receive_res = rs_receive_msg(instance->mcast_socket, &from, msg,
				    sizeof(msg), &ttl);
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
				res = omping_process_msg(instance, msg, receive_res, &from, ttl,
				    (i == 0));

				if (res == -2) {
					return (-2);
				}
			}
		}
	} while (poll_res > 0);

	return (0);
}

/*
 * Process received message. Instance is omping instance, msg is received message with msg_len
 * length, from is source of message. ttl is packet Time-To-Live or 0, if that information was not
 * available. ucast is boolean variable which
 * determines whether packet is unicast (true != 0) or multicast (false = 0).
 * Function returns 0 on success or -2 on EINTR.
 */
static int
omping_process_msg(struct omping_instance *instance, const char *msg, size_t msg_len,
    const struct sockaddr_storage *from, uint8_t ttl, int ucast)
{
	char addr_str[INET6_ADDRSTRLEN];
	struct msg_decoded msg_decoded;
	int res;
	struct rh_item *rh_item;

	res = 0;

	msg_decode(msg, msg_len, &msg_decoded);

	af_sa_to_str((struct sockaddr *)from, addr_str);
	DEBUG_PRINTF("Received message from %s type %c (0x%X), len %zu", addr_str,
	    msg_decoded.msg_type, msg_decoded.msg_type, msg_len);

	if (omping_check_msg_common(&msg_decoded) == -1) {
		res = ms_stop(instance->ucast_socket, &instance->mcast_addr.sas, &msg_decoded,
		    from);
	} else {
		switch (msg_decoded.msg_type) {
		case MSG_TYPE_INIT:
			if (!ucast)
				goto error_unknown_mcast;
			res = omping_process_init_msg(instance, msg, msg_len, &msg_decoded, from);
			break;
		case MSG_TYPE_RESPONSE:
			if (!ucast)
				goto error_unknown_mcast;
			res = omping_process_response_msg(instance, msg, msg_len, &msg_decoded,
			    from);
			break;
		case MSG_TYPE_QUERY:
			if (!ucast)
				goto error_unknown_mcast;
			res = omping_process_query_msg(instance, msg, msg_len, &msg_decoded, from);
			break;
		case MSG_TYPE_ANSWER:
			res = omping_process_answer_msg(instance, msg, msg_len, &msg_decoded, from,
			    ttl, ucast);
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
}

/*
 * Process answer message. Instance is omping instance, msg is received message with msg_len length,
 * msg_decoded is decoded message, from is address of sender. ttl is Time-To-Live of packet. If ttl
 * is 0, it means that it was not possible to find out ttl. ucast is boolean variable which
 * determines whether packet is unicast (true != 0) or multicast (false = 0).
 * Function returns 0 on sucess, otherwise same error as rs_sendto or -4 if message cannot be
 * created (usually due to small message buffer), or -5 if message is invalid (not for us, message
 * without client_id, ...).
 */
static int
omping_process_answer_msg(struct omping_instance *instance, const char *msg, size_t msg_len,
    const struct msg_decoded *msg_decoded, const struct sockaddr_storage *from, uint8_t ttl,
    int ucast)
{
	struct rh_item *rh_item;
	double rtt;
	double avg_rtt;
	uint32_t received;
	int cast_index;
	int dist_set;
	int first_packet;
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

	if (ttl > 0 && msg_decoded->ttl > 0) {
		dist_set = 1;
		dist =  msg_decoded->ttl - ttl;
	} else {
		dist_set = dist = 0;
	}

	if (msg_decoded->client_tstamp_isset) {
		rtt_set = 1;
		rtt = util_time_double_absdiff(msg_decoded->client_tstamp, util_get_time());
	} else {
		rtt_set = rtt = 0;
	}

	avg_rtt = 0;
	cast_index = (ucast ? 0 : 1);

	first_packet = (rh_item->client_info.no_received[cast_index] == 0);

	received = ++rh_item->client_info.no_received[cast_index];
	if (rtt_set) {
		rh_item->client_info.rtt_sum[cast_index] += rtt;
		avg_rtt = rh_item->client_info.rtt_sum[cast_index] / received;

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

	if (received > rh_item->client_info.seq_num) {
		DEBUG_PRINTF("received > seq_num");
		loss = 0;
	} else {
		loss = (int)((1.0 - (float)received / (float)rh_item->client_info.seq_num) * 100.0);
	}

	print_packet_stats(rh_item->addr->host_name, instance->hn_max_len, msg_decoded->seq_num, 0,
	    msg_len, dist_set, dist, rtt_set, rtt, avg_rtt, loss, ucast);

	return (0);
}

/*
 * Process init messge. instance is omping_instance, msg is received message with msg_len length,
 * msg_decoded is decoded message and from is sockaddr of sender.
 * Function returns 0 on sucess, otherwise same error as rs_sendto or -4 if message cannot be
 * created (usually due to small message buffer)
 */
static int
omping_process_init_msg(struct omping_instance *instance, const char *msg, size_t msg_len,
    const struct msg_decoded *msg_decoded, const struct sockaddr_storage *from)
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

	util_gen_sid(rh_item->server_info.ses_id);
	rh_item->server_info.state = RH_SS_ANSWER;

	return (ms_response(instance->ucast_socket, &instance->mcast_addr.sas, msg_decoded, from,
	    1, 0, rh_item->server_info.ses_id, SESSIONID_LEN));
}

/*
 * Process query msg. instance is omping instance, msg is received message with msg_len length,
 * msg_decoded is decoded message and from is sender of message.
 * Function returns 0 on sucess, otherwise same error as rs_sendto or -4 if message cannot be
 * created (usually due to small message buffer)
 */
static int
omping_process_query_msg(struct omping_instance *instance, const char *msg, size_t msg_len,
    const struct msg_decoded *msg_decoded, const struct sockaddr_storage *from)
{
	struct rh_item *rh_item;

	rh_item = rh_list_find(&instance->remote_hosts, (const struct sockaddr *)from);
	if (rh_item == NULL) {
		DEBUG_PRINTF("Received message from unknown address");

		return (ms_stop(instance->ucast_socket, &instance->mcast_addr.sas,
		    msg_decoded, from));
	}

	if (rh_item->server_info.state != RH_SS_ANSWER) {
		DEBUG_PRINTF("Client is not in answer state");

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

	if (msg_decoded->mcast_grp == NULL || msg_decoded->mcast_grp_len == 0) {
		DEBUG_PRINTF("Server doesn't send us multicast group");

		if (rh_item->client_info.state == RH_CS_QUERY) {
			DEBUG_PRINTF("Client was in query state. Put to initial state");

			rh_item->client_info.state = RH_CS_INITIAL;
			util_gen_cid(rh_item->client_info.client_id, &instance->local_addr);
		} else {
			DEBUG_PRINTF("Client was not in query state. Put it to stop state");
			rh_item->client_info.state = RH_CS_STOP;
			print_client_state(rh_item->addr->host_name, instance->hn_max_len, NULL,
			    RH_CS_STOP);
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

	old_cstate = rh_item->client_info.state;
	rh_item->client_info.state = RH_CS_QUERY;
	rh_item->client_info.ses_id_len = msg_decoded->ses_id_len;

	free(rh_item->client_info.ses_id);

	rh_item->client_info.ses_id = malloc(rh_item->client_info.ses_id_len);
	if (rh_item->client_info.ses_id == NULL) {
		errx(1, "Can't alloc memory");
	}

	memcpy(rh_item->client_info.ses_id, msg_decoded->ses_id, rh_item->client_info.ses_id_len);

	if (old_cstate == RH_CS_INITIAL) {
		rh_item->client_info.seq_num++;

		print_client_state(rh_item->addr->host_name, instance->hn_max_len,
		    &instance->mcast_addr.sas, RH_CS_QUERY);
	}

	return (ms_query(instance->ucast_socket, from, &instance->mcast_addr.sas,
	    rh_item->client_info.seq_num, rh_item->client_info.client_id,
	    rh_item->client_info.ses_id, rh_item->client_info.ses_id_len));
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
				print_client_state(remote_host->addr->host_name,
				    instance->hn_max_len, NULL, RH_CS_INITIAL);

				send_res = ms_init(instance->ucast_socket, &remote_host->addr->sas,
				    &instance->mcast_addr.sas, ci->client_id, 0);

				ci->last_init_ts = util_get_time();
			}
			break;
		case RH_CS_QUERY:
			send_res = ms_query(instance->ucast_socket, &remote_host->addr->sas,
			    &instance->mcast_addr.sas, ++ci->seq_num, ci->client_id,
			    ci->ses_id, ci->ses_id_len);
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
 * statistics. instance is omping instance.
 */
static void
omping_send_receive_loop(struct omping_instance *instance)
{
	int clients_res;
	int poll_rec_res;

	do {
		clients_res = omping_send_client_msgs(instance);
		if (clients_res == -2) {
			continue;
		}

		poll_rec_res = omping_poll_receive_loop(instance);
		if (poll_rec_res == -2) {
			continue;
		}
	} while (!exit_requested);

	print_final_stats(&instance->remote_hosts, instance->hn_max_len);
}

/*
 * Print status of client with host_name (maximum length of host_name_len). mcast_addr is current
 * multicast address to be used by client and state is current state of client.
 */
static void
print_client_state(const char *host_name, int host_name_len,
    const struct sockaddr_storage *mcast_addr, enum rh_client_state state)
{
	char addr_str[INET6_ADDRSTRLEN];

	printf("%-*s : ", host_name_len, host_name);

	if (mcast_addr != NULL) {
		af_sa_to_str(AF_CAST_SA(mcast_addr), addr_str);
	}

	switch (state) {
	case RH_CS_INITIAL:
		printf("waiting for response msg");
		break;
	case RH_CS_QUERY:
		printf("joined (S,G) = (*, %s), pinging", addr_str);
		break;
	case RH_CS_STOP:
		printf("server told us to stop");
		break;
	}
	printf("\n");
}

/*
 * Print final statistics. remote_hosts is list with all remote hosts and host_name_len is maximal
 * length of host name in list.
 */
static void
print_final_stats(const struct rh_list *remote_hosts, int host_name_len)
{
	char *cast_str;
	struct rh_item *rh_item;
	struct rh_item_ci *ci;
	double avg_rtt;
	int i;
	int loss;
	uint32_t received;

	printf("\n");

	TAILQ_FOREACH(rh_item, remote_hosts, entries) {
		for (i = 0; i < 2; i++) {
			cast_str = (i == 0 ? "uni" : "multi");
			ci = &rh_item->client_info;

			received = ci->no_received[i];

			printf("%-*s : ", host_name_len, rh_item->addr->host_name);

			if (received == 0) {
				printf("response message never received\n");
				break;
			}

			if (received > rh_item->client_info.seq_num) {
				DEBUG_PRINTF("received > seq_num");
				loss = 0;
			} else {
				loss = (int)((1.0 - (float)received / (float)ci->seq_num) * 100.0);
			}

			avg_rtt = ci->rtt_sum[i] / received;

			printf("%5scast, ", cast_str);

			printf("xmt/rcv/%%loss = ");
			printf("%"PRIu32"/%"PRIu32"/%d%%", ci->seq_num, received, loss);

			printf(", min/avg/max = ");
			printf("%.3f/%.3f/%.3f", ci->rtt_min[i], avg_rtt, ci->rtt_max[i]);
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
 * computed or not. loss is number of lost packets. ucast is boolean variable saying if packet was
 * unicast (true) or multicast (false).
 */
static void
print_packet_stats(const char *host_name, int host_name_len, uint32_t seq, int is_dup,
    size_t msg_len, int dist_set, uint8_t dist, int rtt_set, double rtt, double avg_rtt, int loss,
    int ucast)
{
	char *cast_str;

	cast_str = (ucast ? "uni" : "multi");

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

	printf(" (");

	if (rtt_set) {
		printf("%.3f avg, ", avg_rtt);
	}

	printf("%d%% loss)", loss);
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
