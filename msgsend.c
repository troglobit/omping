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

#include <stdlib.h>

#include "addrfunc.h"
#include "logging.h"
#include "msg.h"
#include "msgsend.h"
#include "omping.h"
#include "rsfunc.h"
#include "util.h"

/*
 * Send answer message. ucast_socket is socket used to send message, mcast_addr is used multicast
 * address, orig_msg is received query message with orig_msg_len, decoded is decoded message,
 * to is sockaddr_storage address of destination, ttl is set TTL and answer_type can specify what
 * type of response to send.
 * Function returns 0 on sucess, otherwise same error as rs_sendto or -4 if message cannot be
 * created (usually due to small message buffer)
 */
int
ms_answer(int ucast_socket, const struct sockaddr_storage *mcast_addr, const char *orig_msg,
    size_t orig_msg_len, const struct msg_decoded *decoded, const struct sockaddr_storage *to,
    uint8_t ttl, enum ms_answer_type answer_type)
{
	char addr_str[INET6_ADDRSTRLEN];
	char new_msg[MAX_MSG_SIZE];
	struct sockaddr_storage to_mcast;
	size_t new_msg_len;
	ssize_t sent;

	new_msg_len = msg_answer_create(orig_msg, orig_msg_len, new_msg, sizeof(new_msg),
	    ttl, decoded->request_opt_server_tstamp);

	if (new_msg_len == 0) {
		return (-4);
	}

	if (answer_type == MS_ANSWER_UCAST || answer_type == MS_ANSWER_BOTH) {
		af_sa_to_str(AF_CAST_SA(to), addr_str);
		DEBUG_PRINTF("Sending unicast answer msg to %s", addr_str);

		msg_update_server_tstamp(new_msg, new_msg_len);

		sent = rs_sendto(ucast_socket, new_msg, new_msg_len, to);

		if (sent < 0) {
			return (sent);
		}
	}

	if (answer_type == MS_ANSWER_MCAST || answer_type == MS_ANSWER_BOTH) {
		af_copy_addr(mcast_addr, to, 1, 2, &to_mcast);

		af_sa_to_str(AF_CAST_SA(&to_mcast), addr_str);
		DEBUG_PRINTF("Sending multicast answer msg to %s", addr_str);

		msg_update_server_tstamp(new_msg, new_msg_len);

		sent = rs_sendto(ucast_socket, new_msg, new_msg_len, &to_mcast);

		if (sent < 0) {
			return (sent);
		}
	}

	return (0);
}

/*
 * Send init message. ucast_socket is socket used to send message, remote_addr is address of host
 * to send message, mcast_addr is used multicast address, client_id is client id string with
 * CLIENTID_LEN length, req_si should be non 0 if server information request is required.
 * Function returns 0 on success, otherwise same error as rs_sendto or -4 if message cannot be
 * created (usually due to small message buffer)
 */
int
ms_init(int ucast_socket, const struct sockaddr_storage *remote_addr,
    const struct sockaddr_storage *mcast_addr, const char *client_id, int req_si)
{
	char addr_str[INET6_ADDRSTRLEN];
	char msg[MAX_MSG_SIZE];
	size_t msg_len;
	ssize_t sent;

	af_sa_to_str(AF_CAST_SA(remote_addr), addr_str);
	DEBUG_PRINTF("Sending init msg to %s", addr_str);

	msg_len = msg_init_create(msg, sizeof(msg), req_si, mcast_addr, client_id, CLIENTID_LEN);

	if (msg_len == 0) {
		return (-4);
	}

	sent = rs_sendto(ucast_socket, msg, msg_len, remote_addr);

	return (sent);
}

/*
 * Send query message. ucast_socket is socket used to send message, remote_addr is address of host
 * to send message, mcast_addr is used multicast address, client_id is client id string with
 * CLIENTID_LEN length, ses_id is Session ID string with ses_id_len length. seq_num is sequential
 * number to set in packet.
 * Function returns 0 on success, otherwise same error as rs_sendto or -4 if message cannot be
 * created (usually due to small message buffer)
 */
int
ms_query(int ucast_socket, const struct sockaddr_storage *remote_addr,
    const struct sockaddr_storage *mcast_addr, uint32_t seq_num, const char *client_id,
    const char *ses_id, size_t ses_id_len)
{
	char addr_str[INET6_ADDRSTRLEN];
	char msg[MAX_MSG_SIZE];
	size_t msg_len;
	ssize_t sent;

	af_sa_to_str(AF_CAST_SA(remote_addr), addr_str);
	DEBUG_PRINTF("Sending query msg to %s", addr_str);

	msg_len = msg_query_create(msg, sizeof(msg), mcast_addr, seq_num, 0, client_id,
	    CLIENTID_LEN, ses_id, SESSIONID_LEN);

	if (msg_len == 0) {
		return (-4);
	}

	sent = rs_sendto(ucast_socket, msg, msg_len, remote_addr);

	return (sent);
}

/*
 * Send response message. ucast_socket is socket used to send message, mcast_addr is used multicast
 * address, decoded is decoded message, to is sockaddr_storage address of destination, mcast_grp is
 * used to distinguish if add or not add mcast group tlv, similarly to mcast_prefix. session_id and
 * is session id string with session_id_len length.
 * Function returns 0 on sucess, otherwise same error as rs_sendto or -4 if message cannot be
 * created (usually due to small message buffer)
 */
int
ms_response(int ucast_socket, const struct sockaddr_storage *mcast_addr,
    const struct msg_decoded *decoded, const struct sockaddr_storage *to, int mcast_grp,
    int mcast_prefix, const char *session_id, size_t session_id_len)
{
	char addr_str[INET6_ADDRSTRLEN];
	char msg[MAX_MSG_SIZE];
	size_t msg_len;
	ssize_t sent;

	af_sa_to_str((struct sockaddr *)to, addr_str);
	DEBUG_PRINTF("Sending response msg to %s", addr_str);

	msg_len = msg_response_create(msg, sizeof(msg), decoded, mcast_grp, mcast_prefix,
	    mcast_addr, session_id, session_id_len);

	if (msg_len == 0) {
		return (-4);
	}

	sent = rs_sendto(ucast_socket, msg, msg_len, to);

	return (sent);
}

/*
 * Send response message with stop meaning. It's just shortcut to ms_send_response where
 * parameters with same name has same meaning. Also returned values are same.
 */
int
ms_stop(int ucast_socket, const struct sockaddr_storage *mcast_addr,
    const struct msg_decoded *decoded, const struct sockaddr_storage *to)
{
	return (ms_response(ucast_socket, mcast_addr, decoded, to, 0,0, NULL, 0));
}
