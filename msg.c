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

#include <err.h>
#include <stdio.h>
#include <string.h>

#include "logging.h"
#include "msg.h"
#include "omping.h"
#include "tlv.h"
#include "util.h"

/*
 * Create answer message from query message. orig_msg is pointer to buffer with query message
 * with orig_msg_len length (only used bytes, not buffer size). new_msg is pointer to buffer where
 * to store result message. new_msg_len is size of buffer. ttl is value of TTL option. server_tstamp
 * is boolean variable and if set, server timestamp option is added to message.
 *
 * All options from original messages are copied without changing order. Only exceptions are Server
 * Info, Multicast Prefix, Session ID, TTL and Server Timestamp, which are not copied.
 *
 * Returned value is size of new message or 0 on fail (mostly because msg_len
 * is smaller then needed). If success, new message is always at least 1 bytes long.
 */
size_t
msg_answer_create(const char *orig_msg, size_t orig_msg_len, char *new_msg, size_t new_msg_len,
    uint8_t ttl, int server_tstamp)
{
	struct tlv_iterator tlv_iter;
	enum tlv_opt_type opt_type;
	size_t pos;

	pos = 0;

	new_msg[pos++] = (unsigned char)MSG_TYPE_ANSWER;

	memset(&tlv_iter, 0, sizeof(tlv_iter));
	tlv_iter_init(orig_msg, orig_msg_len, &tlv_iter);

	while (tlv_iter_next(&tlv_iter) != -1) {
		opt_type = tlv_iter_get_type(&tlv_iter);
		if (opt_type != TLV_OPT_TYPE_SERVER_INFO &&
		    opt_type != TLV_OPT_TYPE_MCAST_PREFIX &&
		    opt_type != TLV_OPT_TYPE_SES_ID &&
		    opt_type != TLV_OPT_TYPE_TTL &&
		    opt_type != TLV_OPT_TYPE_SERVER_TSTAMP) {
			tlv_iter_item_copy(&tlv_iter, new_msg, new_msg_len, &pos);
		}
	}

	if (tlv_add_ttl(new_msg, new_msg_len, &pos, ttl) == -1)
		goto small_buf_err;

	if (server_tstamp) {
		if (tlv_add_server_tstamp(new_msg, new_msg_len, &pos) == -1)
			goto small_buf_err;
	}

	return (pos);

small_buf_err:
	return (0);
}

/*
 * Decode message. Decoded message is stored in msg_decoded structure.
 */
void
msg_decode(const char *msg, size_t msg_len, struct msg_decoded *decoded)
{
	char debug_str[128];
	struct tlv_iterator tlv_iter;
	size_t pos;
	uint32_t u32, u32_2;
	uint16_t tlv_len;
	uint16_t u16;
	uint8_t u8;

	memset(decoded, 0, sizeof(struct msg_decoded));

	decoded->msg_type = (enum msg_type)msg[0];

	DEBUG2_PRINTF("Message type %c (0x%X)", decoded->msg_type, decoded->msg_type);

	tlv_iter_init(msg, msg_len, &tlv_iter);

	while (tlv_iter_next(&tlv_iter) == 0) {
		tlv_len = tlv_iter_get_len(&tlv_iter);

		if (logging_get_verbose() >= LOGGING_LEVEL_DEBUG2) {
			snprintf(debug_str, sizeof(debug_str), "%u:%s:%u:",
			    tlv_iter_get_type(&tlv_iter),
			    tlv_opt_type_to_str(tlv_iter_get_type(&tlv_iter)), tlv_len);
		}

		switch (tlv_iter_get_type(&tlv_iter)) {
		case TLV_OPT_TYPE_VERSION:
			if (tlv_len == 1) {
				memcpy(&u8, tlv_iter_get_data(&tlv_iter), sizeof(u8));

				decoded->version = u8;

				DEBUG2_PRINTF("%s%u", debug_str, u8);
			} else {
				DEBUG2_PRINTF("%slen != 1", debug_str);
			}
			break;
		case TLV_OPT_TYPE_CLIENT_ID:
			if (tlv_len > 0) {
				decoded->client_id_len = tlv_len;
				decoded->client_id = tlv_iter_get_data(&tlv_iter);

				DEBUG2_HEXDUMP(debug_str, decoded->client_id, tlv_len);
			} else {
				DEBUG2_PRINTF("%slen <= 0", debug_str);
			}
			break;
		case TLV_OPT_TYPE_SEQ_NUM:
			if (tlv_len == 4) {
				decoded->seq_num_isset = 1;
				memcpy(&u32, tlv_iter_get_data(&tlv_iter), sizeof(u32));
				u32 = ntohl(u32);
				decoded->seq_num = u32;

				DEBUG2_PRINTF("%s%u", debug_str, u32);
			} else {
				DEBUG2_PRINTF("%slen != 4", debug_str);
			}
			break;
		case TLV_OPT_TYPE_CLIENT_TSTAMP:
			if (tlv_len == 8) {
				memcpy(&u32, tlv_iter_get_data(&tlv_iter), sizeof(u32));
				u32 = ntohl(u32);
				decoded->client_tstamp.tv_sec = u32;

				memcpy(&u32_2, tlv_iter_get_data(&tlv_iter) + sizeof(u32),
				    sizeof(u32_2));
				u32_2 = ntohl(u32_2);
				decoded->client_tstamp.tv_usec = u32_2;

				decoded->client_tstamp_isset = 1;

				DEBUG2_PRINTF("%s(%u,%u)", debug_str, u32, u32_2);
			} else {
				DEBUG2_PRINTF("%slen != 8", debug_str);
			}
			break;
		case TLV_OPT_TYPE_MCAST_GRP:
			if (tlv_len > 2) {
				memcpy(&u16, tlv_iter_get_data(&tlv_iter), sizeof(u16));
				u16 = ntohs(u16);

				if ((u16 == AF_IANA_IP && tlv_len == 6) ||
				    (u16 == AF_IANA_IP6 && tlv_len == 18)) {
					decoded->mcast_grp_len = tlv_len;
					decoded->mcast_grp = tlv_iter_get_data(&tlv_iter);

					DEBUG2_PRINTF("%sAF %u", debug_str, u16);
				} else {
					DEBUG2_PRINTF("%sbad AF %u or len", debug_str, u16);
				}
			} else {
				DEBUG2_PRINTF("%slen <= 2", debug_str);
			}
			break;
		case TLV_OPT_TYPE_OPT_REQUEST:
			if (tlv_len > 1 && (tlv_len % 2  == 0)) {
				for (pos = 0; pos < (uint16_t)(tlv_len / 2); pos++) {
					memcpy(&u16, tlv_iter_get_data(&tlv_iter) + pos * 2,
					    sizeof(u16));

					u16 = ntohs(u16);

					switch (u16) {
					case TLV_OPT_TYPE_SERVER_INFO:
						decoded->request_opt_server_info = 1;

						DEBUG2_PRINTF("%s%zu opt %u", debug_str, pos, u16);
						break;
					case TLV_OPT_TYPE_SERVER_TSTAMP:
						decoded->request_opt_server_tstamp = 1;

						DEBUG2_PRINTF("%s%zu opt %u", debug_str, pos, u16);
						break;
					default:
						DEBUG2_PRINTF("%s%zu unknown opt %u", debug_str,
						    pos, u16);
						break;
					}
				}
			} else {
				DEBUG2_PRINTF("%slen <= 1 || (tlv_len %%2 != 0)", debug_str);
			}
			break;
		case TLV_OPT_TYPE_SERVER_INFO:
			if (tlv_len > 0) {
				decoded->server_info = tlv_iter_get_data(&tlv_iter);
				decoded->server_info_len = tlv_len;

				DEBUG2_HEXDUMP(debug_str, decoded->server_info, tlv_len);
			} else {
				DEBUG2_PRINTF("%slen <= 0", debug_str);
			}
			break;
		case TLV_OPT_TYPE_TTL:
			if (tlv_len == 1) {
				memcpy(&u8, tlv_iter_get_data(&tlv_iter), sizeof(u8));

				decoded->ttl = u8;

				DEBUG2_PRINTF("%s%u", debug_str, u8);
			} else {
				DEBUG2_PRINTF("%slen != 1", debug_str);
			}
			break;
		case TLV_OPT_TYPE_MCAST_PREFIX:
			if (tlv_len > 2) {
				memcpy(&u16, tlv_iter_get_data(&tlv_iter), sizeof(u16));
				u16 = ntohs(u16);

				if (u16 == AF_IANA_IP  || u16 == AF_IANA_IP6) {
					decoded->mcast_prefix_isset = 1;

					DEBUG2_PRINTF("%sAF %u", debug_str, u16);
				} else {
					DEBUG2_PRINTF("%sbad AF %u", debug_str, u16);
				}
			} else {
				DEBUG2_PRINTF("%slen <= 2", debug_str);
			}
			break;
		case TLV_OPT_TYPE_SES_ID:
			if (tlv_len > 0) {
				decoded->ses_id_len = tlv_len;
				decoded->ses_id = tlv_iter_get_data(&tlv_iter);

				DEBUG2_HEXDUMP(debug_str, decoded->ses_id, tlv_len);
			} else {
				DEBUG2_PRINTF("%slen <= 0", debug_str);
			}
			break;
		case TLV_OPT_TYPE_SERVER_TSTAMP:
			if (tlv_len == 8) {
				memcpy(&u32, tlv_iter_get_data(&tlv_iter), sizeof(u32));
				u32 = ntohl(u32);
				decoded->server_tstamp.tv_sec = u32;

				memcpy(&u32_2, tlv_iter_get_data(&tlv_iter) + sizeof(u32),
				    sizeof(u32_2));
				u32_2 = ntohl(u32_2);
				decoded->server_tstamp.tv_usec = u32_2;

				decoded->server_tstamp_isset = 1;

				DEBUG2_PRINTF("%s(%u,%u)", debug_str, u32, u32_2);
			} else {
				DEBUG2_PRINTF("%slen != 8", debug_str);
			}
			break;
		default:
			DEBUG2_PRINTF("%s", debug_str);
			break;
		}
	}
}

/*
 * Create init message. msg is pointer to buffer where to store result message. msg_len is size of
 * buffer. mcast_addr is required multicast address. client_id is client ID to store in message with
 * length client_id_len.
 *
 * Returned value is size of new message or 0 on fail (mostly because msg_len
 * is smaller then needed). If success, new message is always at least 1 bytes long.
 */
size_t
msg_init_create(char *msg, size_t msg_len, int req_si, const struct sockaddr_storage *mcast_addr,
    const char *client_id, size_t client_id_len)
{
	size_t pos;
	uint16_t u16;

	pos = 0;

	if (client_id == NULL) {
		return (0);
	}

	msg[pos++] = (unsigned char)MSG_TYPE_INIT;

	if (tlv_add_version(msg, msg_len, &pos) == -1)
		goto small_buf_err;

	if (tlv_add(msg, msg_len, &pos, TLV_OPT_TYPE_CLIENT_ID, client_id_len, client_id) == -1)
		goto small_buf_err;


	if (req_si) {
		u16 = TLV_OPT_TYPE_SERVER_INFO;

		if (tlv_add_opt_request(msg, msg_len, &pos, &u16, 1) == -1)
			goto small_buf_err;
	}


	if (tlv_add_mcast_prefix(msg, msg_len, &pos, mcast_addr) == -1)
		goto small_buf_err;

	return (pos);

small_buf_err:
	return (0);
}

/*
 * Create query message. msg is pointer to buffer where to store result message. msg_len is size
 * of buffer. mcast_addr is required multicast group address. server_tstamp is boolean to decide if
 * to include Option request option with server time stamp. client_id is Client ID with length
 * client_id_len. session_id with session_id_len is similar, but for Session ID.
 *
 * Returned value is size of new message or 0 on fail (mostly because msg_len
 * is smaller then needed). If success, new message is always at least 1 bytes long.
 */
size_t
msg_query_create(char *msg, size_t msg_len, const struct sockaddr_storage *mcast_addr,
    uint32_t seq_num, int server_tstamp, const char *client_id, size_t client_id_len,
    const char *session_id, size_t session_id_len)
{
	size_t pos;
	uint16_t u16;

	pos = 0;

	msg[pos++] = (unsigned char)MSG_TYPE_QUERY;

	if (tlv_add_version(msg, msg_len, &pos) == -1)
		goto small_buf_err;

	if (client_id) {
		if (tlv_add(msg, msg_len, &pos, TLV_OPT_TYPE_CLIENT_ID, client_id_len,
		    client_id) == -1) {
			goto small_buf_err;
		}
	}

	if (tlv_add_seq_num(msg, msg_len, &pos, seq_num) == -1)
		goto small_buf_err;

	if (tlv_add_client_tstamp(msg, msg_len, &pos) == -1)
		goto small_buf_err;

	if (tlv_add_mcast_grp(msg, msg_len, &pos, mcast_addr) == -1)
		goto small_buf_err;

	if (server_tstamp) {
		u16 = TLV_OPT_TYPE_SERVER_TSTAMP;

		if (tlv_add_opt_request(msg, msg_len, &pos, &u16, 1) == -1)
			goto small_buf_err;
	}

	if (tlv_add(msg, msg_len, &pos, TLV_OPT_TYPE_SES_ID, session_id_len, session_id) == -1)
		goto small_buf_err;

	return (pos);

small_buf_err:
	return (0);
}

/*
 * Create response message. msg is pointer to buffer where to store result message. msg_len is size
 * of buffer. msg_decoded is decoded init message used for some informations (like client id, ...).
 * mcast_grp and mcast_prefix are booleans used for decision, if to add Multicast Group and/or
 * Multicast Prefix options. mcast_addr is value for mcast_grp and/or mcast_prefix. If none of this
 * options is/are required, mcasr_addr can be set to NULL. ulticast address. session_id is
 * session ID of client.
 *
 * Returned value is size of new message or 0 on fail (mostly because msg_len
 * is smaller then needed). If success, new message is always at least 1 bytes long.
 */
size_t
msg_response_create(char *msg, size_t msg_len, const struct msg_decoded *msg_decoded,
    int mcast_grp, int mcast_prefix, const struct sockaddr_storage *mcast_addr,
    const char *session_id, size_t session_id_len)
{
	size_t pos;

	pos = 0;

	msg[pos++] = (unsigned char)MSG_TYPE_RESPONSE;
	if (tlv_add_version(msg, msg_len, &pos) == -1)
		goto small_buf_err;

	if (msg_decoded->client_id) {
		if (tlv_add(msg, msg_len, &pos, TLV_OPT_TYPE_CLIENT_ID, msg_decoded->client_id_len,
		    msg_decoded->client_id) == -1)
			goto small_buf_err;
	}

	if (msg_decoded->seq_num_isset) {
		if (tlv_add_seq_num(msg, msg_len, &pos, msg_decoded->seq_num) == -1)
			goto small_buf_err;
	}

	if (mcast_grp) {
		if (tlv_add_mcast_grp(msg, msg_len, &pos, mcast_addr) == -1)
			goto small_buf_err;
	}

	if (msg_decoded->request_opt_server_info) {
		if (tlv_add_server_info(msg, msg_len, &pos, PROGRAM_SERVER_INFO) == -1)
			goto small_buf_err;
	}

	if (mcast_prefix) {
		if (tlv_add_mcast_prefix(msg, msg_len, &pos, mcast_addr) == -1)
			goto small_buf_err;
	}

	if (session_id) {
		if (tlv_add(msg, msg_len, &pos, TLV_OPT_TYPE_SES_ID, session_id_len,
		    session_id) == -1) {
			goto small_buf_err;
		}
	}

	return (pos);

small_buf_err:
	return (0);
}

/*
 * Update Server Timestamp option in message to current time stamp. msg is pointer to buffer with
 * message and msg_len is length of message (without unused space).
 * Function returns 0 on success, otherwise -1.
 */
int
msg_update_server_tstamp(char *msg, size_t msg_len)
{
	struct tlv_iterator tlv_iter;
	size_t pos;

	memset(&tlv_iter, 0, sizeof(tlv_iter));
	tlv_iter_init(msg, msg_len, &tlv_iter);

	while (tlv_iter_next(&tlv_iter) != -1) {
		if (tlv_iter_get_type(&tlv_iter) == TLV_OPT_TYPE_SERVER_TSTAMP) {
			pos = tlv_iter.pos;

			if (tlv_add_server_tstamp(msg, msg_len, &pos) == -1)
				goto add_tstamp_err;
		}
	}

	return (0);

add_tstamp_err:
	return (-1);
}
