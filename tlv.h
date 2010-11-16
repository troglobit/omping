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

#ifndef _TLV_H_
#define _TLV_H_

#include <sys/socket.h>

#include <netinet/in.h>

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Definitions
 */

/*
 * Address families how defined by AIANA
 */
enum {
	AF_IANA_IP	= 1,
	AF_IANA_IP6	= 2,
};

/*
 * TLV option type definition
 */
enum tlv_opt_type {
	TLV_OPT_TYPE_VERSION		=  0,
	TLV_OPT_TYPE_CLIENT_ID		=  1,
	TLV_OPT_TYPE_SEQ_NUM		=  2,
	TLV_OPT_TYPE_CLIENT_TSTAMP	=  3,
	TLV_OPT_TYPE_MCAST_GRP		=  4,
	TLV_OPT_TYPE_OPT_REQUEST	=  5,
	TLV_OPT_TYPE_SERVER_INFO	=  6,
	/* 7 and 8 are reserved and copied only */
	TLV_OPT_TYPE_TTL		=  9,
	TLV_OPT_TYPE_MCAST_PREFIX	= 10,
	TLV_OPT_TYPE_SES_ID		= 11,
	TLV_OPT_TYPE_SERVER_TSTAMP	= 12,
};

/*
 * tlv_iterator type
 */
struct tlv_iterator {
	const char *msg;
	size_t msg_len;
	size_t pos;
};

/*
 * Functions
 */
extern int	tlv_add(char *msg, size_t msg_len, size_t *pos, enum tlv_opt_type opt_type,
    uint16_t opt_len, const void *value);

extern int	tlv_add_client_tstamp(char *msg, size_t msg_len, size_t *pos);

extern int	tlv_add_mcast_grp(char *msg, size_t msg_len, size_t *pos,
    const struct sockaddr_storage *sas);

extern int	tlv_add_mcast_prefix(char *msg, size_t msg_len, size_t *pos,
    const struct sockaddr_storage *sas);

extern int	tlv_add_opt_request(char *msg, size_t msg_len, size_t *pos, uint16_t *opts,
    size_t opts_len);

extern int	tlv_add_seq_num(char *msg, size_t msg_len, size_t *pos, uint32_t seq);

extern int	tlv_add_server_info(char *msg, size_t msg_len, size_t *pos,
    const char *server_info);

extern int	tlv_add_server_tstamp(char *msg, size_t msg_len, size_t *pos);

extern int	tlv_add_ttl(char *msg, size_t msg_len, size_t *pos, uint8_t ttl);

extern int	tlv_add_version(char *msg, size_t msg_len, size_t *pos);

extern const char	*tlv_iter_get_data(const struct tlv_iterator *tlv_iter);

extern uint16_t	tlv_iter_get_len(const struct tlv_iterator *tlv_iter);

extern enum tlv_opt_type	tlv_iter_get_type(const struct tlv_iterator *tlv_iter);

extern void	tlv_iter_init(const char *msg, size_t msg_len, struct tlv_iterator *tlv_iter);

extern int	tlv_iter_item_copy(const struct tlv_iterator *tlv_iter, char *new_msg,
    size_t new_msg_len,    size_t *pos);

extern int	tlv_iter_next(struct tlv_iterator *tlv_iter);

extern int	tlv_iter_pref_eq(const struct tlv_iterator *tlv_iter,
    const struct sockaddr_storage *sas);

extern int	tlv_mcast_grp_eq(const struct sockaddr_storage *sas, const char *mcast_grp,
    size_t mcast_grp_len);

extern const char	*tlv_opt_type_to_str(enum tlv_opt_type opt);

extern int	tlv_pref_eq(const struct sockaddr_storage *sas, uint16_t iana_af, uint8_t prefix,
    const char *addr);

#ifdef __cplusplus
}
#endif

#endif /* _TLV_H_ */
