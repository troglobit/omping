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

#include <arpa/inet.h>

#include <netinet/in.h>

#ifdef __sun
#include <alloca.h>
#endif /* __sun */

#include <err.h>
#define __STDC_FORMAT_MACROS
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "addrfunc.h"
#include "logging.h"
#include "omping.h"
#include "tlv.h"
#include "util.h"

static int	tlv_add_actual_ts(char *msg, size_t msg_len, size_t *pos, enum tlv_opt_type opt);

static int	tlv_add_sas(char *msg, size_t msg_len, size_t *pos, enum tlv_opt_type opt,
    const struct sockaddr_storage *sas, int store_prefix_len);

static int	tlv_add_ts(char *msg, size_t msg_len, size_t *pos, enum tlv_opt_type opt,
    struct timeval *tv);

static int	tlv_add_u8(char *msg, size_t msg_len, size_t *pos, enum tlv_opt_type opt,
    uint8_t val);

/*
 * Add option opt_type with length opt_len and value to message msg with msg_len length to position
 * pos. Position is automatically adjusted to new position, so subsequent calls of function add
 * new option to correct position. Function returns 0 on success, otherwise -1.
 */
int
tlv_add(char *msg, size_t msg_len, size_t *pos, enum tlv_opt_type opt_type, uint16_t opt_len,
    const void *value)
{
	uint16_t nlen;
	uint16_t nopt_type;

	DEBUG2_PRINTF("Add option %"PRIu16" with len %"PRIu16" pos %zu", opt_type, opt_len, *pos);

	if (*pos + sizeof(nopt_type) + sizeof(nlen) + opt_len > msg_len) {
		DEBUG2_PRINTF("Can't store option. msg_len too small.");
		return (-1);
	}

	nopt_type = ntohs((uint16_t)opt_type);
	memcpy(msg + *pos, &nopt_type, sizeof(nopt_type));
	*pos += sizeof(nopt_type);

	nlen = htons(opt_len);

	memcpy(msg + *pos, &nlen, sizeof(nlen));
	*pos += sizeof(nlen);

	memcpy(msg + *pos, value, opt_len);

	*pos += opt_len;

	return (0);
}

/*
 * Add TLV with actual time stamp
 */
static int
tlv_add_actual_ts(char *msg, size_t msg_len, size_t *pos, enum tlv_opt_type opt)
{
	struct timeval tv;

	tv = util_get_time();

	return (tlv_add_ts(msg, msg_len, pos, opt, &tv));
}

/*
 * Add TLV with actual client time stamp
 */
int
tlv_add_client_tstamp(char *msg, size_t msg_len, size_t *pos)
{
	return (tlv_add_actual_ts(msg, msg_len, pos, TLV_OPT_TYPE_CLIENT_TSTAMP));
}

/*
 * Add TLV with mcast group
 */
int
tlv_add_mcast_grp(char *msg, size_t msg_len, size_t *pos, const struct sockaddr_storage *sas)
{
	return (tlv_add_sas(msg, msg_len, pos, TLV_OPT_TYPE_MCAST_GRP, sas, 0));
}

/*
 * Add TLV with mcast prefix
 */
int
tlv_add_mcast_prefix(char *msg, size_t msg_len, size_t *pos, const struct sockaddr_storage *sas)
{
	return (tlv_add_sas(msg, msg_len, pos, TLV_OPT_TYPE_MCAST_PREFIX, sas, 1));
}

/*
 * Add TLV with option request option. Options are passed in opts array with opts_len length.
 */
int
tlv_add_opt_request(char *msg, size_t msg_len, size_t *pos, uint16_t *opts, size_t opts_len)
{
	char *value;
	size_t val_len;
	unsigned int i;
	uint16_t opt;

	if (opts_len == 0)
		return (-1);

	val_len = opts_len * sizeof(uint16_t);

	value = (char *)alloca(val_len);

	for (i = 0; i < opts_len; i++) {
		opt = htons(opts[i]);

		memcpy(value + i * sizeof(opt), &opt, sizeof(opt));
	}

	return (tlv_add(msg, msg_len, pos, TLV_OPT_TYPE_OPT_REQUEST, val_len, value));
}

/*
 * Add TLV with sockaddr_storage ip address. If store_prefix_len is set, prefix length of address
 * (always full prefix) is also stored.
 */
static int
tlv_add_sas(char *msg, size_t msg_len, size_t *pos, enum tlv_opt_type opt,
    const struct sockaddr_storage *sas, int store_prefix_len)
{
	char *value;
	void *addr_pointer;
	size_t addr_len;
	size_t opt_len;
	uint16_t af;
	uint8_t pref_len_val;

	switch (sas->ss_family) {
	case AF_INET:
		af = AF_IANA_IP;
		addr_len = sizeof(struct in_addr);
		addr_pointer = &((struct sockaddr_in *)sas)->sin_addr;
		break;
	case AF_INET6:
		af = AF_IANA_IP6;
		addr_len = sizeof(struct in6_addr);
		addr_pointer = &((struct sockaddr_in6 *)sas)->sin6_addr;
		break;
	default:
		DEBUG_PRINTF("Unknown sas family %d", sas->ss_family);
		errx(1, "Unknown sas family %d", sas->ss_family);
	}

	pref_len_val = addr_len * 8;

	opt_len = sizeof(af) + addr_len;

	if (store_prefix_len)
		opt_len += sizeof(pref_len_val);

	value = (char *)alloca(opt_len);

	af = htons(af);

	memcpy(value, &af, sizeof(af));
	if (store_prefix_len)
		memcpy(value + sizeof(af), &pref_len_val, sizeof(pref_len_val));

	memcpy(value + sizeof(af) + (store_prefix_len ? sizeof(pref_len_val) : 0), addr_pointer,
	    addr_len);

	return (tlv_add(msg, msg_len, pos, opt, opt_len, value));

}

/*
 * Add sequence number TLV.
 */
int
tlv_add_seq_num(char *msg, size_t msg_len, size_t *pos, uint32_t seq)
{
	uint32_t nseq;

	nseq = htonl(seq);
	return (tlv_add(msg, msg_len, pos, TLV_OPT_TYPE_SEQ_NUM, sizeof(nseq), &nseq));
}

/*
 * Add TLV with server info
 */
int
tlv_add_server_info(char *msg, size_t msg_len, size_t *pos, const char *server_info)
{
	if (strlen(server_info) == 0)
		return (-1);

	return (tlv_add(msg, msg_len, pos, TLV_OPT_TYPE_SERVER_INFO, strlen(server_info),
	    server_info));
}

/*
 * Add TLV with actual server timestamp
 */
int
tlv_add_server_tstamp(char *msg, size_t msg_len, size_t *pos)
{
	return (tlv_add_actual_ts(msg, msg_len, pos, TLV_OPT_TYPE_SERVER_TSTAMP));
}

/*
 * Add timestamp
 */
static int
tlv_add_ts(char *msg, size_t msg_len, size_t *pos, enum tlv_opt_type opt, struct timeval *tv)
{
	char value[8];
	uint32_t u32;

	u32 = tv->tv_sec;
	u32 = htonl(u32);
	memcpy(value, &u32, sizeof(u32));

	u32 = tv->tv_usec;
	u32 = htonl(u32);
	memcpy(value + sizeof(u32), &u32, sizeof(u32));

	return (tlv_add(msg, msg_len, pos, opt, sizeof(value), value));
}

/*
 * Add server's TTL TLV
 */
int
tlv_add_ttl(char *msg, size_t msg_len, size_t *pos, uint8_t ttl)
{
	return (tlv_add_u8(msg, msg_len, pos, TLV_OPT_TYPE_TTL, ttl));
}

/*
 * Add uint8_t type as option opt.
 */
static int
tlv_add_u8(char *msg, size_t msg_len, size_t *pos, enum tlv_opt_type opt, uint8_t val)
{
	return (tlv_add(msg, msg_len, pos, opt, sizeof(val), &val));
}

/*
 * Add TLV with protocol version.
 */
int
tlv_add_version(char *msg, size_t msg_len, size_t *pos)
{
	uint8_t ver;

	ver = PROTOCOL_VERSION;

	return (tlv_add_u8(msg, msg_len, pos, TLV_OPT_TYPE_VERSION, ver));
}

/*
 * Return pointer to tlv data
 */
const char *
tlv_iter_get_data(const struct tlv_iterator *tlv_iter)
{
	return (tlv_iter->msg + tlv_iter->pos + 2 * sizeof(uint16_t));
}

/*
 * Get length of item currently pointed by iterator
 */
uint16_t
tlv_iter_get_len(const struct tlv_iterator *tlv_iter)
{
	uint16_t len;

	memcpy(&len, tlv_iter->msg + tlv_iter->pos + sizeof(uint16_t), sizeof(len));
	len = ntohs(len);

	return (len);
}

/*
 * Get type of item currently pointed by iterator
 */
enum tlv_opt_type
tlv_iter_get_type(const struct tlv_iterator *tlv_iter)
{
	uint16_t res;

	memcpy(&res, tlv_iter->msg + tlv_iter->pos, sizeof(res));
	res = ntohs(res);

	return ((enum tlv_opt_type)res);
}

/*
 * Initialize iterator
 */
void
tlv_iter_init(const char *msg, size_t msg_len, struct tlv_iterator *tlv_iter)
{

	tlv_iter->msg = msg;
	tlv_iter->msg_len = msg_len;
	tlv_iter->pos = 0;
}

/*
 * Copy item from message pointed with iterator tlv_iter to new message new_msg with new_msg_len
 * length to position pos. Return 0 on success, and -1 on failure.
 */
int
tlv_iter_item_copy(const struct tlv_iterator *tlv_iter, char *new_msg, size_t new_msg_len,
    size_t *pos)
{
	size_t item_size;

	DEBUG2_PRINTF("Copy option %"PRIu16" with len %"PRIu16" pos %zu",
	    tlv_iter_get_type(tlv_iter), tlv_iter_get_len(tlv_iter), *pos);

	item_size = tlv_iter_get_len(tlv_iter) + 2 * sizeof(uint16_t);

	if (*pos + item_size > new_msg_len) {
		DEBUG2_PRINTF("Can't copy option. new_msg_len too small.");

		return (-1);
	}

	memcpy(new_msg + *pos, tlv_iter->msg + tlv_iter->pos, item_size);

	*pos += item_size;

	return (0);
}

/*
 * Move iterator to the next item. Returns 0 when move was successful, or -1 if end of the message
 * was reached.
 */
int
tlv_iter_next(struct tlv_iterator *tlv_iter)
{
	uint16_t nlen;

	if (tlv_iter->pos == 0) {
		tlv_iter->pos = 1;
		return (0);
	}

	nlen = tlv_iter_get_len(tlv_iter);

	if (tlv_iter->pos + sizeof(uint16_t) + sizeof(nlen) + nlen >= tlv_iter->msg_len) {
		return (-1);
	}

	tlv_iter->pos += sizeof(uint16_t) + sizeof(nlen) + nlen;

	return (0);
}

/*
 * Compare msg item pointed by iterator of MCAST_PREFIX type with sockaddr address
 */
int
tlv_iter_pref_eq(const struct tlv_iterator *tlv_iter, const struct sockaddr_storage *sas)
{
	uint16_t tlv_len;
	uint16_t u16;
	uint8_t pref_len;
	uint8_t min_len;

	if (tlv_iter_get_type(tlv_iter) != TLV_OPT_TYPE_MCAST_PREFIX) {
		return (0);
	}

	tlv_len = tlv_iter_get_len(tlv_iter);

	if (tlv_len <= 2) {
		return (0);
	}

	memcpy(&u16, tlv_iter_get_data(tlv_iter), sizeof(u16));
	u16 = ntohs(u16);

	if (u16 != AF_IANA_IP  && u16 != AF_IANA_IP6) {
		return (0);
	}

	memcpy(&pref_len, tlv_iter_get_data(tlv_iter) + 2, sizeof(pref_len));

	min_len = pref_len / 8;
	if (pref_len % 8 != 0)
		min_len++;

	if (tlv_len - 3 < min_len) {
		return (0);
	}

	return (tlv_pref_eq(sas, u16, pref_len, tlv_iter_get_data(tlv_iter) + 3));
}

/*
 * Compare sockaddr_storage address sas with mcast_grp received in message with length
 * mcast_grp_len. Return 0 if addresses mismatch, otherwise not 0.
 */
int
tlv_mcast_grp_eq(const struct sockaddr_storage *sas, const char *mcast_grp, size_t mcast_grp_len)
{
	uint16_t u16;

	memcpy(&u16, mcast_grp, sizeof(u16));
	u16 = ntohs(u16);

	if (!((u16 == AF_IANA_IP && mcast_grp_len == 6) ||
	    (u16 == AF_IANA_IP6 && mcast_grp_len == 18))) {
		return (0);
	}

	if (u16 == AF_IANA_IP && sas->ss_family != AF_INET) {
		return (0);
	}

	if (u16 == AF_IANA_IP6 && sas->ss_family != AF_INET6) {
		return (0);
	}

	return (tlv_pref_eq(sas, u16, (mcast_grp_len - 2) * 8, mcast_grp + 2));
}

/*
 * Return static string with opt name
 */
const char *
tlv_opt_type_to_str(enum tlv_opt_type opt)
{
	const char *res;

	switch (opt) {
	case TLV_OPT_TYPE_VERSION: res = "Version"; break;
	case TLV_OPT_TYPE_CLIENT_ID: res = "Client ID"; break;
	case TLV_OPT_TYPE_SEQ_NUM: res = "Sequence Number"; break;
	case TLV_OPT_TYPE_CLIENT_TSTAMP: res = "Client Timestamp"; break;
	case TLV_OPT_TYPE_MCAST_GRP: res = "Multicast Group"; break;
	case TLV_OPT_TYPE_OPT_REQUEST: res = "Option Request Option"; break;
	case TLV_OPT_TYPE_SERVER_INFO: res = "Server Information"; break;
	case TLV_OPT_TYPE_TTL: res = "TTL"; break;
	case TLV_OPT_TYPE_MCAST_PREFIX: res = "Multicast Prefix"; break;
	case TLV_OPT_TYPE_SES_ID: res = "Session ID"; break;
	case TLV_OPT_TYPE_SERVER_TSTAMP: res = "Server Timestamp"; break;
	default: res = "Unknown"; break;
	}

	return (res);
}

/*
 * Compare prefix address with sockaddr_storage address. iana_af is IANA address family, prefix is
 * prefix length and addr is pointer to bytes of prefixed address. Only needed number of bytes is
 * compared.
 */
int
tlv_pref_eq(const struct sockaddr_storage *sas, uint16_t iana_af, uint8_t prefix, const char *addr)
{
	char sas_addr[32];
	size_t sas_addr_len;
	uint16_t sas_iana_af;
	unsigned char cb1, cb2;
	uint8_t plen_max, plen_min;

	memset(sas_addr, 0, sizeof(sas_addr));

	switch (sas->ss_family) {
	case AF_INET:
		sas_iana_af = AF_IANA_IP;

		plen_min = 4;
		plen_max = 32;

		sas_addr_len = sizeof(struct in_addr);
		memcpy(sas_addr, &((struct sockaddr_in *)sas)->sin_addr, sas_addr_len);
		break;
	case AF_INET6:
		sas_iana_af = AF_IANA_IP6;

		plen_min = 8;
		plen_max = 128;

		sas_addr_len = sizeof(struct in6_addr);
		memcpy(sas_addr, &((struct sockaddr_in6 *)sas)->sin6_addr, sas_addr_len);
		break;
	default:
		DEBUG_PRINTF("Unknown ss family %d", sas->ss_family);
		errx(1, "Unknown ss family %d", sas->ss_family);
	}

	if (iana_af != sas_iana_af) {
		return (0);
	}

	if (prefix == 0) {
		/*
		 * Wildcard
		 */
		return (1);
	}

	if (prefix < plen_min || prefix > plen_max) {
		return (0);
	}

	/*
	 * Full bytes comparation
	 */
	if (memcmp(sas_addr, addr, prefix / 8) != 0) {
		return (0);
	}


	/*
	 * Rest bit comparation
	 */
	if (prefix % 8 != 0 && prefix / 8 < sizeof(sas_addr_len)) {
		cb1 = (unsigned char)(sas_addr[prefix / 8] & (0xff << (8 - (prefix % 8))));
		cb2 = (unsigned char)(addr[prefix / 8] & (0xff << (8 - (prefix % 8))));
		if (cb1 != cb2) {
			return (0);
		}
	}

	return (1);
}
