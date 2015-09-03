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

#ifndef _OMPING_H_
#define _OMPING_H_

#include "aiifunc.h"
#include "rhfunc.h"
#include "sockfunc.h"

#ifdef __cplusplus
extern "C" {
#endif

#define PROGRAM_NAME		"omping"
#define PROGRAM_VERSION		"0.0.5"
#define PROGRAM_SERVER_INFO	PROGRAM_NAME" "PROGRAM_VERSION

#define DEFAULT_PORT_S		"4321"
#define DEFAULT_MCAST4_ADDR	"232.43.211.234"
#define DEFAULT_MCAST6_ADDR	"ff3e::4321:1234"

#define DEFAULT_WAIT_TIME	1000
#define DEFAULT_TTL		64

/*
 * Mark a function variable as unused, useful for generic callbacks
 */
#ifndef UNUSED
#define UNUSED(x) UNUSED_ ## x __attribute__ ((unused))
#endif

/*
 * Default Wait For Finish multiply constant. wait_time is multiplied with following
 * value.
 */
#define DEFAULT_WFF_TIME_MUL	3

/*
 * Minimum number of elements in duplicate buffer
 */
#define MIN_DUP_BUF_ITEMS	1024
/*
 * Default seconds which must be stored in duplicate buffer.
 * This value is divided by ping interval in seconds. If value is smaller
 * then MIN_DUP_BUF_ITEMS, then MIN_DUP_BUF_ITEMS is used.
 */
#define DUP_BUF_SECS		(2 * 60)

/*
 * Default burst value for rate limit GCRA
 */
#define GCRA_BURST		5

/*
 * Minimum send and receive socket buffer size
 */
#define MIN_SNDBUF_SIZE		2048
#define MIN_RCVBUF_SIZE		2048

/*
 * Protocol version used in messages
 */
#define PROTOCOL_VERSION	2

#define MAX_MSG_SIZE		65535

/*
 * Operational mode of omping
 */
enum omping_op_mode {
	OMPING_OP_MODE_NORMAL,
	OMPING_OP_MODE_CLIENT,
	OMPING_OP_MODE_SERVER,
	OMPING_OP_MODE_SHOW_VERSION,
};

/*
 * Structure with internal omping data. Should be filled by cli_parse and no longer modified outside
 * omping_ functions.
 */
struct omping_instance {
	struct ai_item	local_addr;
	struct ai_item	mcast_addr;
	struct rh_list	remote_hosts;
	struct aii_list	remote_addrs;
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

#ifdef __cplusplus
}
#endif

#endif /* _OMPING_H_ */
