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

#ifdef __cplusplus
extern "C" {
#endif

#define PROGRAM_NAME		"omping"
#define PROGRAM_VERSION		"0.0.4"
#define PROGRAM_SERVER_INFO	PROGRAM_NAME" "PROGRAM_VERSION

#define DEFAULT_PORT_S		"4321"
#define DEFAULT_MCAST4_ADDR	"232.43.211.234"
#define DEFAULT_MCAST6_ADDR	"ff3e::4321:1234"

#define DEFAULT_WAIT_TIME	1000
#define DEFAULT_TTL		64

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

enum omping_op_mode {
	OMPING_OP_MODE_NORMAL,
	OMPING_OP_MODE_CLIENT,
	OMPING_OP_MODE_SERVER,
	OMPING_OP_MODE_SHOW_VERSION,
};

#ifdef __cplusplus
}
#endif

#endif /* _OMPING_H_ */
