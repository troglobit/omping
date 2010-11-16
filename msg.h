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

#ifndef _MSG_H_
#define _MSG_H_

#include <sys/types.h>

#include <sys/socket.h>
#include <sys/time.h>

#ifdef __cplusplus
extern "C" {
#endif

enum { MSG_DECODED_OPT_REQUEST_LEN = 16 };

enum msg_type {
	MSG_TYPE_INIT		= 'I',
	MSG_TYPE_RESPONSE	= 'S',
	MSG_TYPE_QUERY		= 'Q',
	MSG_TYPE_ANSWER		= 'A',
};

struct msg_decoded {
	struct timeval	 client_tstamp;
	struct timeval	 server_tstamp;
	enum msg_type	 msg_type;
	size_t		 client_id_len;
	size_t		 mcast_grp_len;
	size_t		 opt_request_len;
	size_t		 server_info_len;
	size_t		 ses_id_len;
	uint32_t	 seq_num;
	int		 client_tstamp_isset;
	int		 mcast_prefix_isset;
	int		 request_opt_server_info;
	int		 request_opt_server_tstamp;
	int		 seq_num_isset;
	int		 server_tstamp_isset;
	const char 	*client_id;
	const char	*mcast_grp;
	const char	*server_info;
	const char	*ses_id;
	uint8_t		 ttl;
	uint8_t		 version;
};

extern size_t	msg_answer_create(const char *orig_msg, size_t orig_msg_len, char *new_msg,
    size_t new_msg_len, uint8_t ttl, int server_tstamp);

extern void	msg_decode(const char *msg, size_t msg_len, struct msg_decoded *decoded);

extern size_t	msg_init_create(char *msg, size_t msg_len, int req_si,
    const struct sockaddr_storage *mcast_addr, const char *client_id, size_t client_id_len);

extern size_t	msg_query_create(char *msg, size_t msg_len,
    const struct sockaddr_storage *mcast_addr, uint32_t seq_num, int server_tstamp,
    const char *client_id, size_t client_id_len, const char *session_id, size_t session_id_len);

extern size_t	msg_response_create(char *msg, size_t msg_len,
    const struct msg_decoded *msg_decoded, int mcast_grp, int mcast_prefix,
    const struct sockaddr_storage *mcast_addr, const char *session_id, size_t session_id_len);

extern int	msg_update_server_tstamp(char *msg, size_t msg_len);

#ifdef __cplusplus
}
#endif

#endif /* _MSG_H_ */
