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

#ifndef _MSGSEND_H_
#define _MSGSEND_H_

#include <sys/types.h>

#include <sys/socket.h>

#include <net/if.h>
#include <netinet/in.h>
#include <arpa/inet.h>

enum ms_answer_type {
	MS_ANSWER_UCAST = 1,
	MS_ANSWER_MCAST = 2,
	MS_ANSWER_BOTH  = 3,
};

extern int	ms_answer(int ucast_socket, const struct sockaddr_storage *mcast_addr,
    const char *orig_msg, size_t orig_msg_len, const struct msg_decoded *decoded,
    const struct sockaddr_storage *to, uint8_t ttl, enum ms_answer_type answer_type);

extern int	ms_init(int ucast_socket, const struct sockaddr_storage *remote_addr,
    const struct sockaddr_storage *mcast_addr, const char *client_id, int req_si);

extern int	ms_query(int ucast_socket, const struct sockaddr_storage *remote_addr,
    const struct sockaddr_storage *mcast_addr, uint32_t seq_num, const char *client_id,
    const char *ses_id, size_t ses_id_len);

extern int	ms_response(int ucast_socket, const struct sockaddr_storage *mcast_addr,
    const struct msg_decoded *decoded, const struct sockaddr_storage *to, int mcast_grp,
    int mcast_prefix, const char *session_id, size_t session_id_len);

extern int	ms_stop(int ucast_socket, const struct sockaddr_storage *mcast_addr,
    const struct msg_decoded *decoded, const struct sockaddr_storage *to);

#ifdef __cplusplus
}
#endif

#endif /* _MSGSEND_H_ */
