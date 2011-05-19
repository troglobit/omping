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
#include <sys/uio.h>

#include <net/if.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include <err.h>
#include <errno.h>
#include <netdb.h>
#include <poll.h>
#include <string.h>

#include "addrfunc.h"
#include "logging.h"
#include "rsfunc.h"
#include "util.h"

/*
 * Wrapper on top of poll. This poll stores old timestamp so it's possible to put always same
 * timeout but correct timeout is computed from old_tstamp and current time. In other words, this
 * function will always after timeout expire return timeout (0) not depending on number of times
 * this function was called.
 * unicast_socket and multicast_socket are two sockets, timeout is absolute timeout (after this
 * value, function returns 0) and old_tstamp is internal state variable (on first call value
 * must be zeroed).
 * Function return bit field (unicast_socket - bit 1, multicast_socket - bit 2) if something was
 * read, 0 on timeout, -1 on fail (use errno) and -2 on interrupt.
 */
int
rs_poll_timeout(int unicast_socket, int multicast_socket, int timeout, struct timeval *old_tstamp)
{
	struct pollfd pfds[2];
	struct timeval cur_time;
	int poll_timeout;
	int poll_res;
	int res;

	cur_time = util_get_time();

	if (old_tstamp->tv_sec == 0 && old_tstamp->tv_usec == 0) {
		*old_tstamp = cur_time;
	}

	if ((int)util_time_absdiff(cur_time, *old_tstamp) > timeout) {
		memset(old_tstamp, 0, sizeof(*old_tstamp));

		return (0);
	}

	poll_timeout = timeout - util_time_absdiff(cur_time, *old_tstamp);
	if (poll_timeout < 0) {
		poll_timeout = 0;
	}

	memset(pfds, 0, sizeof(struct pollfd) * 2);

	pfds[0].fd = unicast_socket;
	pfds[0].events = POLLIN;

	pfds[1].fd = multicast_socket;
	pfds[1].events = POLLIN;

	poll_res = poll(pfds, 2, poll_timeout);

	if (poll_res == 0) {
		memset(old_tstamp, 0, sizeof(*old_tstamp));

		return (0);
	}

	if (poll_res == -1) {
		if (errno == EINTR) {
			DEBUG2_PRINTF("poll error - EINTR");
			return (-2);
		} else {
			DEBUG2_PRINTF("poll error - errno = %d", errno);
			return (-1);
		}
	}

	if (pfds[0].revents & POLLERR || pfds[0].revents & POLLHUP || pfds[0].revents & POLLNVAL) {
		DEBUG2_PRINTF("poll error. pfds[0] revents = %d", pfds[0].revents);
		return (-1);
	}

	if (pfds[1].revents & POLLERR || pfds[1].revents & POLLHUP || pfds[1].revents & POLLNVAL) {
		DEBUG2_PRINTF("poll error. pfds[1] revents = %d", pfds[1].revents);
		return (-1);
	}

	res = 0;
	if (pfds[0].revents & POLLIN) {
		res |= 1;
	}

	if (pfds[1].revents & POLLIN) {
		res |= 2;
	}

	return (res);
}

/*
 * Wrapper on top of recvmsg which emulates recvfrom but it's also able to return ttl. sock is
 * socket where to make recvmsg. from_addr is address where address of source will be stored. msg is
 * buffer where to store message with maximum msg_len size. ttl is pointer where TTL (time-to-live)
 * from packet will be stored (or 0 if no such information is available). Timestamp is filled
 * either by SCM_TIMESTAMP directly from packet (if supported) or current get gettimeofday.
 * NULL can be passed as timestamp pointer.
 * Return number of received bytes, or -2 on EINTR, -3 on one of EHOSTUNREACH | ENETDOWN |
 * EHOSTDOWN | ECONNRESET, -4 if message is truncated, or -1 on different error.
 */
ssize_t
rs_receive_msg(int sock, struct sockaddr_storage *from_addr, char *msg, size_t msg_len,
    uint8_t *ttl, struct timeval *timestamp)
{
	char cmsg_buf[CMSG_SPACE(1024)];
	struct cmsghdr *cmsg;
	struct iovec msg_iovec;
	struct msghdr msg_hdr;
	ssize_t recv_size;
	int ittl;
	int timestamp_set;

	ittl = 0;
	timestamp_set = 0;

	memset(&msg_iovec, 0, sizeof(msg_iovec));
	msg_iovec.iov_base = msg;
	msg_iovec.iov_len = msg_len;

	memset(&msg_hdr, 0, sizeof(msg_hdr));
	msg_hdr.msg_name = from_addr;
	msg_hdr.msg_namelen = sizeof(struct sockaddr_storage);
	msg_hdr.msg_iov = &msg_iovec;
	msg_hdr.msg_iovlen = 1;
	msg_hdr.msg_control = cmsg_buf;
	msg_hdr.msg_controllen = sizeof(cmsg_buf);

	recv_size = recvmsg(sock, &msg_hdr, 0);

	if (recv_size == -1) {
		if (errno == EINTR) {
			DEBUG2_PRINTF("recvmsg error - EINTR");
			return (-2);
		}

		if (errno == EHOSTUNREACH || errno == EHOSTDOWN || errno == ENETDOWN ||
		    errno == ECONNRESET) {
			DEBUG2_PRINTF("recvmsg error - EHOSTUNREACH || EHOSTDOWN || ENETDOWN ||"
			    " ECONNRESET");
			return (-3);
		}

		DEBUG2_PRINTF("recvmsg error - errno = %d", errno);
		return (-1);
	}

	if (msg_hdr.msg_flags & MSG_TRUNC || msg_hdr.msg_flags & MSG_CTRUNC) {
		DEBUG2_PRINTF("recvmsg error - MSG_TRUNC | MSG_CTRUNC");
		return (-4);
	}

	for (cmsg = CMSG_FIRSTHDR(&msg_hdr); cmsg != NULL; cmsg = CMSG_NXTHDR(&msg_hdr, cmsg)) {
		switch (cmsg->cmsg_level) {
		case SOL_SOCKET:
#ifdef SCM_TIMESTAMP
			if (cmsg->cmsg_type == SCM_TIMESTAMP &&
			    cmsg->cmsg_len >= sizeof(struct timeval) && timestamp != NULL) {
				memcpy(timestamp, CMSG_DATA(cmsg), sizeof(struct timeval));
				timestamp_set = 1;
			}
#endif
		case IPPROTO_IP:
			if (cmsg->cmsg_type == IP_TTL && cmsg->cmsg_len == CMSG_LEN(sizeof(int))) {
				memcpy(&ittl, CMSG_DATA(cmsg), sizeof(ittl));
			}
#ifdef IP_RECVTTL
			if (cmsg->cmsg_type == IP_RECVTTL && cmsg->cmsg_len > 1) {
				ittl = *(uint8_t *)CMSG_DATA(cmsg);
			}
#endif
			break;
		case IPPROTO_IPV6:
			if (cmsg->cmsg_type == IPV6_HOPLIMIT && cmsg->cmsg_len ==
			    CMSG_LEN(sizeof(int))) {
				memcpy(&ittl, CMSG_DATA(cmsg), sizeof(ittl));
			}
			break;
		}
	}

	*ttl = (uint8_t)ittl;

	if (!timestamp_set && timestamp != NULL) {
		*timestamp = util_get_time();
	}

	return (recv_size);
}

/*
 * Thin wrapper on top of sendto. sock is socket, msg is message with msg_size length to send and to
 * is address where to send message.
 * Return number of sent bytes or -2 on EINTR, -3 on one of EHOSTDOWN | ENETDOWN | EHOSTUNREACH |
 * ENOBUFS or -1 on some different error (sent != msg_size).
 */
ssize_t
rs_sendto(int sock, const char *msg, size_t msg_size, const struct sockaddr_storage *to)
{
	ssize_t sent;

	sent = sendto(sock, msg, msg_size, 0, (struct sockaddr *)to, af_sas_len(to));

	if (sent == -1) {
		if (errno == EINTR) {
			DEBUG2_PRINTF("sendto error - EINTR");
			return (-2);
		}

		if (errno == EHOSTUNREACH || errno == EHOSTDOWN || errno == ENETDOWN ||
		    errno == ENOBUFS) {
			DEBUG2_PRINTF("sendto error - EHOSTUNREACH || EHOSTDOWN || ENETDOWN ||"
			    "ENOBUFS");
			return (-3);
		}

		DEBUG2_PRINTF("sendto error - errno = %d", errno);
		return (-1);
	}

	if ((size_t)sent != msg_size) {
		DEBUG2_PRINTF("sendto error - sent != msg_size");

		return (-1);
	}

	return (sent);
}
