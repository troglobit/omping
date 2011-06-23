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

#include <err.h>
#include <errno.h>
#include <netdb.h>
#include <string.h>

#include "logging.h"
#include "sfset.h"

/*
 * Set buffer size for socket sock. snd_buf is boolean which if set, send buffer is modified,
 * otherwise receive buffer is modified. buf_size is size of buffer to allocate. This can be <=0 and
 * then buffer is left unchanged. new_buf_size is real size provided by OS. new_buf_size also
 * accepts NULL as pointer, if information about new buffer size is not needed. if force_buf_size is
 * set and OS will not provide enough buffer, error code is returned and errno is set to ENOBUFS
 * (this is emulation of *BSD behavior).
 * On success 0 is returned, otherwise -1.
 */
int
sfset_buf_size(int sock, int snd_buf, int buf_size, int *new_buf_size, int force_buf_size)
{
	const char *opt_name_s;
	socklen_t optlen;
	int opt_name;
	int res;
	int tmp_buf_size;

	if (snd_buf) {
		opt_name = SO_SNDBUF;
		opt_name_s = "SO_SNDBUF";
	} else {
		opt_name = SO_RCVBUF;
		opt_name_s = "SO_RCVBUF";
	}

	if (buf_size > 0) {
		res = setsockopt(sock, SOL_SOCKET, opt_name, &buf_size, sizeof(buf_size));

		if (res == -1) {
			DEBUG_PRINTF("setsockopt %s failed", opt_name_s);

			return (-1);
		}
	}

	if (new_buf_size == NULL && !force_buf_size) {
		return (0);
	}

	optlen = sizeof(tmp_buf_size);
	res = getsockopt(sock, SOL_SOCKET, opt_name, &tmp_buf_size, &optlen);

	if (res == -1) {
		DEBUG_PRINTF("getsockopt %s failed", opt_name_s);

		return (-1);
	}

	if (force_buf_size && tmp_buf_size < buf_size) {
		VERBOSE_PRINTF("Buffer size request was %u bytes, but only %u"
		    " bytes was allocated", buf_size, tmp_buf_size);
		errno = ENOBUFS;
		return (-1);
	}

	if (new_buf_size != NULL) {
		*new_buf_size = tmp_buf_size;
	}

	return (0);
}

/*
 * Enable or disable broadcast sending
 * Function returns 0 on success, otherwise -1.
 */
int
sfset_broadcast(int sock, int enable)
{
	int opt;

	opt = (enable ? 1 : 0);

	if (setsockopt(sock, SOL_SOCKET, SO_BROADCAST, &opt, sizeof(opt)) == -1) {
		DEBUG_PRINTF("setsockopt SO_BROADCAST failed");

		return (-1);
	}

	return (0);
}

/*
 * Set ipv6 only flag to socket. Function works only for socket with family AF_INET6.
 * Function returns 0 on success, otherwise -1.
 */
int
sfset_ipv6only(const struct sockaddr *sa, int sock)
{
	int opt;

	opt = 1;

	if (sa->sa_family != AF_INET6) {
		return (-1);
	}

#ifdef IPV6_V6ONLY
	if (setsockopt(sock, IPPROTO_IPV6, IPV6_V6ONLY, &opt, sizeof(opt)) == -1) {
		DEBUG_PRINTF("setsockopt IPV6_V6ONLY failed");

		return (-1);
	}
#endif

	return (0);
}

/*
 * Set interface to use for sending multicast packets. local_addr is interface from which packets
 * will be send. sock is socket to set option and local_ifname is name of interface with local_addr
 * address.
 * Function returns 0 on success, otherwise -1.
 */
int
sfset_mcast_if(const struct sockaddr *local_addr, int sock, const char *local_ifname)
{
	int iface_index;

	switch (local_addr->sa_family) {
	case AF_INET:
		if (setsockopt(sock, IPPROTO_IP, IP_MULTICAST_IF,
		    &((struct sockaddr_in *)local_addr)->sin_addr, sizeof(struct in_addr)) == -1) {
			DEBUG_PRINTF("setsockopt IP_MULTICAST_IF failed");

			return (-1);
		}
		break;
	case AF_INET6:
		iface_index = if_nametoindex(local_ifname);
		if (iface_index == 0) {
			DEBUG_PRINTF("if_nametoindex cannot convert iface name %s to index",
			    local_ifname);

			return (-1);
		}

		if (setsockopt(sock, IPPROTO_IPV6, IPV6_MULTICAST_IF, &iface_index,
		    sizeof(iface_index)) == -1) {
			DEBUG_PRINTF("setsockopt IPV6_MULTICAST_IF failed");

			return (-1);
		}
		break;

	default:
		DEBUG_PRINTF("Unknown sockaddr family");
		errx(1, "Unknown sockaddr family");
	}

	return (0);
}

/*
 * Enables or disables multicast loop on socket. mcast_addr is sockadddr used for address family.
 * sock is socket to set and enable should be set to 0 for disable of multicast loop, other values
 * means enable.
 * Function returns 0 on success, otherwise -1.
 */
int
sfset_mcast_loop(const struct sockaddr *mcast_addr, int sock, int enable)
{
	uint8_t val;
	int ival;

	val = (enable ? 1 : 0);
	ival = val;

	switch (mcast_addr->sa_family) {
	case AF_INET:
		if (setsockopt(sock, IPPROTO_IP, IP_MULTICAST_LOOP, &val, sizeof(val)) == -1) {
			DEBUG_PRINTF("setsockopt IP_MULTICAST_LOOP failed");

			return (-1);
		}
		break;
	case AF_INET6:
		if (setsockopt(sock, IPPROTO_IPV6, IPV6_MULTICAST_LOOP, &ival,
		    sizeof(ival)) == -1) {
			DEBUG_PRINTF("setsockopt IPV6_MULTICAST_LOOP failed");

			return (-1);
		}
		break;
	default:
		DEBUG_PRINTF("Unknown sockaddr family");
		errx(1, "Unknown sockaddr family");
	}

	return (0);
}

/*
 * Set option to receive TTL inside packet information (recvmsg). sa is sockaddr used for address
 * family and sock is socket to use.
 * Function returns 0 on success. -2 is returned on systems, where IP_RECVTTL is not available,
 * otherwise -1 is returned.
 */
int
sfset_recvttl(const struct sockaddr *sa, int sock)
{
	int opt;

	opt = 1;

	switch (sa->sa_family) {
	case AF_INET:
#ifdef IP_RECVTTL
		if (setsockopt(sock, IPPROTO_IP, IP_RECVTTL, &opt, sizeof(opt)) == -1) {
			DEBUG_PRINTF("setsockopt IP_RECVTTL failed");

			return (-1);
		}
#else
		return (-2);
#endif
		break;
	case AF_INET6:
#ifdef IPV6_RECVHOPLIMIT
		if (setsockopt(sock, IPPROTO_IPV6, IPV6_RECVHOPLIMIT, &opt, sizeof(opt)) == -1) {
			DEBUG_PRINTF("setsockopt IPV6_RECVHOPLIMIT failed");

			return (-1);
		}
#else
		if (setsockopt(sock, IPPROTO_IPV6, IPV6_HOPLIMIT, &opt, sizeof(opt)) == -1) {
			DEBUG_PRINTF("setsockopt IPV6_HOPLIMIT failed");

			return (-1);
		}
#endif
		break;
	default:
		DEBUG_PRINTF("Unknown sockaddr family");
		errx(1, "Unknown sockaddr family");
	}


	return (0);
}

/*
 * Set reuse of address on socket sock.
 * Function returns 0 on success, otherwise -1.
 */
int
sfset_reuse(int sock)
{
	int opt;

	opt = 1;

	if (setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt)) == -1) {
		DEBUG_PRINTF("setsockopt SO_REUSEADDR failed");

		return (-1);
	}

#ifdef SO_REUSEPORT
	if (setsockopt(sock, SOL_SOCKET, SO_REUSEPORT, &opt, sizeof(opt)) == -1) {
		DEBUG_PRINTF("setsockopt SO_REUSEPORT failed");

		return (-1);
	}
#endif

	return (0);
}

/*
 * Enable receiving of timestamp for socket.
 * Function returns 0 on success, otherwise -1.
 */
int
sfset_timestamp(int sock)
{
#ifdef SO_TIMESTAMP
	int opt;

	opt = 1;

	if (setsockopt(sock, SOL_SOCKET, SO_TIMESTAMP, &opt, sizeof(opt)) == -1) {
		DEBUG_PRINTF("setsockopt SO_TIMESTAMP failed");

		return (-1);
	}
#endif

	return (0);
}

/*
 * Set TTL (time-to-live) to socket. sa is sockaddr used to determine address family, cast_type is
 * variable used to determine if socket is unicast, multicast or broadcast and ttl is actual
 * TTL to set.
 * Function returns 0 on success, otherwise -1.
 */
int
sfset_ttl(const struct sockaddr *sa, enum sf_cast_type cast_type, int sock, uint8_t ttl)
{
	int ittl;
	int res;

	ittl = ttl;

	switch (sa->sa_family) {
	case AF_INET:
		if (cast_type == SF_CT_MULTI) {
			res = setsockopt(sock, IPPROTO_IP, IP_MULTICAST_TTL, &ttl, sizeof(ttl));
			if (res == -1) {
				DEBUG_PRINTF("setsockopt IP_MULTICAST_TTL failed");
				return (-1);
			}
		} else {
			res = setsockopt(sock, IPPROTO_IP, IP_TTL, &ittl, sizeof(ittl));
			if (res == -1) {
				DEBUG_PRINTF("setsockopt IP_TTL failed");
				return (-1);
			}
		}
		break;
	case AF_INET6:
		if (cast_type == SF_CT_MULTI) {
			res = setsockopt(sock, IPPROTO_IPV6, IPV6_MULTICAST_HOPS, &ittl,
			    sizeof(ittl));

			if (res == -1) {
				DEBUG_PRINTF("setsockopt IPV6_MULTICAST_HOPS failed");

				return (-1);
			}
		} else {
			res = setsockopt(sock, IPPROTO_IPV6, IPV6_UNICAST_HOPS, &ittl,
			    sizeof(ittl));

			if (res == -1) {
				DEBUG_PRINTF("setsockopt IPV6_UNICAST_HOPS failed");

				return (-1);
			}
		}
		break;
	default:
		DEBUG_PRINTF("Unknown sockaddr family");
		errx(1, "Unknown sockaddr family");
	}

	return (0);
}
