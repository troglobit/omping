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

#include <sys/types.h>

#include <sys/socket.h>

#include <net/if.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include <err.h>
#include <netdb.h>
#include <string.h>

#include "addrfunc.h"
#include "logging.h"
#include "sockfunc.h"

/*
 * Bind socket sock to given address bind_addr.
 * Function returns 0 on success, otherwise -1.
 */
int
sf_bind_socket(const struct sockaddr *bind_addr, int sock)
{
	if (bind(sock, bind_addr, af_sa_len(bind_addr)) == -1) {
		DEBUG_PRINTF("Can't bind socket");

		return (-1);
	}

	return (0);
}

/*
 * Create and bind UDP multicast socket. Socket is created with mcast_addr address, joined to
 * local_addr address on local_ifname NIC interface with ttl Time-To-Live.
 * Return -1 on failure, otherwise socket file descriptor is returned.
 */
int
sf_create_multicast_socket(const struct sockaddr *mcast_addr, const struct sockaddr *local_addr,
    const char *local_ifname, uint8_t ttl)
{
	int sock;

	sock = sf_create_udp_socket(mcast_addr);
	if (sock == -1) {
		return (-1);
	}

	if (sf_set_socket_ttl(mcast_addr, 1, sock, ttl) == -1) {
		return (-1);
	}

	if (sf_set_socket_recvttl(mcast_addr, sock) == -1) {
		return (-1);
	}

	if (sf_set_socket_reuse(sock) == -1) {
		return (-1);
	}

	if (sf_bind_socket(mcast_addr, sock) == -1) {
		return (-1);
	}

	if (sf_set_socket_mcast_loop(mcast_addr, sock, 0) == -1) {
		return (-1);
	}

	if (sf_mcast_join_group(mcast_addr, local_addr, local_ifname, sock) == -1) {
		return (-1);
	}

	return (sock);
}

/*
 * Create UDP socket with family from sa.
 * Return -1 on failure, otherwise socket file descriptor is returned.
 */
int
sf_create_udp_socket(const struct sockaddr *sa)
{
	int sock;

	sock = socket(sa->sa_family, SOCK_DGRAM, 0);
	if (sock == -1) {
		DEBUG_PRINTF("Can't create socket");
		return (-1);
	}

	return (sock);
}

/*
 * Create and bind UDP unicast socket with ttl Time-To-Live. It can also set multicast ttl if
 * set_mcast_ttl not 0. If mcast_send is set, options for sending multicast packets are set.
 * local_ifname is name of local interface where local_addr is present.
 * Return -1 on failure, otherwise socket file descriptor is returned.
 */
int
sf_create_unicast_socket(const struct sockaddr *local_addr, uint8_t ttl, int mcast_send,
    const char *local_ifname)
{
	int sock;

	sock = sf_create_udp_socket(local_addr);
	if (sock == -1) {
		return (-1);
	}

	if (sf_set_socket_ttl(local_addr, 0, sock, ttl) == -1) {
		return (-1);
	}

	if (mcast_send) {
		if (sf_set_socket_ttl(local_addr, 1, sock, ttl) == -1) {
			return (-1);
		}

		if (sf_set_socket_mcast_loop(local_addr, sock, 0) == -1) {
			return (-1);
		}

		if (sf_set_socket_mcast_if(local_addr, sock, local_ifname) == -1) {
			return (-1);
		}
	}

	if (sf_set_socket_recvttl(local_addr, sock) == -1) {
		return (-1);
	}

	if (sf_set_socket_reuse(sock) == -1) {
		return (-1);
	}


	if (sf_bind_socket(local_addr, sock) == -1) {
		return (-1);
	}

	return (sock);
}

/*
 * Join socket to multicast group (ASM). mcast_addr is multicast address, local_address is address
 * of local interface to join on, local_ifname is name of interface with local_address address and
 * sock is socket to use.
 * Function returns 0 on success, otherwise -1.
 */
int
sf_mcast_join_group(const struct sockaddr *mcast_addr, const struct sockaddr *local_addr,
    const char *local_ifname, int sock)
{
	struct ip_mreq mreq4;
	struct ipv6_mreq mreq6;
	int iface_index;

	switch (mcast_addr->sa_family) {
	case AF_INET:
		memset(&mreq4, 0, sizeof(mreq4));

		mreq4.imr_multiaddr = ((struct sockaddr_in *)mcast_addr)->sin_addr;
		mreq4.imr_interface = ((struct sockaddr_in *)local_addr)->sin_addr;
		if (setsockopt(sock, IPPROTO_IP, IP_ADD_MEMBERSHIP, &mreq4, sizeof(mreq4)) == -1) {
			DEBUG_PRINTF("setsockopt IP_ADD_MEMBERSHIP failed");

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
		memset(&mreq6, 0, sizeof(mreq6));

		mreq6.ipv6mr_multiaddr = ((struct sockaddr_in6 *)mcast_addr)->sin6_addr;
		mreq6.ipv6mr_interface = iface_index;
		if (setsockopt(sock, IPPROTO_IPV6, IPV6_JOIN_GROUP, &mreq6, sizeof(mreq6)) == -1) {
			DEBUG_PRINTF("setsockopt IPV6_JOIN_GROUP failed");

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
 * Set interface to use for sending multicast packets. local_addr is interface from which packets
 * will be send. sock is socket to set option and local_ifname is name of interface with local_addr
 * address.
 * Function returns 0 on success, otherwise -1.
 */
int
sf_set_socket_mcast_if(const struct sockaddr *local_addr, int sock, const char *local_ifname)
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
sf_set_socket_mcast_loop(const struct sockaddr *mcast_addr, int sock, int enable)
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
 * Function returns 0 on success, otherwise -1.
 */
int
sf_set_socket_recvttl(const struct sockaddr *sa, int sock)
{
	int opt;

	opt = 1;

	switch (sa->sa_family) {
	case AF_INET:
		if (setsockopt(sock, IPPROTO_IP, IP_RECVTTL, &opt, sizeof(opt)) == -1) {
			DEBUG_PRINTF("setsockopt IP_RECVTTL failed");

			return (-1);
		}
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
sf_set_socket_reuse(int sock)
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
 * Set TTL (time-to-live) to socket. sa is sockaddr used to determine address family, mcast is
 * boolean variable used to determine if socket is multicast (>1) or not (0) and ttl is actual TTL
 * to set.
 * Function returns 0 on success, otherwise -1.
 */
int
sf_set_socket_ttl(const struct sockaddr *sa, int mcast, int sock, uint8_t ttl)
{
	int ittl;
	int res;

	ittl = ttl;

	switch (sa->sa_family) {
	case AF_INET:
		if (mcast) {
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
		if (mcast) {
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
