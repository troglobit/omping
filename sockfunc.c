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
#include <netdb.h>
#include <string.h>

#include "addrfunc.h"
#include "logging.h"
#include "sockfunc.h"

static int	sf_set_socket_common_options(int sock, const struct sockaddr *addr, int mcast,
    uint8_t ttl, int force_recvttl, int receive_timestamp, int sndbuf_size, int rcvbuf_size);

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
 * local_addr address on local_ifname NIC interface with ttl Time-To-Live. allow_mcast_loop
 * is boolean flag to set mcast_loop. transport_method is transport method to use. remote_addrs are
 * list of remote addresses of ai_list type. This is used for SSM to join into appropriate source
 * groups. If receive_timestamp is set, recvmsg cmsg will (if supported) contain timestamp of
 * packet receive. force_recv_ttl is used to force set of recvttl (if option is not supported,
 * error is returned). sndbuf_size is size of socket buffer to allocate for sending packets.
 * rcvbuf_size is size of socket buffer to allocate for receiving packets.
 * Return -1 on failure, otherwise socket file descriptor is returned.
 */
int
sf_create_multicast_socket(const struct sockaddr *mcast_addr, const struct sockaddr *local_addr,
    const char *local_ifname, uint8_t ttl, int allow_mcast_loop,
    enum sf_transport_method transport_method, const struct ai_list *remote_addrs,
    int receive_timestamp, int force_recvttl, int sndbuf_size, int rcvbuf_size)
{
	int sock;

	sock = sf_create_udp_socket(mcast_addr);
	if (sock == -1) {
		return (-1);
	}

	if (sf_set_socket_common_options(sock, mcast_addr, 1, ttl, force_recvttl,
	    receive_timestamp, sndbuf_size, rcvbuf_size) == -1) {
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

	switch (transport_method) {
	case SF_TM_ASM:
		if (sf_mcast_join_asm_group(mcast_addr, local_addr, local_ifname, sock) == -1) {
			return (-1);
		}
		break;
	case SF_TM_SSM:
		if (sf_mcast_join_ssm_group_list(mcast_addr, local_addr, remote_addrs,
		    local_ifname, sock) == -1) {
			return (-1);
		}
		break;
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
 * allow_mcast_loop is boolean flag to set mcast_loop. local_ifname is name of local interface
 * where local_addr is present. transport_method is transport method to use. If receive_timestamp is
 * set, recvmsg cmsg will (if supported) contain timestamp of packet receive. force_recv_ttl is
 * used to force set of recvttl (if option is not supported, error is returned). sndbuf_size is
 * size of socket buffer to allocate for sending packets. rcvbuf_size is size of socket buffer
 * to allocate for receiving packets.
 * Return -1 on failure, otherwise socket file descriptor is returned.
 */
int
sf_create_unicast_socket(const struct sockaddr *local_addr, uint8_t ttl, int mcast_send,
    int allow_mcast_loop, const char *local_ifname, enum sf_transport_method transport_method,
    int receive_timestamp, int force_recvttl, int sndbuf_size, int rcvbuf_size)
{
	int sock;

	sock = sf_create_udp_socket(local_addr);
	if (sock == -1) {
		return (-1);
	}

	if (sf_set_socket_common_options(sock, local_addr, 0, ttl, force_recvttl,
	    receive_timestamp, sndbuf_size, rcvbuf_size) == -1) {
		return (-1);
	}

	if (mcast_send) {
		if (sf_set_socket_ttl(local_addr, 1, sock, ttl) == -1) {
			return (-1);
		}

		if (sf_set_socket_mcast_loop(local_addr, sock, allow_mcast_loop) == -1) {
			return (-1);
		}

		if (sf_set_socket_mcast_if(local_addr, sock, local_ifname) == -1) {
			return (-1);
		}
	}

	if (sf_bind_socket(local_addr, sock) == -1) {
		return (-1);
	}

	return (sock);
}

int
sf_is_ssm_supported(void)
{
#if defined (IP_ADD_SOURCE_MEMBERSHIP) || defined (MCAST_JOIN_SOURCE_GROUP)
	return (1);
#else
	return (0);
#endif
}

/*
 * Join socket to multicast group (ASM). mcast_addr is multicast address, local_address is address
 * of local interface to join on, local_ifname is name of interface with local_address address and
 * sock is socket to use.
 * Function returns 0 on success, otherwise -1.
 */
int
sf_mcast_join_asm_group(const struct sockaddr *mcast_addr, const struct sockaddr *local_addr,
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
 * Join socket to multicast group (SSM). mcast_addr is multicast address, local_address is address
 * of local interface to join on, remote_addr is used for source of multicast, local_ifname
 * is name of interface with local_address address and sock is socket to use.
 * Function returns 0 on success, otherwise -1.
 */
int
sf_mcast_join_ssm_group(const struct sockaddr *mcast_addr, const struct sockaddr *local_addr,
    const struct sockaddr *remote_addr, const char *local_ifname, int sock)
{
#ifdef IP_ADD_SOURCE_MEMBERSHIP
	struct ip_mreq_source mreq4;
#endif
#ifdef MCAST_JOIN_SOURCE_GROUP
	struct group_source_req greq;
	size_t addr_len;
	int iface_index;
	int ip_lv;
#endif

#ifdef IP_ADD_SOURCE_MEMBERSHIP
	if (mcast_addr->sa_family == AF_INET) {
		memset(&mreq4, 0, sizeof(mreq4));

		mreq4.imr_multiaddr = ((struct sockaddr_in *)mcast_addr)->sin_addr;
		mreq4.imr_interface = ((struct sockaddr_in *)local_addr)->sin_addr;
		mreq4.imr_sourceaddr = ((struct sockaddr_in *)remote_addr)->sin_addr;

		if (setsockopt(sock, IPPROTO_IP, IP_ADD_SOURCE_MEMBERSHIP, &mreq4,
		    sizeof(mreq4)) == -1) {
			DEBUG_PRINTF("setsockopt IP_ADD_SOURCE_MEMBERSHIP failed");

			return (-1);
		}

		return (0);
	}
#endif

#ifdef MCAST_JOIN_SOURCE_GROUP
	if (mcast_addr->sa_family == AF_INET || mcast_addr->sa_family == AF_INET6) {
		iface_index = if_nametoindex(local_ifname);
		if (iface_index == 0) {
			DEBUG_PRINTF("if_nametoindex cannot convert iface name %s to index",
			    local_ifname);

			return (-1);
		}

		memset(&greq, 0, sizeof(greq));

		switch (mcast_addr->sa_family) {
		case AF_INET:
			addr_len = sizeof(struct sockaddr_in);
			ip_lv = IPPROTO_IP;
			break;
		case AF_INET6:
			addr_len = sizeof(struct sockaddr_in6);
			ip_lv = IPPROTO_IPV6;
			break;
		default:
			DEBUG_PRINTF("Unknown sockaddr family");
			errx(1, "Unknown sockaddr family");
			/* NOTREACHED */
		}

		greq.gsr_interface = iface_index;
		memcpy(&greq.gsr_group, mcast_addr, addr_len);
		memcpy(&greq.gsr_source, remote_addr, addr_len);

		if (setsockopt(sock, ip_lv, MCAST_JOIN_SOURCE_GROUP, &greq, sizeof(greq)) == -1) {
			DEBUG_PRINTF("setsockopt MCAST_JOIN_SOURCE_GROUP failed");

			return (-1);
		}

		return (0);
	}
#endif
	DEBUG_PRINTF("Can't join to Source-Specific Multicast because of no compile time support");
	errx(1, "Can't join to Source-Specific Multicast because of no compile time support");
	/* NOTREACHED */

	return (-1);
}

/*
 * Join socket to multicast group (SSM). mcast_addr is multicast address, local_address is address
 * of local interface to join on, remote_addrs is used for source of multicast, local_ifname
 * is name of interface with local_address address and sock is socket to use.
 * Function returns 0 on success, otherwise -1.
 */
int
sf_mcast_join_ssm_group_list(const struct sockaddr *mcast_addr, const struct sockaddr *local_addr,
    const struct ai_list *remote_addrs, const char *local_ifname, int sock)
{
	struct ai_item *ai_item_i;

	TAILQ_FOREACH(ai_item_i, remote_addrs, entries) {
		if (sf_mcast_join_ssm_group(mcast_addr, local_addr,
		    (const struct sockaddr *)&ai_item_i->sas, local_ifname, sock) == -1) {
			return (-1);
		}
	}

	return (0);
}

/*
 * Set buffer size for socket sock. snd_buf is boolean which if set, send buffer is modified,
 * otherwise receive buffer is modified. buf_size is size of buffer to allocate. This can be <=0 and
 * then buffer is left unchanged. new_buf_size is real size provided by OS. new_buf_size also
 * accepts NULL as pointer, if information about new buffer size is not needed.
 */
int
sf_set_socket_buf_size(int sock, int snd_buf, int buf_size, int *new_buf_size)
{
	char *opt_name_s;
	socklen_t optlen;
	int opt_name;
	int res;

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

	if (new_buf_size == NULL) {
		return (0);
	}

	optlen = sizeof(*new_buf_size);
	res = getsockopt(sock, SOL_SOCKET, opt_name, new_buf_size, &optlen);

	if (res == -1) {
		DEBUG_PRINTF("getsockopt %s failed", opt_name_s);

		return (-1);
	}

	return (0);
}

/*
 * Set common options for socket. Options are ipv6only, ttl, recvttl and receive timestamp. sock is
 * socket to set options, addr is address, mcast should be true if socket is multicast otherwise
 * false, ttl is new Time-To-Live. force_recv_ttl is used to force set of recvttl (if option is
 * not supported, error is returned). If receive_timestamp is set, recvmsg cmsg will (if
 * supported) contain timestamp of packet receive. sndbuf_size is size of socket buffer to
 * allocate for sending packets. rcvbuf_size is size of socket buffer to allocate for receiving
 * packets.
 * Return -1 on failure, otherwise 0.
 */
static int
sf_set_socket_common_options(int sock, const struct sockaddr *addr, int mcast, uint8_t ttl,
    int force_recvttl, int receive_timestamp, int sndbuf_size, int rcvbuf_size)
{
	const char *cast_str;
	int new_buf_size;
	int res;

	cast_str = (!mcast ? "uni" : "multi");

	if (sf_set_socket_buf_size(sock, 1, sndbuf_size, &new_buf_size) == -1) {
		return (-1);
	}

	DEBUG_PRINTF("Send buffer (%scast socket) allocated %u bytes", cast_str, new_buf_size);
	if (new_buf_size < sndbuf_size) {
		VERBOSE_PRINTF("Send buffer (%scast socket) size option was %u bytes, but only %u"
		    " bytes was allocated", cast_str, sndbuf_size, new_buf_size);
	}

	if (sf_set_socket_buf_size(sock, 0, rcvbuf_size, &new_buf_size) == -1) {
		return (-1);
	}

	DEBUG_PRINTF("Receive buffer (%scast socket) allocated %u bytes", cast_str, new_buf_size);
	if (new_buf_size < rcvbuf_size) {
		VERBOSE_PRINTF("Receive buffer (%scast socket) size option was %u bytes, but only"
		    " %u bytes was allocated", cast_str, rcvbuf_size, new_buf_size);
	}

	if (addr->sa_family == AF_INET6) {
		if (sf_set_socket_ipv6only(addr, sock) == -1) {
			return (-1);
		}
	}

	if (sf_set_socket_ttl(addr, mcast, sock, ttl) == -1) {
		return (-1);
	}

	res = sf_set_socket_recvttl(addr, sock);
	if (res == -1 || (res == -2 && force_recvttl)) {
		return (-1);
	}

	if (receive_timestamp) {
		if (sf_set_socket_timestamp(sock) == -1) {
			return (-1);
		}
	}

	return (0);
}

/*
 * Set ipv6 only flag to socket. Function works only for socket with family AF_INET6.
 * Function returns 0 on success, otherwise -1.
 */
int
sf_set_socket_ipv6only(const struct sockaddr *sa, int sock)
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
 * Function returns 0 on success. -2 is returned on systems, where IP_RECVTTL is not available,
 * otherwise -1 is returned.
 */
int
sf_set_socket_recvttl(const struct sockaddr *sa, int sock)
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
 * Enable receiving of timestamp for socket.
 * Function returns 0 on success, otherwise -1.
 */
int
sf_set_socket_timestamp(int sock)
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
