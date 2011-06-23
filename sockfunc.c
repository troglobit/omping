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

#include "addrfunc.h"
#include "logging.h"
#include "sockfunc.h"

static int	sf_set_socket_common_options(int sock, const struct sockaddr *addr,
    enum sf_cast_type cast_type, uint8_t ttl, int force_recvttl, int receive_timestamp,
    int sndbuf_size, int rcvbuf_size, int force_buf_size);

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
 * Return cast_type converted to string (uni/multi/broad).
 */
const char *
sf_cast_type_to_str(enum sf_cast_type cast_type)
{
	const char *res;

	switch (cast_type) {
	case SF_CT_UNI:
		res = "uni";
		break;
	case SF_CT_MULTI:
		res = "multi";
		break;
	case SF_CT_BROAD:
		res = "broad";
		break;
	default:
		DEBUG_PRINTF("Internal error - unknown transport method");
		errx(1, "Internal error - unknown transport method");
		/* NOTREACHED */
	}

	return (res);
}

/*
 * Create and bind UDP multicast/broadcast socket.
 * Socket is created with mcast_addr address, joined to local_addr address on local_ifname NIC
 * interface with ttl Time-To-Live.
 * allow_mcast_loop is boolean flag to set mcast_loop.
 * transport_method is transport method to use.
 * remote_addrs are list of remote addresses of aii_list type. This is used for SSM to join into
 * appropriate source groups. If receive_timestamp is set, recvmsg cmsg will (if supported)
 * contain timestamp of packet receive.
 * force_recv_ttl is used to force set of recvttl (if option is not supported,
 * error is returned). sndbuf_size is size of socket buffer to allocate for sending packets.
 * rcvbuf_size is size of socket buffer to allocate for receiving packets.
 * bind_port is port to bind. It can be 0 and then port from mcast_addr is used.
 * Return -1 on failure, otherwise socket file descriptor is returned.
 */
int
sf_create_multicast_socket(const struct sockaddr *mcast_addr, const struct sockaddr *local_addr,
    const char *local_ifname, uint8_t ttl, int allow_mcast_loop,
    enum sf_transport_method transport_method, const struct aii_list *remote_addrs,
    int receive_timestamp, int force_recvttl, int sndbuf_size, int rcvbuf_size, uint16_t bind_port)
{
#ifdef __CYGWIN__
	struct sockaddr_storage any_sas;
#endif
	struct sockaddr_storage bind_addr;
	int sock;
	enum sf_cast_type cast_type;

	sock = sf_create_udp_socket(mcast_addr);
	if (sock == -1) {
		return (-1);
	}

	switch (transport_method) {
	case SF_TM_ASM:
	case SF_TM_SSM:
		cast_type = SF_CT_MULTI;
		break;
	case SF_TM_IPBC:
		cast_type = SF_CT_BROAD;
		break;
	default:
		DEBUG_PRINTF("Internal error - unknown transport method");
		errx(1, "Internal error - unknown transport method");
		/* NOTREACHED */
	}

	if (sf_set_socket_common_options(sock, mcast_addr, cast_type, ttl, force_recvttl,
	    receive_timestamp, sndbuf_size, rcvbuf_size, 1) == -1) {
		return (-1);
	}

	if (sfset_reuse(sock) == -1) {
		return (-1);
	}

	af_copy_sa_to_sas(&bind_addr, mcast_addr);
	if (bind_port != 0) {
		af_sa_set_port(AF_CAST_SA(&bind_addr), bind_port);
	}

	switch (transport_method) {
	case SF_TM_ASM:
	case SF_TM_SSM:
#ifdef __CYGWIN__
		af_sa_to_any_addr(AF_CAST_SA(&any_sas), AF_CAST_SA(&bind_addr));
		memcpy(&bind_addr, &any_sas, sizeof(*any_sas));
#endif

		if (sf_bind_socket(AF_CAST_SA(&bind_addr), sock) == -1) {
			return (-1);
		}

		if (sfset_mcast_loop(mcast_addr, sock, allow_mcast_loop) == -1) {
			return (-1);
		}

		break;
	case SF_TM_IPBC:
		if (sf_bind_socket(AF_CAST_SA(&bind_addr), sock) == -1) {
			return (-1);
		}
		break;
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
	case SF_TM_IPBC:
		/*
		 * Broadcast packet doesn't need any special handling on receiver side
		 */
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
 * set_mcast_ttl not 0. If mcast_send is set, options for sending multicast/broadcast packets are
 * set. allow_mcast_loop is boolean flag to set mcast_loop. local_ifname is name of local interface
 * where local_addr is present. transport_method is transport method to use. If receive_timestamp is
 * set, recvmsg cmsg will (if supported) contain timestamp of packet receive. force_recv_ttl is
 * used to force set of recvttl (if option is not supported, error is returned). sndbuf_size is
 * size of socket buffer to allocate for sending packets. rcvbuf_size is size of socket buffer
 * to allocate for receiving packets. bind_port is port to bind. It can be set to NULL, and then
 * port from local_addr is used. If real pointer is used, and value is 0, random port is choosen and
 * real port is returned there. Other value will bind port to given value. Port is in network
 * format.
 * Return -1 on failure, otherwise socket file descriptor is returned.
 */
int
sf_create_unicast_socket(const struct sockaddr *local_addr, uint8_t ttl, int mcast_send,
    int allow_mcast_loop, const char *local_ifname, enum sf_transport_method transport_method,
    int receive_timestamp, int force_recvttl, int sndbuf_size, int rcvbuf_size,
    uint16_t *bind_port)
{
	struct sockaddr_storage bind_addr;
	socklen_t bind_addr_len;
	int sock;

	sock = sf_create_udp_socket(local_addr);
	if (sock == -1) {
		return (-1);
	}

	if (sf_set_socket_common_options(sock, local_addr, SF_CT_UNI, ttl, force_recvttl,
	    receive_timestamp, sndbuf_size, rcvbuf_size, 1) == -1) {
		return (-1);
	}

	if (mcast_send) {
		switch (transport_method) {
		case SF_TM_ASM:
		case SF_TM_SSM:
			if (sfset_ttl(local_addr, SF_CT_MULTI, sock, ttl) == -1) {
				return (-1);
			}

			if (sfset_mcast_loop(local_addr, sock, allow_mcast_loop) == -1) {
				return (-1);
			}

			if (sfset_mcast_if(local_addr, sock, local_ifname) == -1) {
				return (-1);
			}
			break;
		case SF_TM_IPBC:
			if (sfset_broadcast(sock, 1) == -1) {
				return (-1);
			}
			break;
		}
	}

	af_copy_sa_to_sas(&bind_addr, local_addr);

	if (bind_port != NULL) {
		af_sa_set_port(AF_CAST_SA(&bind_addr), *bind_port);
	}

	if (sf_bind_socket(AF_CAST_SA(&bind_addr), sock) == -1) {
		return (-1);
	}

	if (bind_port != NULL && *bind_port == 0) {
		bind_addr_len = sizeof(bind_addr);

		if (getsockname(sock, AF_CAST_SA(&bind_addr), &bind_addr_len) == -1) {
			return (-1);
		}

		*bind_port = af_sa_port(AF_CAST_SA(&bind_addr));
	}

	return (sock);
}

/*
 * Return 1 if broadcast is supported on given OS on compilation time, otherwise 0
 */
int
sf_is_ipbc_supported(void)
{
#ifdef __CYGWIN__
	return (0);
#endif

#ifndef SO_BROADCAST
	return (0);
#endif

	return (1);
}

/*
 * Return 1 if ssm is supported on given OS on compilation time, otherwise 0
 */
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
    const struct aii_list *remote_addrs, const char *local_ifname, int sock)
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
 * Set common options for socket. Options are ipv6only, ttl, recvttl and receive timestamp. sock is
 * socket to set options, addr is address, cast_type is ether uni/multi or broad cast socket.
 * ttl is new Time-To-Live. force_recv_ttl is used to force set of recvttl (if option is
 * not supported, error is returned). If receive_timestamp is set, recvmsg cmsg will (if
 * supported) contain timestamp of packet receive. sndbuf_size is size of socket buffer to
 * allocate for sending packets. rcvbuf_size is size of socket buffer to allocate for receiving
 * packets. if force_buf_size is set and OS will not provide enough buffer, error code is returned
 * and errno is set to ENOBUFS (this is emulation of *BSD behavior).
 * Return -1 on failure, otherwise 0.
 */
static int
sf_set_socket_common_options(int sock, const struct sockaddr *addr, enum sf_cast_type cast_type,
    uint8_t ttl, int force_recvttl, int receive_timestamp, int sndbuf_size, int rcvbuf_size,
    int force_buf_size)
{
	const char *cast_str;
	int new_buf_size;
	int res;

	cast_str = sf_cast_type_to_str(cast_type);

	if (sfset_buf_size(sock, 1, sndbuf_size, &new_buf_size, force_buf_size) == -1) {
		return (-1);
	}

	DEBUG_PRINTF("Send buffer (%scast socket) allocated %u bytes", cast_str, new_buf_size);

	if (sfset_buf_size(sock, 0, rcvbuf_size, &new_buf_size, force_buf_size) == -1) {
		return (-1);
	}

	DEBUG_PRINTF("Receive buffer (%scast socket) allocated %u bytes", cast_str, new_buf_size);

	if (addr->sa_family == AF_INET6) {
		if (sfset_ipv6only(addr, sock) == -1) {
			return (-1);
		}
	}

	if (sfset_ttl(addr, cast_type, sock, ttl) == -1) {
		return (-1);
	}

	res = sfset_recvttl(addr, sock);
	if (res == -1 || (res == -2 && force_recvttl)) {
		return (-1);
	}

	if (receive_timestamp) {
		if (sfset_timestamp(sock) == -1) {
			return (-1);
		}
	}

	return (0);
}
