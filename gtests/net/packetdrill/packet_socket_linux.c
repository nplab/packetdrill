/*
 * Copyright 2013 Google Inc.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA
 * 02110-1301, USA.
 */
/*
 * Author: ncardwell@google.com (Neal Cardwell)
 *
 * API to read and write raw packets implemented using Linux packet socket.
 */

#include "packet_socket.h"

#include <errno.h>
#include <net/if.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/uio.h>
#include <unistd.h>

#ifdef linux

#include <netpacket/packet.h>
#include <linux/filter.h>
#include <linux/sockios.h>

#include "assert.h"
#include "ethernet.h"
#include "logging.h"

/* Number of bytes to buffer in the packet socket we use for sniffing. */
static const int PACKET_SOCKET_RCVBUF_BYTES = 2*1024*1024;

struct packet_socket {
	int packet_fd;	/* socket for sending, sniffing timestamped packets */
	char *name;	/* malloc-allocated copy of interface name */
	int index;	/* interface index from if_nametoindex */
	bool trim_ethernet_header;
};

/* Set the receive buffer for a socket to the given size in bytes. */
static void set_receive_buffer_size(int fd, int bytes)
{
	if (setsockopt(fd, SOL_SOCKET, SO_RCVBUF, &bytes, sizeof(bytes)) < 0)
		die_perror("setsockopt SOL_SOCKET SO_RCVBUF");
}

/* Bind the packet socket with the given fd to the given interface. */
static void bind_to_interface(int fd, int interface_index)
{
	struct sockaddr_ll sll;
	memset(&sll, 0, sizeof(sll));
	sll.sll_family		= AF_PACKET;
	sll.sll_ifindex		= interface_index;
	sll.sll_protocol	= htons(ETH_P_ALL);

	if (bind(fd, (struct sockaddr *)&sll, sizeof(sll)) < 0)
		die_perror("bind packet socket");
}

/* Allocate and configure a packet socket just like the one tcpdump
 * uses. We do this so we can get timestamps on the outbound packets
 * the kernel sends, to verify the correct timing (tun devices do not
 * take timestamps). To reduce CPU load and filtering complexity, we
 * bind the socket to a single device so we only receive packets for
 * that device.
 */
static void packet_socket_setup(struct packet_socket *psock)
{
	struct timeval tv;

	psock->packet_fd = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
	if (psock->packet_fd < 0)
		die_perror("socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL))");

	psock->index = if_nametoindex(psock->name);
	if (psock->index == 0)
		die_perror("if_nametoindex");
	DEBUGP("device index: %s -> %d\n", psock->name, psock->index);

	bind_to_interface(psock->packet_fd, psock->index);

	set_receive_buffer_size(psock->packet_fd, PACKET_SOCKET_RCVBUF_BYTES);


	/* Pay the non-trivial latency cost to enable timestamps now, before
	 * the test starts, to avoid significant delays in the middle of tests.
	 */
	ioctl(psock->packet_fd, SIOCGSTAMP, &tv);
}

static int count_local_family(const struct path *paths, int paths_cnt, int family) {
	int count = 0;
	for (int i = 0; i < paths_cnt; i++) {
		if(paths[i].local_ip.address_family == family)
			count++;
	}
	return count;
}

/* Add a filter so we only sniff packets we want. */
void packet_socket_set_filter(struct packet_socket *psock,
			      const struct ether_addr *client_ether_addr,
			      const struct path *paths, uint paths_cnt)
{
	const u8 *client_ether = client_ether_addr->ether_addr_octet;

	int v4_cnt = count_local_family(paths, paths_cnt, AF_INET);
	int v6_cnt = count_local_family(paths, paths_cnt, AF_INET6);

	/* summ lines of filter instructions */
	int filter_lines = 4 + 2;   /* ether + return */
	if (v4_cnt > 0)
		filter_lines += 3 + v4_cnt;
	if (v6_cnt > 0)
		filter_lines += 3 + v6_cnt;

	struct sock_filter *bpf_src, *bpf_src_next;
	bpf_src = bpf_src_next = calloc(filter_lines, sizeof(struct sock_filter));

	/* attach flter for ether adddress */
	*bpf_src_next = (struct sock_filter) { 0x20, 0,  0, 0x00000008 };
	bpf_src_next++;
	*bpf_src_next = (struct sock_filter) { 0x15, 0,  7, 0x33445566 };   /* ether: 33:44:55:66 */
	bpf_src_next->k = (((u32)client_ether[2] << 24) |
			           ((u32)client_ether[3] << 16) |
			           ((u32)client_ether[4] << 8)  |
			           ((u32)client_ether[5]));
	bpf_src_next++;
	*bpf_src_next = (struct sock_filter) { 0x28, 0,  0, 0x00000006 };
	bpf_src_next++;
	*bpf_src_next = (struct sock_filter) { 0x15, 0,  5, 0x00001122 };   /* ether: 11:22 */
	bpf_src_next->k = (((u32)client_ether[0] << 8)  |
			           ((u32)client_ether[1]));
	bpf_src_next++;

	if (v4_cnt > 0) {
		/* attach flter for ipv4 adddress */
		*bpf_src_next = (struct sock_filter) { 0x28, 0,  0, 0x0000000c };
		bpf_src_next++;
		*bpf_src_next = (struct sock_filter) { 0x15, 0,  3, 0x00000800 };
		bpf_src_next++;
		*bpf_src_next = (struct sock_filter) { 0x20, 0,  0, 0x0000001a };
		bpf_src_next++;

		/* Fill in the client-side IPv4 address to look for. */
		for (int i = 0; i < paths_cnt; i++)	{
			const struct path *path = &paths[i];

			if (path->local_ip.address_family != AF_INET)
				continue;

			*bpf_src_next = (struct sock_filter) { 0x15, 0,  1, 0x01020304 };   /* IPv4: 1.2.3.4 */
			bpf_src_next->k = ntohl(path->local_ip.ip.v4.s_addr);
			bpf_src_next++;
		}
	}

	if (v6_cnt > 0) {
		/* attach flter for ipv6 adddress */
		*bpf_src_next = (struct sock_filter) { 0x28, 0,  0, 0x0000000c };
		bpf_src_next++;
		*bpf_src_next = (struct sock_filter) { 0x15, 0,  9, 0x000086dd };
		bpf_src_next++;

		struct sock_filter bpf_ipv6_src[] = {
			{ 0x20, 0,  0, 0x00000016 },
			{ 0x20, 0,  0, 0x0000001a },
			{ 0x20, 0,  0, 0x0000001e },
			{ 0x20, 0,  0, 0x00000022 }
		};

		/* Fill in the client-side IPv6 address to look for. */
		for (int i = 0; i < 4; i++) {
			*bpf_src_next = bpf_ipv6_src[i];
			bpf_src_next++;

			/* check each two blocks */
			for (int i = 0; i < paths_cnt; i++)	{
				const struct path *path = &paths[i];

				if (path->local_ip.address_family != AF_INET6)
					continue;

				*bpf_src_next = (struct sock_filter) { 0x15, 0,  7, 0x00010002 },   /* IPv6: 1:2 */
				bpf_src_next->k = ntohl(path->local_ip.ip.v6.s6_addr32[i]);
				bpf_src_next++;
			}

		}
	}

	/* attach returns */
	*bpf_src_next = (struct sock_filter) {  0x6, 0,  0, 0x0000ffff };
	bpf_src_next++;
	*bpf_src_next = (struct sock_filter) {  0x6, 0,  0, 0x00000000 };

	/* bpf_src_next sould now be at the end of the buffer */
	assert(bpf_src_next == bpf_src + filter_lines);

	/* update length of jumps to the end (return false) */
	for (int i = -1; i < filter_lines; i++, bpf_src_next--) {
		if (bpf_src_next->code == 0x15)
			bpf_src_next->jf = i;
	}

	struct sock_fprog bpfcode;
	bpfcode.len = filter_lines;
	bpfcode.filter = bpf_src;

	if (debug_logging) {
		int i;
		DEBUGP("filter constants:\n");
		for (i = 0; i < bpfcode.len; ++i)
			DEBUGP("0x%x\n", bpfcode.filter[i].k);
	}

	/* Attach the filter. */
	if (setsockopt(psock->packet_fd, SOL_SOCKET, SO_ATTACH_FILTER,
		       &bpfcode, sizeof(bpfcode)) < 0) {
		die_perror("setsockopt SOL_SOCKET, SO_ATTACH_FILTER");
	}

	psock->trim_ethernet_header = true;
}

struct packet_socket *packet_socket_new(const char *device_name)
{
	struct packet_socket *psock = calloc(1, sizeof(struct packet_socket));

	psock->name = strdup(device_name);
	psock->packet_fd = -1;
	psock->trim_ethernet_header = false;

	packet_socket_setup(psock);

	return psock;
}

void packet_socket_free(struct packet_socket *psock)
{
	if (psock->packet_fd >= 0)
		close(psock->packet_fd);

	if (psock->name != NULL)
		free(psock->name);

	memset(psock, 0, sizeof(*psock));	/* paranoia to catch bugs*/
	free(psock);
}

int packet_socket_writev(struct packet_socket *psock,
			 const struct iovec *iov, int iovcnt)
{
	if (writev(psock->packet_fd, iov, iovcnt) < 0) {
		perror("writev");
		return STATUS_ERR;
	}
	return STATUS_OK;
}

int packet_socket_receive(struct packet_socket *psock,
			  enum direction_t direction, u16 *ether_type,
			  struct packet *packet, int *in_bytes)
{
	struct sockaddr_ll from;
	struct ether_header ether;
	struct iovec iov[2];
	struct msghdr msg;

	/* Read the packet out of our kernel packet socket buffer. */
	memset(&from, 0, sizeof(from));
	if (psock->trim_ethernet_header) {
		iov[0].iov_base = &ether;
		iov[0].iov_len = sizeof(struct ether_header);
		iov[1].iov_base = packet->buffer;
		iov[1].iov_len = packet->buffer_bytes;
	} else {
		iov[0].iov_base = packet->buffer;
		iov[0].iov_len = packet->buffer_bytes;
	}
	msg.msg_name = &from;
	msg.msg_namelen = (socklen_t)sizeof(struct sockaddr_ll);
	msg.msg_iov = iov;
	msg.msg_iovlen = (psock->trim_ethernet_header == 1) ? 2 : 1;
	msg.msg_control = NULL;
	msg.msg_controllen = 0;
	msg.msg_flags = 0;
	*in_bytes = recvmsg(psock->packet_fd, &msg, 0);

	if (psock->trim_ethernet_header)
		assert(*in_bytes <=
		       packet->buffer_bytes + sizeof(struct ether_header));
	else
		assert(*in_bytes <= packet->buffer_bytes);
	if (*in_bytes < 0) {
		if (errno == EINTR) {
			DEBUGP("EINTR\n");
			return STATUS_ERR;
		} else {
			die_perror("packet socket recvfrom()");
		}
	}

	/* We only want packets our kernel is sending out. */
	if (direction == DIRECTION_OUTBOUND &&
	    from.sll_pkttype != PACKET_OUTGOING) {
		DEBUGP("not outbound\n");
		return STATUS_ERR;
	}
	if (direction == DIRECTION_INBOUND &&
	    from.sll_pkttype != PACKET_HOST) {
		DEBUGP("not inbound\n");
		return STATUS_ERR;
	}

	/* We only want packets on our tun device. The kernel
	 * can put packets for other devices in our receive
	 * buffer before we bind the packet socket to the tun
	 * device.
	 */
	if (from.sll_ifindex != psock->index) {
		DEBUGP("not correct index\n");
		return STATUS_ERR;
	}

	/* Get the time at which the kernel sniffed the packet. */
	struct timeval tv;
	if (ioctl(psock->packet_fd, SIOCGSTAMP, &tv) < 0)
		die_perror("SIOCGSTAMP");
	packet->time_usecs = timeval_to_usecs(&tv);
	DEBUGP("sniffed packet sent at %u.%u = %lld\n",
	       (u32)tv.tv_sec, (u32)tv.tv_usec,
	       packet->time_usecs);

	DEBUGP("reported sll_protocol = 0x%04x\n", ntohs(from.sll_protocol));
	if (psock->trim_ethernet_header) {
		if (*in_bytes < sizeof(struct ether_header)) {
			DEBUGP("packet does not contain ethernet header\n");
			return STATUS_ERR;
		} else {
			*ether_type = ntohs(ether.ether_type);
			*in_bytes -= sizeof(struct ether_header);
		}
	} else {
		*ether_type = ntohs(from.sll_protocol);
	}
	DEBUGP("ether_type is 0x%04x\n", *ether_type);
	return STATUS_OK;
}

#endif  /* linux */
