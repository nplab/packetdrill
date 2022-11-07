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
 * Implementation for a module to checksum TCP/IP packets.
 */

#include "packet_checksum.h"

#include "checksum.h"
#include "icmp.h"
#include "icmpv6.h"
#include "ip.h"
#include "ipv6.h"
#include "tcp.h"

static void checksum_ipv4_packet(struct packet *packet)
{
	struct ipv4 *ipv4 = packet->ipv4;

	/* Fill in IPv4 header checksum. */
	ipv4->check = 0;
	ipv4->check = ipv4_checksum(ipv4, ipv4_header_len(ipv4));
	assert(packet->ip_bytes >= ntohs(ipv4->tot_len));

	/* Find the length of layer 4 header, options, and payload. */
	const int l4_bytes = ntohs(ipv4->tot_len) - ipv4_header_len(ipv4);
	assert(l4_bytes > 0);

	/* Fill in IPv4-based layer 4 checksum. */
	if (packet->sctp != NULL) {
		struct sctp_common_header *sctp = packet->sctp;
		struct udp *udp;

		sctp->crc32c = htonl(0);
		if ((packet->flags & FLAGS_SCTP_ZERO_CHECKSUM) == 0) {
			if (packet->flags & FLAGS_UDP_ENCAPSULATED) {
				sctp->crc32c = sctp_crc32c(sctp, l4_bytes - sizeof(struct udp));
			} else {
				sctp->crc32c = sctp_crc32c(sctp, l4_bytes);
			}
			if (packet->flags & FLAGS_SCTP_BAD_CRC32C) {
				sctp->crc32c = htonl(ntohl(sctp->crc32c) + 1);
			}
		}
		if (packet->flags & FLAGS_UDP_ENCAPSULATED) {
			udp = ((struct udp *)sctp) - 1;
			udp->check = 0;
			udp->check = tcp_udp_v4_checksum(ipv4->src_ip,
							 ipv4->dst_ip,
							 IPPROTO_UDP, udp,
							 l4_bytes);
		}
	} else if (packet->tcp != NULL) {
		struct tcp *tcp = packet->tcp;
		struct udp *udp;

		tcp->check = 0;
		if (packet->flags & FLAGS_UDP_ENCAPSULATED) {
			tcp->check = tcp_udp_v4_checksum(ipv4->src_ip,
							 ipv4->dst_ip,
							 IPPROTO_TCP, tcp,
							 l4_bytes - sizeof(struct udp));
		} else {
			tcp->check = tcp_udp_v4_checksum(ipv4->src_ip,
							 ipv4->dst_ip,
							 IPPROTO_TCP, tcp,
							 l4_bytes);
		}
		if (packet->flags & FLAGS_UDP_ENCAPSULATED) {
			udp = ((struct udp *)tcp) - 1;
			udp->check = 0;
			udp->check = tcp_udp_v4_checksum(ipv4->src_ip,
							 ipv4->dst_ip,
							 IPPROTO_UDP, udp,
							 l4_bytes);
		}
	} else if (packet->udp != NULL) {
		struct udp *udp = packet->udp;

		udp->check = 0;
		udp->check = tcp_udp_v4_checksum(ipv4->src_ip,
						 ipv4->dst_ip,
						 IPPROTO_UDP, udp, l4_bytes);
	} else if (packet->udplite != NULL) {
		struct udplite *udplite = packet->udplite;
		u16 coverage;

		coverage = ntohs(udplite->cov);
		if ((coverage == 0) || (coverage > l4_bytes))
			coverage = l4_bytes;
		udplite->check = 0;
		udplite->check = udplite_v4_checksum(ipv4->src_ip,
						     ipv4->dst_ip,
						     IPPROTO_UDPLITE,
						     udplite,
						     l4_bytes, coverage);
	} else if (packet->icmpv4 != NULL) {
		struct icmpv4 *icmpv4 = packet->icmpv4;

		icmpv4->checksum = 0;
		icmpv4->checksum = ipv4_checksum(icmpv4, l4_bytes);
	} else {
		assert(!"not SCTP or TCP or UDP or UDPLite or ICMP");
	}
}

static void checksum_ipv6_packet(struct packet *packet)
{
	struct ipv6 *ipv6 = packet->ipv6;

	/* IPv6 has no header checksum. */
	/* For now we do not support IPv6 extension headers. */
	assert(packet->ip_bytes >= sizeof(*ipv6) + ntohs(ipv6->payload_len));

	/* Find the length of layer 4 header, options, and payload. */
	const int l4_bytes = ntohs(ipv6->payload_len);
	assert(l4_bytes > 0);

	/* Fill in IPv6-based layer 4 checksum. */
	if (packet->sctp != NULL) {
		struct sctp_common_header *sctp = packet->sctp;
		struct udp *udp;

		sctp->crc32c = htonl(0);
		if ((packet->flags & FLAGS_SCTP_ZERO_CHECKSUM) == 0) {
			if (packet->flags & FLAGS_UDP_ENCAPSULATED) {
				sctp->crc32c = sctp_crc32c(sctp, l4_bytes - sizeof(struct udp));
			} else {
				sctp->crc32c = sctp_crc32c(sctp, l4_bytes);
			}
			if (packet->flags & FLAGS_SCTP_BAD_CRC32C) {
				sctp->crc32c = htonl(ntohl(sctp->crc32c) + 1);
			}
		}
		if (packet->flags & FLAGS_UDP_ENCAPSULATED) {
			udp = ((struct udp *)sctp) - 1;
			udp->check = 0;
			udp->check = tcp_udp_v6_checksum(&ipv6->src_ip,
							 &ipv6->dst_ip,
							 IPPROTO_UDP, udp,
							 l4_bytes);
		}
	} else if (packet->tcp != NULL) {
		struct tcp *tcp = packet->tcp;
		struct udp *udp;

		tcp->check = 0;
		if (packet->flags & FLAGS_UDP_ENCAPSULATED) {
			tcp->check = tcp_udp_v6_checksum(&ipv6->src_ip,
							 &ipv6->dst_ip,
							 IPPROTO_TCP, tcp,
							 l4_bytes - sizeof(struct udp));
		} else {
			tcp->check = tcp_udp_v6_checksum(&ipv6->src_ip,
							 &ipv6->dst_ip,
							 IPPROTO_TCP, tcp,
							 l4_bytes);
		}
		if (packet->flags & FLAGS_UDP_ENCAPSULATED) {
			udp = ((struct udp *)tcp) - 1;
			udp->check = 0;
			udp->check = tcp_udp_v6_checksum(&ipv6->src_ip,
							 &ipv6->dst_ip,
							 IPPROTO_UDP, udp,
							 l4_bytes);
		}
	} else if (packet->udp != NULL) {
		struct udp *udp = packet->udp;

		udp->check = 0;
		udp->check = tcp_udp_v6_checksum(&ipv6->src_ip,
						 &ipv6->dst_ip,
						 IPPROTO_UDP, udp, l4_bytes);
	} else if (packet->udplite != NULL) {
		struct udplite *udplite = packet->udplite;
		u16 coverage;

		coverage = ntohs(udplite->cov);
		if ((coverage == 0) || (coverage > l4_bytes))
			coverage = l4_bytes;
		udplite->check = 0;
		udplite->check = udplite_v6_checksum(&ipv6->src_ip,
						     &ipv6->dst_ip,
						     IPPROTO_UDPLITE,
						     udplite,
						     l4_bytes, coverage);
	} else if (packet->icmpv6 != NULL) {
		/* IPv6 ICMP has a pseudo-header checksum, like TCP. */
		struct icmpv6 *icmpv6 = packet->icmpv6;
		icmpv6->checksum = 0;
		icmpv6->checksum =
			tcp_udp_v6_checksum(&ipv6->src_ip,
					    &ipv6->dst_ip,
					    IPPROTO_ICMPV6, icmpv6, l4_bytes);
	} else {
		assert(!"not SCTP or TCP or UDP or UDPLite or ICMP");
	}
}

void checksum_packet(struct packet *packet)
{
	int address_family = packet_address_family(packet);
	if (address_family == AF_INET)
		checksum_ipv4_packet(packet);
	else if (address_family == AF_INET6)
		checksum_ipv6_packet(packet);
	else
		assert(!"bad ip version");
}
