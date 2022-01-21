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
 * Implementation for module for formatting UDPLite packets.
 */

#include "udplite_packet.h"

#include "ip_packet.h"
#include "udplite.h"

struct packet *new_udplite_packet(int address_family,
				  enum direction_t direction,
				  struct ip_info ip_info,
				  u16 udplite_payload_bytes,
				  u16 checksum_coverage,
				  u16 src_port,
				  u16 dst_port,
				  char **error)
{
#if defined(IPPROTO_UDPLITE)
	struct packet *packet = NULL;  /* the newly-allocated result packet */
	struct header *udplite_header = NULL;  /* the UDPLITE header info */
	/* Calculate lengths in bytes of all sections of the packet */
	const int ip_option_bytes = 0;
	const int ip_header_bytes = (ip_header_min_len(address_family) +
				     ip_option_bytes);
	const int udplite_header_bytes = sizeof(struct udplite);
	const int ip_bytes =
		 ip_header_bytes + udplite_header_bytes + udplite_payload_bytes;

	/* Sanity-check all the various lengths */
	if (ip_option_bytes & 0x3) {
		asprintf(error, "IP options are not padded correctly "
			 "to ensure IP header is a multiple of 4 bytes: "
			 "%d excess bytes", ip_option_bytes & 0x3);
		return NULL;
	}
	assert((udplite_header_bytes & 0x3) == 0);
	assert((ip_header_bytes & 0x3) == 0);

	if (ip_bytes > MAX_UDPLITE_DATAGRAM_BYTES) {
		asprintf(error, "UDPLite datagram too large");
		return NULL;
	}

	/* Allocate and zero out a packet object of the desired size */
	packet = packet_new(ip_bytes);
	memset(packet->buffer, 0, ip_bytes);

	packet->direction = direction;
	packet->flags = 0;
	packet->tos_chk = ip_info.tos.check;

	/* Set IP header fields */
	set_packet_ip_header(packet, address_family, ip_bytes,
			     ip_info.tos.value, ip_info.flow_label,
			     ip_info.ttl, IPPROTO_UDPLITE);

	udplite_header = packet_append_header(packet, HEADER_UDPLITE,
					      sizeof(struct udplite));
	udplite_header->total_bytes = udplite_header_bytes +
				      udplite_payload_bytes;

	/* Find the start of UDPLite section of the packet */
	packet->udplite =
	    (struct udplite *)(ip_start(packet) + ip_header_bytes);

	/* Set UDPLITE header fields */
	packet->udplite->src_port	= htons(src_port);
	packet->udplite->dst_port	= htons(dst_port);
	packet->udplite->cov		= htons(checksum_coverage);
	packet->udplite->check		= 0;

	packet->ip_bytes = ip_bytes;
	return packet;
#else
	return NULL;
#endif
}
