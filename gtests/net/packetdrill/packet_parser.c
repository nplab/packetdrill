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
 * Implementation for a module to parse TCP/IP packets.
 */

#include "packet_parser.h"

#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

#include "assert.h"
#include "checksum.h"
#include "ethernet.h"
#include "gre.h"
#include "ip.h"
#include "ip_address.h"
#include "logging.h"
#include "packet.h"
#include "tcp.h"

static int parse_ipv4(struct packet *packet, u8 udp_encaps,
		      u8 *header_start, u8 *packet_end, char **error);
static int parse_ipv6(struct packet *packet, u8 udp_encaps,
		      u8 *header_start, u8 *packet_end, char **error);
static int parse_mpls(struct packet *packet, u8 udp_encaps,
		      u8 *header_start, u8 *packet_end, char **error);
static int parse_layer3_packet_by_proto(struct packet *packet,
					u16 proto, u8 udp_encaps,
					u8 *header_start, u8 *packet_end,
					char **error);
static int parse_layer4(struct packet *packet, u8 udp_encaps, u8 *header_start,
			int layer4_protocol, int layer4_bytes,
			u8 *packet_end, bool *is_inner, char **error);

static int parse_layer3_packet_by_proto(struct packet *packet,
					u16 proto, u8 udp_encaps,
					u8 *header_start, u8 *packet_end,
					char **error)
{
	u8 *p = header_start;

	if (proto == ETHERTYPE_IP) {
		struct ipv4 *ip = NULL;

		/* Examine IPv4 header. */
		if (p + sizeof(struct ipv4) > packet_end) {
			asprintf(error, "IPv4 header overflows packet");
			goto error_out;
		}

		/* Look at the IP version number, which is in the first 4 bits
		 * of both IPv4 and IPv6 packets.
		 */
		ip = (struct ipv4 *)p;
		if (ip->version == 4) {
			return parse_ipv4(packet, udp_encaps, p, packet_end,
					  error);
		} else {
			asprintf(error, "Bad IP version for ETHERTYPE_IP");
			goto error_out;
		}
	} else if (proto == ETHERTYPE_IPV6) {
		struct ipv6 *ip = NULL;

		/* Examine IPv6 header. */
		if (p + sizeof(struct ipv6) > packet_end) {
			asprintf(error, "IPv6 header overflows packet");
			goto error_out;
		}

		/* Look at the IP version number, which is in the first 4 bits
		 * of both IPv4 and IPv6 packets.
		 */
		ip = (struct ipv6 *)p;
		if (ip->version == 6) {
			return parse_ipv6(packet, udp_encaps, p, packet_end,
					  error);
		} else {
			asprintf(error, "Bad IP version for ETHERTYPE_IPV6");
			goto error_out;
		}
	} else if ((proto == ETHERTYPE_MPLS_UC) ||
		   (proto == ETHERTYPE_MPLS_MC)) {
		return parse_mpls(packet, udp_encaps, p, packet_end, error);
	} else {
		return PACKET_UNKNOWN_L4;
	}

error_out:
	return PACKET_BAD;
}

static int parse_layer3_packet(struct packet *packet, u8 udp_encaps,
			       u8 *header_start, u8 *packet_end,
			       char **error)
{
	u8 *p = header_start;
	/* Note that packet_end points to the byte beyond the end of packet. */
	struct ipv4 *ip = NULL;

	/* Examine IPv4/IPv6 header. */
	if (p + sizeof(struct ipv4) > packet_end) {
		asprintf(error, "IP header overflows packet");
		return PACKET_BAD;
	}

	/* Look at the IP version number, which is in the first 4 bits
	 * of both IPv4 and IPv6 packets.
	 */
	ip = (struct ipv4 *) (p);
	if (ip->version == 4)
		return parse_ipv4(packet, udp_encaps, p, packet_end, error);
	else if (ip->version == 6)
		return parse_ipv6(packet, udp_encaps, p, packet_end, error);

	asprintf(error, "Unsupported IP version");
	return PACKET_BAD;
}

int parse_packet(struct packet *packet, int in_bytes,
		 u16 ether_type, u8 udp_encaps, char **error)
{
	assert(in_bytes <= packet->buffer_bytes);
	char *message = NULL;		/* human-readable error summary */
	char *hex = NULL;		/* hex dump of bad packet */
	enum packet_parse_result_t result = PACKET_BAD;
	u8 *header_start = packet->buffer;
	/* packet_end points to the byte beyond the end of packet. */
	u8 *packet_end = packet->buffer + in_bytes;

	result = parse_layer3_packet_by_proto(packet, ether_type, udp_encaps,
					      header_start, packet_end, error);

	if (result != PACKET_BAD)
		return result;

	/* Error. Add a packet hex dump to the error string we're returning. */
	hex_dump(packet->buffer, in_bytes, &hex);
	message = *error;
	asprintf(error, "%s: packet of %d bytes:\n%s", message, in_bytes, hex);
	free(message);
	free(hex);

	return PACKET_BAD;
}

/* Parse the IPv4 header and the TCP header inside. Return a
 * packet_parse_result_t.
 * Note that packet_end points to the byte beyond the end of packet.
 */
static int parse_ipv4(struct packet *packet, u8 udp_encaps,
		      u8 *header_start, u8 *packet_end, char **error)
{
	struct header *ip_header = NULL;
	u8 *p = header_start;
	const bool is_outer = (packet->ip_bytes == 0);
	bool is_inner = false;
	enum packet_parse_result_t result = PACKET_BAD;
	struct ipv4 *ipv4 = (struct ipv4 *) (p);

	const int ip_header_bytes = ipv4_header_len(ipv4);
	assert(ip_header_bytes >= 0);
	if (ip_header_bytes < sizeof(*ipv4)) {
		asprintf(error, "IP header too short");
		goto error_out;
	}
	if (p + ip_header_bytes > packet_end) {
		asprintf(error, "Full IP header overflows packet");
		goto error_out;
	}
	const int ip_total_bytes = ntohs(ipv4->tot_len);

	if (p + ip_total_bytes > packet_end) {
		asprintf(error, "IP payload overflows packet");
		goto error_out;
	}
	if (ip_header_bytes > ip_total_bytes) {
		asprintf(error, "IP header bigger than datagram");
		goto error_out;
	}
	if (ntohs(ipv4->frag_off) & IP_MF) {	/* more fragments? */
		asprintf(error, "More fragments remaining");
		goto error_out;
	}
	if (ntohs(ipv4->frag_off) & IP_OFFMASK) {  /* fragment offset */
		asprintf(error, "Non-zero fragment offset");
		goto error_out;
	}
	const u16 checksum = ipv4_checksum(ipv4, ip_header_bytes);
	if (checksum != 0) {
		u16 received_checksum, computed_checksum;

		received_checksum = ntohs(ipv4->check);
		ipv4->check = 0;
		computed_checksum = ntohs(ipv4_checksum(ipv4, ip_header_bytes));
		ipv4->check = htons(received_checksum);
		asprintf(error, "Bad IP checksum 0x%04x (expected 0x%04x)",
			 received_checksum, computed_checksum);
		goto error_out;
	}

	ip_header = packet_append_header(packet, HEADER_IPV4, ip_header_bytes);
	if (ip_header == NULL) {
		asprintf(error, "Too many nested headers at IPv4 header");
		goto error_out;
	}
	ip_header->total_bytes = ip_total_bytes;

	/* Move on to the header inside. */
	p += ip_header_bytes;
	assert(p <= packet_end);

#if defined(DEBUG)
	if (debug_logging) {
		char src_string[ADDR_STR_LEN];
		char dst_string[ADDR_STR_LEN];
		struct ip_address src_ip, dst_ip;
		ip_from_ipv4(&ipv4->src_ip, &src_ip);
		ip_from_ipv4(&ipv4->dst_ip, &dst_ip);
		DEBUGP("src IP: %s\n", ip_to_string(&src_ip, src_string));
		DEBUGP("dst IP: %s\n", ip_to_string(&dst_ip, dst_string));
	}
#endif /* DEBUG */

	/* Examine the L4 header. */
	const int layer4_bytes = ip_total_bytes - ip_header_bytes;
	const int layer4_protocol = ipv4->protocol;
	result = parse_layer4(packet, udp_encaps, p, layer4_protocol,
			      layer4_bytes, packet_end, &is_inner, error);

	/* If this is the innermost IP header then this is the primary. */
	if (is_inner)
		packet->ipv4 = ipv4;
	/* If this is the outermost IP header then this is the packet length. */
	if (is_outer)
		packet->ip_bytes = ip_total_bytes;

	return result;

error_out:
	return PACKET_BAD;
}

/* Parse the IPv6 header and the TCP header inside. We do not
 * currently support parsing IPv6 extension headers or any layer 4
 * protocol other than TCP. Return a packet_parse_result_t.
 * Note that packet_end points to the byte beyond the end of packet.
 */
static int parse_ipv6(struct packet *packet, u8 udp_encaps,
		      u8 *header_start, u8 *packet_end, char **error)
{
	struct header *ip_header = NULL;
	u8 *p = header_start;
	const bool is_outer = (packet->ip_bytes == 0);
	bool is_inner = false;
	struct ipv6 *ipv6 = (struct ipv6 *) (p);
	enum packet_parse_result_t result = PACKET_BAD;

	/* Check that header fits in sniffed packet. */
	const int ip_header_bytes = sizeof(*ipv6);
	if (p + ip_header_bytes > packet_end) {
		asprintf(error, "IPv6 header overflows packet");
		goto error_out;
	}

	/* Check that payload fits in sniffed packet. */
	const int ip_total_bytes = (ip_header_bytes +
				    ntohs(ipv6->payload_len));

	if (p + ip_total_bytes > packet_end) {
		asprintf(error, "IPv6 payload overflows packet");
		goto error_out;
	}
	assert(ip_header_bytes <= ip_total_bytes);

	ip_header = packet_append_header(packet, HEADER_IPV6, ip_header_bytes);
	if (ip_header == NULL) {
		asprintf(error, "Too many nested headers at IPv6 header");
		goto error_out;
	}
	ip_header->total_bytes = ip_total_bytes;

	/* Move on to the header inside. */
	p += ip_header_bytes;
	assert(p <= packet_end);

#if defined(DEBUG)
	if (debug_logging) {
		char src_string[ADDR_STR_LEN];
		char dst_string[ADDR_STR_LEN];
		struct ip_address src_ip, dst_ip;
		ip_from_ipv6(&ipv6->src_ip, &src_ip);
		ip_from_ipv6(&ipv6->dst_ip, &dst_ip);
		DEBUGP("src IP: %s\n", ip_to_string(&src_ip, src_string));
		DEBUGP("dst IP: %s\n", ip_to_string(&dst_ip, dst_string));
	}
#endif /* DEBUG */

	/* Examine the L4 header. */
	const int layer4_bytes = ip_total_bytes - ip_header_bytes;
	const int layer4_protocol = ipv6->next_header;
	result = parse_layer4(packet, udp_encaps, p, layer4_protocol,
			      layer4_bytes, packet_end, &is_inner, error);

	/* If this is the innermost IP header then this is the primary. */
	if (is_inner)
		packet->ipv6 = ipv6;
	/* If this is the outermost IP header then this is the packet length. */
	if (is_outer)
		packet->ip_bytes = ip_total_bytes;

	return result;

error_out:
	return PACKET_BAD;
}

/* Parse the SCTP header. Return a packet_parse_result_t. */
static int parse_sctp(struct packet *packet, u8 *layer4_start, int layer4_bytes,
		      u8 *packet_end, char **error)
{
	u32 received_crc32c, computed_crc32c;
	struct header *sctp_header = NULL;
	u8 *p = layer4_start;

	assert(layer4_bytes >= 0);
	if (layer4_bytes < sizeof(struct sctp_common_header)) {
		asprintf(error, "Truncated SCTP common header");
		goto error_out;
	}
	packet->sctp = (struct sctp_common_header *) p;

	received_crc32c = ntohl(packet->sctp->crc32c);
	if (received_crc32c != 0) {
		packet->sctp->crc32c = htonl(0);
		computed_crc32c = ntohl(sctp_crc32c(packet->sctp, layer4_bytes));
		packet->sctp->crc32c = htonl(received_crc32c);
		if (received_crc32c != computed_crc32c) {
			asprintf(error, "Bad SCTP checksum 0x%08x (expected 0x%08x)",
				 received_crc32c, computed_crc32c);
			goto error_out;
		}
	}
	const int sctp_header_len = sizeof(struct sctp_common_header);
	sctp_header = packet_append_header(packet, HEADER_SCTP,
					   sctp_header_len);
	if (sctp_header == NULL) {
		asprintf(error, "Too many nested headers at SCTP header");
		goto error_out;
	}
	sctp_header->total_bytes = layer4_bytes;
	p += layer4_bytes;
	assert(p <= packet_end);

	DEBUGP("SCTP src port: %d\n", ntohs(packet->sctp->src_port));
	DEBUGP("SCTP dst port: %d\n", ntohs(packet->sctp->dst_port));
	return PACKET_OK;

error_out:
	return PACKET_BAD;
}

/* Parse the TCP header. Return a packet_parse_result_t. */
static int parse_tcp(struct packet *packet, u8 *layer4_start, int layer4_bytes,
		     u8 *packet_end, char **error)
{
	struct header *tcp_header = NULL;
	u8 *p = layer4_start;

	assert(layer4_bytes >= 0);
	if (layer4_bytes < sizeof(struct tcp)) {
		asprintf(error, "Truncated TCP header");
		goto error_out;
	}
	packet->tcp = (struct tcp *) p;
	const int tcp_header_len = packet_tcp_header_len(packet);
	if (tcp_header_len < sizeof(struct tcp)) {
		asprintf(error, "TCP data offset too small");
		goto error_out;
	}
	if (tcp_header_len > layer4_bytes) {
		asprintf(error, "TCP data offset too big");
		goto error_out;
	}

	tcp_header = packet_append_header(packet, HEADER_TCP, tcp_header_len);
	if (tcp_header == NULL) {
		asprintf(error, "Too many nested headers at TCP header");
		goto error_out;
	}
	tcp_header->total_bytes = layer4_bytes;

	p += layer4_bytes;
	assert(p <= packet_end);

	DEBUGP("TCP src port: %d\n", ntohs(packet->tcp->src_port));
	DEBUGP("TCP dst port: %d\n", ntohs(packet->tcp->dst_port));
	return PACKET_OK;

error_out:
	return PACKET_BAD;
}

/* Parse the UDP header. Return a packet_parse_result_t. */
static int parse_udp(struct packet *packet, u8 udp_encaps,
		     u8 *layer4_start, int layer4_bytes, u8 *packet_end,
		     char **error)
{
	struct header *udp_header = NULL;
	u8 *p = layer4_start;
	struct udp *udp;

	assert(layer4_bytes >= 0);
	if (layer4_bytes < sizeof(struct udp)) {
		asprintf(error, "Truncated UDP header");
		goto error_out;
	}
	udp = (struct udp *) p;
	const int udp_len = ntohs(udp->len);
	const int udp_header_len = sizeof(struct udp);
	if (udp_len < udp_header_len) {
		asprintf(error, "UDP datagram length too small for UDP header");
		goto error_out;
	}
	if (udp_len < layer4_bytes) {
		asprintf(error, "UDP datagram length too small");
		goto error_out;
	}
	if (udp_len > layer4_bytes) {
		asprintf(error, "UDP datagram length too big");
		goto error_out;
	}

	udp_header = packet_append_header(packet, HEADER_UDP, udp_header_len);
	if (udp_header == NULL) {
		asprintf(error, "Too many nested headers at UDP header");
		goto error_out;
	}
	udp_header->total_bytes = layer4_bytes;

	DEBUGP("UDP src port: %d\n", ntohs(udp->src_port));
	DEBUGP("UDP dst port: %d\n", ntohs(udp->dst_port));
	if (udp_encaps == IPPROTO_SCTP) {
		packet->flags |= FLAGS_UDP_ENCAPSULATED;
		return parse_sctp(packet, p + udp_header_len,
				  layer4_bytes - udp_header_len,
				  packet_end, error);
	} else if (udp_encaps == IPPROTO_TCP) {
		packet->flags |= FLAGS_UDP_ENCAPSULATED;
		return parse_tcp(packet, p + udp_header_len,
				 layer4_bytes - udp_header_len,
				  packet_end, error);
	} else {
		assert(udp_encaps == 0);
		packet->udp = udp;
		p += layer4_bytes;
		assert(p <= packet_end);
		return PACKET_OK;
	}

error_out:
	return PACKET_BAD;
}

/* Parse the UDPLite header. Return a packet_parse_result_t. */
static int parse_udplite(struct packet *packet, u8 *layer4_start,
			 int layer4_bytes, u8 *packet_end, char **error)
{
	struct header *udplite_header = NULL;
	u8 *p = layer4_start;

	assert(layer4_bytes >= 0);
	if (layer4_bytes < sizeof(struct udplite)) {
		asprintf(error, "Truncated UDPLite header");
		goto error_out;
	}
	packet->udplite = (struct udplite *) p;
	const int udplite_header_len = sizeof(struct udplite);

	if (layer4_bytes < udplite_header_len) {
		asprintf(error,
			 "UDPLITE datagram length too small for UDPLite header");
		goto error_out;
	}

	udplite_header = packet_append_header(packet, HEADER_UDPLITE,
					      udplite_header_len);
	if (udplite_header == NULL) {
		asprintf(error, "Too many nested headers at UDPLite header");
		goto error_out;
	}
	udplite_header->total_bytes = layer4_bytes;

	p += layer4_bytes;
	assert(p <= packet_end);

	DEBUGP("UDPLite src port: %d\n", ntohs(packet->udplite->src_port));
	DEBUGP("UDPLite dst port: %d\n", ntohs(packet->udplite->dst_port));
	return PACKET_OK;

error_out:
	return PACKET_BAD;
}

/* Parse the ICMPv4 header. Return a packet_parse_result_t. */
static int parse_icmpv4(struct packet *packet, u8 *layer4_start,
			int layer4_bytes, u8 *packet_end, char **error)
{
	struct header *icmp_header = NULL;
	const int icmp_header_len = sizeof(struct icmpv4);
	u8 *p = layer4_start;

	assert(layer4_bytes >= 0);
	/* Make sure the immediately preceding header was IPv4. */
	if (packet_inner_header(packet)->type != HEADER_IPV4) {
		asprintf(error, "Bad IP version for IPPROTO_ICMP");
		goto error_out;
	}

	if (layer4_bytes < sizeof(struct icmpv4)) {
		asprintf(error, "Truncated ICMPv4 header");
		goto error_out;
	}

	packet->icmpv4 = (struct icmpv4 *) p;

	icmp_header = packet_append_header(packet, HEADER_ICMPV4,
					   icmp_header_len);
	if (icmp_header == NULL) {
		asprintf(error, "Too many nested headers at ICMPV4 header");
		goto error_out;
	}
	icmp_header->total_bytes = layer4_bytes;

	p += layer4_bytes;
	assert(p <= packet_end);

	return PACKET_OK;

error_out:
	return PACKET_BAD;
}

/* Parse the ICMPv6 header. Return a packet_parse_result_t. */
static int parse_icmpv6(struct packet *packet, u8 *layer4_start,
			int layer4_bytes, u8 *packet_end, char **error)
{
	struct header *icmp_header = NULL;
	const int icmp_header_len = sizeof(struct icmpv6);
	u8 *p = layer4_start;

	assert(layer4_bytes >= 0);
	/* Make sure the immediately preceding header was IPv6. */
	if (packet_inner_header(packet)->type != HEADER_IPV6) {
		asprintf(error, "Bad IP version for IPPROTO_ICMPV6");
		goto error_out;
	}
	if (layer4_bytes < sizeof(struct icmpv6)) {
		asprintf(error, "Truncated ICMPv6 header");
		goto error_out;
	}

	packet->icmpv6 = (struct icmpv6 *) p;

	icmp_header = packet_append_header(packet, HEADER_ICMPV6,
					   icmp_header_len);
	if (icmp_header == NULL) {
		asprintf(error, "Too many nested headers at ICMPV6 header");
		goto error_out;
	}
	icmp_header->total_bytes = layer4_bytes;

	p += layer4_bytes;
	assert(p <= packet_end);

	return PACKET_OK;

error_out:
	return PACKET_BAD;
}

/* Parse the GRE header. Return a packet_parse_result_t. */
static int parse_gre(struct packet *packet, u8 udp_encaps,
		     u8 *layer4_start, int layer4_bytes, u8 *packet_end,
		     char **error)
{
	struct header *gre_header = NULL;
	u8 *p = layer4_start;
	struct gre *gre = (struct gre *) p;

	assert(layer4_bytes >= 0);
	if (layer4_bytes < sizeof(struct gre)) {
		asprintf(error, "Truncated GRE header");
		goto error_out;
	}
	if (gre->version != 0) {
		asprintf(error, "GRE header has unsupported version number");
		goto error_out;
	}
	if (gre->has_routing) {
		asprintf(error, "GRE header has unsupported routing info");
		goto error_out;
	}
	const int gre_header_len = gre_len(gre);
	if (gre_header_len < sizeof(struct gre)) {
		asprintf(error, "GRE header length too small for GRE header");
		goto error_out;
	}
	if (gre_header_len > layer4_bytes) {
		asprintf(error, "GRE header length too big");
		goto error_out;
	}

	assert(p + layer4_bytes <= packet_end);

	DEBUGP("GRE header len: %d\n", gre_header_len);

	gre_header = packet_append_header(packet, HEADER_GRE, gre_header_len);
	if (gre_header == NULL) {
		asprintf(error, "Too many nested headers at GRE header");
		goto error_out;
	}
	gre_header->total_bytes = layer4_bytes;

	p += gre_header_len;
	assert(p <= packet_end);
	return parse_layer3_packet_by_proto(packet, ntohs(gre->protocol),
					    udp_encaps, p, packet_end, error);

error_out:
	return PACKET_BAD;
}

static int parse_mpls(struct packet *packet, u8 udp_encaps,
		      u8 *header_start, u8 *packet_end, char **error)
{
	struct header *mpls_header = NULL;
	u8 *p = header_start;
	int mpls_header_bytes = 0;
	int mpls_total_bytes = packet_end - p;
	bool is_stack_bottom = false;

	do {
		struct mpls *mpls_entry = (struct mpls *)(p);

		if (p + sizeof(struct mpls) > packet_end) {
			asprintf(error, "MPLS stack entry overflows packet");
			goto error_out;
		}

		is_stack_bottom = mpls_entry_stack(mpls_entry);

		p += sizeof(struct mpls);
		mpls_header_bytes += sizeof(struct mpls);
	} while (!is_stack_bottom && p < packet_end);

	assert(mpls_header_bytes <= mpls_total_bytes);

	mpls_header = packet_append_header(packet, HEADER_MPLS,
					   mpls_header_bytes);
	if (mpls_header == NULL) {
		asprintf(error, "Too many nested headers at MPLS header");
		goto error_out;
	}
	mpls_header->total_bytes = mpls_total_bytes;

	/* Move on to the header inside the MPLS label stack. */
	assert(p <= packet_end);
	return parse_layer3_packet(packet, udp_encaps, p, packet_end, error);

error_out:
	return PACKET_BAD;
}

static int parse_layer4(struct packet *packet, u8 udp_encaps, u8 *layer4_start,
			int layer4_protocol, int layer4_bytes,
			u8 *packet_end, bool *is_inner, char **error)
{
	if (layer4_protocol == IPPROTO_SCTP) {
		*is_inner = true;	/* found inner-most layer 4 */
		return parse_sctp(packet, layer4_start, layer4_bytes,
				  packet_end, error);
	} else if (layer4_protocol == IPPROTO_TCP) {
		*is_inner = true;	/* found inner-most layer 4 */
		return parse_tcp(packet, layer4_start, layer4_bytes, packet_end,
				 error);
	} else if (layer4_protocol == IPPROTO_UDP) {
		*is_inner = true;	/* found inner-most layer 4 */
		return parse_udp(packet, udp_encaps, layer4_start, layer4_bytes,
				 packet_end, error);
	} else if (layer4_protocol == IPPROTO_UDPLITE) {
		*is_inner = true;	/* found inner-most layer 4 */
		return parse_udplite(packet, layer4_start, layer4_bytes,
				     packet_end, error);
	} else if (layer4_protocol == IPPROTO_ICMP) {
		*is_inner = true;	/* found inner-most layer 4 */
		return parse_icmpv4(packet, layer4_start, layer4_bytes,
				    packet_end, error);
	} else if (layer4_protocol == IPPROTO_ICMPV6) {
		*is_inner = true;	/* found inner-most layer 4 */
		return parse_icmpv6(packet, layer4_start, layer4_bytes,
				    packet_end, error);
	} else if (layer4_protocol == IPPROTO_GRE) {
		*is_inner = false;
		return parse_gre(packet, udp_encaps, layer4_start, layer4_bytes,
				 packet_end, error);
	} else if (layer4_protocol == IPPROTO_IPIP) {
		*is_inner = false;
		return parse_ipv4(packet, udp_encaps, layer4_start, packet_end,
				  error);
	} else if (layer4_protocol == IPPROTO_IPV6) {
		*is_inner = false;
		return parse_ipv6(packet, udp_encaps, layer4_start, packet_end,
				  error);
	}
	return PACKET_UNKNOWN_L4;
}
