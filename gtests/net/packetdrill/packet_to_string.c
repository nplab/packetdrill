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
 * Implementation for generating human-readable representations of IP
 * packets.
 */

#include "packet_to_string.h"

#include <stdlib.h>
#include "socket.h"
#include "sctp_iterator.h"
#include "sctp_chunk_to_string.h"
#include "tcp_options_to_string.h"

static void endpoints_to_string(FILE *s, const struct packet *packet)
{
	char src_string[ADDR_STR_LEN];
	char dst_string[ADDR_STR_LEN];
	struct tuple tuple;

	get_packet_tuple(packet, &tuple);

	fprintf(s, "%s:%u > %s:%u",
		ip_to_string(&tuple.src.ip, src_string), ntohs(tuple.src.port),
		ip_to_string(&tuple.dst.ip, dst_string), ntohs(tuple.dst.port));
}

static void packet_buffer_to_string(FILE *s, struct packet *packet)
{
	char *hex = NULL;
	hex_dump(packet->buffer, packet_end(packet) - packet->buffer, &hex);
	fputc('\n', s);
	fprintf(s, "%s", hex);
	free(hex);
}

static int ipv4_header_to_string(FILE *s, struct packet *packet, int layer,
				 enum dump_format_t format, char **error)
{
	char src_string[ADDR_STR_LEN];
	char dst_string[ADDR_STR_LEN];
	struct ip_address src_ip, dst_ip;
	const struct ipv4 *ipv4 = packet->headers[layer].h.ipv4;

	ip_from_ipv4(&ipv4->src_ip, &src_ip);
	ip_from_ipv4(&ipv4->dst_ip, &dst_ip);

	fprintf(s, "ipv4 %s > %s: ",
		ip_to_string(&src_ip, src_string),
		ip_to_string(&dst_ip, dst_string));

	return STATUS_OK;
}

static int ipv6_header_to_string(FILE *s, struct packet *packet, int layer,
				 enum dump_format_t format, char **error)
{
	char src_string[ADDR_STR_LEN];
	char dst_string[ADDR_STR_LEN];
	struct ip_address src_ip, dst_ip;
	const struct ipv6 *ipv6 = packet->headers[layer].h.ipv6;

	ip_from_ipv6(&ipv6->src_ip, &src_ip);
	ip_from_ipv6(&ipv6->dst_ip, &dst_ip);

	fprintf(s, "ipv6 %s > %s: ",
		ip_to_string(&src_ip, src_string),
		ip_to_string(&dst_ip, dst_string));

	return STATUS_OK;
}

static int gre_header_to_string(FILE *s, struct packet *packet, int layer,
				enum dump_format_t format, char **error)
{
	fputs("gre: ", s);

	return STATUS_OK;
}

static int mpls_header_to_string(FILE *s, struct packet *packet, int layer,
				 enum dump_format_t format, char **error)
{
	struct header *header = &packet->headers[layer];
	int num_entries = header->header_bytes / sizeof(struct mpls);
	int i = 0;

	fputs("mpls", s);

	for (i = 0; i < num_entries; ++i) {
		const struct mpls *mpls = header->h.mpls + i;

		fprintf(s, " (label %u, tc %u,%s ttl %u)",
			mpls_entry_label(mpls),
			mpls_entry_tc(mpls),
			mpls_entry_stack(mpls) ? " [S]," : "",
			mpls_entry_ttl(mpls));
	}

	fprintf(s, ": ");
	return STATUS_OK;
}

static int sctp_packet_to_string(FILE *s, struct packet *packet, int i,
				 enum dump_format_t format, char **error)
{
	struct sctp_chunks_iterator iter;
	struct sctp_chunk *chunk;
	u16 index;
	int result = STATUS_OK;       /* return value */

	assert(*error == NULL);
	if ((format == DUMP_FULL) || (format == DUMP_VERBOSE)) {
		endpoints_to_string(s, packet);
		fputc(' ', s);
	}

	fputs("sctp", s);
	if (packet->flags & FLAGS_SCTP_BAD_CRC32C) {
		fputs("(bad_crc32c)", s);
	}

	if (packet->headers[i + 1].type == HEADER_UDP) {
		struct udp *udp = packet->headers[i + 1].h.udp;

		fprintf(s, "/udp(%u > %u)",
			ntohs(udp->src_port), ntohs(udp->dst_port));
	}
	fputc(':', s);

	index = 0;
	for (chunk = sctp_chunks_begin(packet, &iter, error);
	     chunk != NULL;
	     chunk = sctp_chunks_next(&iter, error)) {
		if (index == 0)
			fputc(' ', s);
		else
			fputs("; ", s);
		if (*error != NULL) {
			fputs(*error, s);
			free(*error);
			*error = NULL;
			break;
		}
		result = sctp_chunk_to_string(s, chunk, error);
		assert(result != STATUS_OK  || *error == NULL);
		if (result != STATUS_OK)
			break;
		index++;
	}
	if (*error != NULL)
		result = STATUS_ERR;

	if (format == DUMP_VERBOSE)
		packet_buffer_to_string(s, packet);

	return result;
}

/* Print a string representation of the TCP packet:
 *  direction opt_ip_info flags seq ack window tcp_options
 */
static int tcp_packet_to_string(FILE *s, struct packet *packet, int i,
				enum dump_format_t format, char **error)
{
	int result = STATUS_OK;       /* return value */
	int ace = 0;

	if ((format == DUMP_FULL) || (format == DUMP_VERBOSE)) {
		endpoints_to_string(s, packet);
		fputc(' ', s);
	}

	/* We print flags in the same order as tcpdump 4.1.1. */
	if (packet->tcp->fin)
		fputc('F', s);
	if (packet->tcp->syn)
		fputc('S', s);
	if (packet->tcp->rst)
		fputc('R', s);
	if (packet->tcp->psh)
		fputc('P', s);
	if (packet->tcp->ack)
		fputc('.', s);
	if (packet->tcp->urg)
		fputc('U', s);
	if (packet->flags & FLAG_PARSE_ACE) {
		if (packet->tcp->ece)
			ace |= 1;
		if (packet->tcp->cwr)
			ace |= 2;
		if (packet->tcp->ae)
			ace |= 4;
		fputc('0' + ace, s);
	} else {
		if (packet->tcp->ece)
			fputc('E', s);   /* ECN *E*cho sent (ECN) */
		if (packet->tcp->cwr)
			fputc('W', s);   /* Congestion *W*indow reduced (ECN) */
		if (packet->tcp->ae)
			fputc('A', s);   /* *A*ccurate ECN */
	}

	fprintf(s, " %u:%u(%u)",
		ntohl(packet->tcp->seq),
		ntohl(packet->tcp->seq) + packet_payload_len(packet),
		packet_payload_len(packet));

	if (packet->tcp->ack)
		fprintf(s, " ack %u", ntohl(packet->tcp->ack_seq));

	if (!(packet->flags & FLAG_WIN_NOCHECK))
		fprintf(s, " win %u", ntohs(packet->tcp->window));

	if (packet->tcp->urg)
		fprintf(s, " urg %u", ntohs(packet->tcp->urg_ptr));

	if (packet_tcp_options_len(packet) > 0) {
		char *tcp_options = NULL;
		if (tcp_options_to_string(packet, &tcp_options, error))
			result = STATUS_ERR;
		else
			fprintf(s, " <%s>", tcp_options);
		free(tcp_options);
	}

	if (packet->headers[i + 1].type == HEADER_UDP) {
		struct udp *udp = packet->headers[i + 1].h.udp;

		fprintf(s, "/udp(%u > %u)",
			ntohs(udp->src_port), ntohs(udp->dst_port));
	}

	if (format == DUMP_VERBOSE)
		packet_buffer_to_string(s, packet);

	return result;
}

static int udp_packet_to_string(FILE *s, struct packet *packet,
				enum dump_format_t format, char **error)
{
	int result = STATUS_OK;       /* return value */

	if ((format == DUMP_FULL) || (format == DUMP_VERBOSE)) {
		endpoints_to_string(s, packet);
		fputc(' ', s);
	}

	fprintf(s, "udp (%u)", packet_payload_len(packet));

	if (format == DUMP_VERBOSE)
		packet_buffer_to_string(s, packet);

	return result;
}

static int udplite_packet_to_string(FILE *s, struct packet *packet,
				    enum dump_format_t format, char **error)
{
	int result = STATUS_OK;       /* return value */

	if ((format == DUMP_FULL) || (format == DUMP_VERBOSE)) {
		endpoints_to_string(s, packet);
		fputc(' ', s);
	}

	fprintf(s, "udplite (%u, %u)",
		packet_payload_len(packet), ntohs(packet->udplite->cov));

	if (format == DUMP_VERBOSE)
		packet_buffer_to_string(s, packet);

	return result;
}

static int icmpv4_packet_to_string(FILE *s, struct packet *packet,
				   enum dump_format_t format, char **error)
{
	fputs("icmpv4", s);
	/* TODO(ncardwell): print type, code; use tables from icmp_packet.c */
	return STATUS_OK;
}

static int icmpv6_packet_to_string(FILE *s, struct packet *packet,
				   enum dump_format_t format, char **error)
{
	fputs("icmpv6", s);
	/* TODO(ncardwell): print type, code; use tables from icmp_packet.c */
	return STATUS_OK;
}

typedef int (*header_to_string_func)(FILE *s, struct packet *packet, int layer,
				     enum dump_format_t format, char **error);

static int encap_header_to_string(FILE *s, struct packet *packet, int layer,
				  enum dump_format_t format, char **error)
{
	header_to_string_func printers[HEADER_NUM_TYPES] = {
		[HEADER_IPV4]	= ipv4_header_to_string,
		[HEADER_IPV6]	= ipv6_header_to_string,
		[HEADER_GRE]	= gre_header_to_string,
		[HEADER_MPLS]	= mpls_header_to_string,
	};
	header_to_string_func printer = NULL;
	enum header_t type = packet->headers[layer].type;

	assert(type > HEADER_NONE);
	assert(type < HEADER_NUM_TYPES);
	printer = printers[type];
	assert(printer != NULL);
	return printer(s, packet, layer, format, error);
}

int packet_to_string(struct packet *packet,
		     enum dump_format_t format,
		     char **ascii_string, char **error)
{
	assert(packet != NULL);
	int result = STATUS_ERR;       /* return value */
	size_t size = 0;
	FILE *s = open_memstream(ascii_string, &size);  /* output string */
	int i;
	int header_count = packet_header_count(packet);
	int limit;

	if (packet->ip_src_index != 0 || packet->ip_dst_index != 0) {
		if (packet->ip_src_index == packet->ip_dst_index)
			fprintf(s, "[%d] ", packet->ip_src_index);
		else
			fprintf(s, "[%d>%d] ", packet->ip_src_index, packet->ip_dst_index);
	}

	/* Print any encapsulation headers preceding layer 3 and 4 headers. */
	if (packet->flags & FLAGS_UDP_ENCAPSULATED)
		limit = header_count - 3;
	else
		limit = header_count - 2;
	for (i = 0; i < limit; ++i) {
		if (packet->headers[i].type == HEADER_NONE)
			break;
		if (encap_header_to_string(s, packet, i, format, error))
			goto out;
	}

	if ((packet->ipv4 == NULL) && (packet->ipv6 == NULL)) {
		fputs("[NO IP HEADER]", s);
	} else {
		if (packet->sctp != NULL) {
			if (sctp_packet_to_string(s, packet, limit, format,
						  error))
				goto out;
		} else if (packet->tcp != NULL) {
			if (tcp_packet_to_string(s, packet, limit, format,
						 error))
				goto out;
		} else if (packet->udp != NULL) {
			if (udp_packet_to_string(s, packet, format, error))
				goto out;
		} else if (packet->udplite != NULL) {
			if (udplite_packet_to_string(s, packet, format, error))
				goto out;
		} else if (packet->icmpv4 != NULL) {
			if (icmpv4_packet_to_string(s, packet, format, error))
				goto out;
		} else if (packet->icmpv6 != NULL) {
			if (icmpv6_packet_to_string(s, packet, format, error))
				goto out;
		} else {
			fputs("[No SCTP, TCP, UDP, UDPLite or ICMP header]", s);
		}
	}

	result = STATUS_OK;

out:
	fclose(s);
	return result;
}
