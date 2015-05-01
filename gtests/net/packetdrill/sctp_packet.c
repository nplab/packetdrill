/*
 * Copyright 2015 Michael Tuexen
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
 * Author: tuexen@fh-muenster.de (Michael Tuexen)
 *
 * Implementation of module for formatting SCTP packets.
 */

#include "logging.h"
#include "sctp_packet.h"
#include "ip_packet.h"
#include "sctp.h"

/*
 * ToDo:
 * - Add support for chunk flags (fix hard coded flags for DATA chunk)
 * - Add support for user data length in DATA chunks (fix hard coded payload)
 * - Add support for parameters (fix hard coded state cookie in INIT-ACK)
 * - Add support for error causes
 */
 
struct sctp_chunk_list_item *
sctp_chunk_list_item_new(struct sctp_chunk *chunk, u32 length, u32 flags)
{
	struct sctp_chunk_list_item *item;

	item = malloc(sizeof(struct sctp_chunk_list_item));
	assert(item != NULL);
	item->next = NULL;
	item->chunk = chunk;
	item->length = length;
	item->flags = flags;
	return item;
}

struct sctp_chunk_list_item *
sctp_data_chunk_new(s64 tsn, s64 sid, s64 ssn, s64 ppid)
{
	struct sctp_chunk_list_item *item;
	struct sctp_data_chunk *chunk;
	u32 flags;
	u16 payload_len = 1000;

	flags = 0;
	chunk = malloc(sizeof(struct sctp_data_chunk) + payload_len);
	assert(chunk != NULL);
	chunk->type = SCTP_DATA_CHUNK_TYPE;
	chunk->flags = 0x03; /* FIXME */
	chunk->length = htons(sizeof(struct sctp_data_chunk) + payload_len);
	if (tsn == -1) {
		chunk->tsn = htonl(0);
		flags |= FLAG_DATA_CHUNK_TSN_NOCHECK;
	} else {
		chunk->tsn = htonl((u32)tsn);
	}
	if (sid == -1) {
		chunk->sid = htons(0);
		flags |= FLAG_DATA_CHUNK_SID_NOCHECK;
	} else {
		chunk->sid = htons((u16)sid);
	}
	if (ssn == -1) {
		chunk->ssn = htons(0);
		flags |= FLAG_DATA_CHUNK_SSN_NOCHECK;
	} else {
		chunk->ssn = htons((u16)ssn);
	}
	if (ppid == -1) {
		chunk->ppid = htons(0);
		flags |= FLAG_DATA_CHUNK_PPID_NOCHECK;
	} else {
		chunk->ppid = htons((u32)ppid);
	}
	memset(chunk->data, 0, payload_len);
	item = sctp_chunk_list_item_new((struct sctp_chunk *)chunk,
	                                (u32)sizeof(struct sctp_data_chunk) + payload_len,
	                                flags);
	return item;
}

struct sctp_chunk_list_item *
sctp_init_chunk_new(s64 tag, s64 a_rwnd, s64 os, s64 is, s64 tsn)
{
	struct sctp_chunk_list_item *item;
	struct sctp_init_chunk *chunk;
	u32 flags;

	flags = 0;
	chunk = malloc(sizeof(struct sctp_init_chunk));
	assert(chunk != NULL);
	chunk->type = SCTP_INIT_CHUNK_TYPE;
	chunk->flags = 0;
	/* FIXME */
	flags |= FLAG_CHUNK_LENGTH_NOCHECK;
	chunk->length = htons(sizeof(struct sctp_init_chunk));
	chunk->initiate_tag = htonl((u32)tag);
	if (a_rwnd == -1) {
		chunk->a_rwnd = htonl(0);
		flags |= FLAG_INIT_CHUNK_A_RWND_NOCHECK;
	} else {
		chunk->a_rwnd = htonl((u32)a_rwnd);
	}
	if (os == -1) {
		chunk->os = htons(0);
		flags |= FLAG_INIT_CHUNK_OS_NOCHECK;
	} else {
		chunk->os = htons((u16)os);
	}
	if (is == -1) {
		chunk->is = htons(0);
		flags |= FLAG_INIT_CHUNK_IS_NOCHECK;
	} else {
		chunk->is = htons((u16)is);
	}
	chunk->initial_tsn = htonl((u32)tsn);
	item = sctp_chunk_list_item_new((struct sctp_chunk *)chunk,
	                                (u32)sizeof(struct sctp_init_chunk),
	                                flags);
	return item;
}

/* FIXME: Don't fake the cookie that way... */
struct sctp_chunk_list_item *
sctp_init_ack_chunk_new(s64 tag, s64 a_rwnd, s64 os, s64 is, s64 tsn)
{
	struct sctp_chunk_list_item *item;
	struct sctp_init_ack_chunk *chunk;
	struct sctp_state_cookie_parameter state_cookie_parameter;
	u32 flags;

	flags = 0;
	chunk = malloc(sizeof(struct sctp_init_ack_chunk) + sizeof(struct sctp_state_cookie_parameter));
	assert(chunk != NULL);
	chunk->type = SCTP_INIT_ACK_CHUNK_TYPE;
	chunk->flags = 0;
	/* FIXME */
	flags |= FLAG_CHUNK_LENGTH_NOCHECK;
	chunk->length = htons(sizeof(struct sctp_init_ack_chunk) + sizeof(struct sctp_state_cookie_parameter));
	chunk->initiate_tag = htonl((u32)tag);
	if (a_rwnd == -1) {
		chunk->a_rwnd = htonl(0);
		flags |= FLAG_INIT_CHUNK_A_RWND_NOCHECK;
	} else {
		chunk->a_rwnd = htonl((u32)a_rwnd);
	}
	if (os == -1) {
		chunk->os = htons(0);
		flags |= FLAG_INIT_CHUNK_OS_NOCHECK;
	} else {
		chunk->os = htons((u16)os);
	}
	if (is == -1) {
		chunk->is = htons(0);
		flags |= FLAG_INIT_CHUNK_IS_NOCHECK;
	} else {
		chunk->is = htons((u16)is);
	}
	chunk->initial_tsn = htonl((u32)tsn);
	state_cookie_parameter.type = htons(SCTP_STATE_COOKIE_PARAMETER_TYPE);
	state_cookie_parameter.length = htons(sizeof(struct sctp_state_cookie_parameter));
	memcpy(chunk->parameter, &state_cookie_parameter, sizeof(struct sctp_state_cookie_parameter));
	item = sctp_chunk_list_item_new((struct sctp_chunk *)chunk,
	                                (u32)sizeof(struct sctp_init_ack_chunk) + sizeof(struct sctp_state_cookie_parameter),
	                                flags);
	return item;
}

struct sctp_chunk_list_item *
sctp_sack_chunk_new(s64 cum_tsn, s64 a_rwnd)
{
	struct sctp_chunk_list_item *item;
	struct sctp_sack_chunk *chunk;
	u32 flags;

	flags = 0;
	chunk = malloc(sizeof(struct sctp_sack_chunk));
	assert(chunk != NULL);
	chunk->type = SCTP_SACK_CHUNK_TYPE;
	chunk->flags = 0;
	chunk->length = htons(sizeof(struct sctp_sack_chunk));
	if (cum_tsn == -1) {
		chunk->cum_tsn = htonl(0);
		flags |= FLAG_SACK_CHUNK_CUM_TSN_NOCHECK;
	} else {
		chunk->cum_tsn = htonl((u32)cum_tsn);
	}
	if (a_rwnd == -1) {
		chunk->a_rwnd = htonl(0);
		flags |= FLAG_SACK_CHUNK_A_RWND_NOCHECK;
	} else {
		chunk->a_rwnd = htonl((u32)a_rwnd);
	}
	chunk->nr_gap_blocks = htons(0);
	chunk->nr_dup_tsns = htons(0);
	item = sctp_chunk_list_item_new((struct sctp_chunk *)chunk,
	                                (u32)sizeof(struct sctp_sack_chunk), 
	                                flags);
	return item;
}

struct sctp_chunk_list_item *
sctp_heartbeat_chunk_new(u8 flags)
{
	struct sctp_chunk_list_item *item;
	struct sctp_heartbeat_chunk *chunk;

	chunk = malloc(sizeof(struct sctp_heartbeat_chunk));
	assert(chunk != NULL);
	chunk->type = SCTP_HEARTBEAT_CHUNK_TYPE;
	chunk->flags = flags;
	chunk->length = htons(sizeof(struct sctp_heartbeat_chunk));
	item = sctp_chunk_list_item_new((struct sctp_chunk *)chunk,
	                                (u32)sizeof(struct sctp_heartbeat_chunk), 
	                                FLAG_CHUNK_LENGTH_NOCHECK | FLAG_CHUNK_VALUE_NOCHECK);
	return item;
}

struct sctp_chunk_list_item *
sctp_heartbeat_ack_chunk_new(u8 flags)
{
	struct sctp_chunk_list_item *item;
	struct sctp_heartbeat_ack_chunk *chunk;

	chunk = malloc(sizeof(struct sctp_heartbeat_ack_chunk));
	assert(chunk != NULL);
	chunk->type = SCTP_HEARTBEAT_ACK_CHUNK_TYPE;
	chunk->flags = flags;
	chunk->length = htons(sizeof(struct sctp_heartbeat_ack_chunk));
	item = sctp_chunk_list_item_new((struct sctp_chunk *)chunk,
	                                (u32)sizeof(struct sctp_heartbeat_ack_chunk), 
	                                FLAG_CHUNK_LENGTH_NOCHECK | FLAG_CHUNK_VALUE_NOCHECK);
	return item;
}

struct sctp_chunk_list_item *
sctp_abort_chunk_new(u8 flags)
{
	struct sctp_chunk_list_item *item;
	struct sctp_abort_chunk *chunk;

	chunk = malloc(sizeof(struct sctp_abort_chunk));
	assert(chunk != NULL);
	chunk->type = SCTP_ABORT_CHUNK_TYPE;
	chunk->flags = flags;
	chunk->length = htons(sizeof(struct sctp_abort_chunk));
	item = sctp_chunk_list_item_new((struct sctp_chunk *)chunk,
	                                (u32)sizeof(struct sctp_abort_chunk), 
	                                0);
	return item;
}

struct sctp_chunk_list_item *
sctp_shutdown_chunk_new(s64 cum_tsn)
{
	struct sctp_chunk_list_item *item;
	struct sctp_shutdown_chunk *chunk;
	u32 flags;

	flags = 0;
	chunk = malloc(sizeof(struct sctp_shutdown_chunk));
	assert(chunk != NULL);
	chunk->type = SCTP_SHUTDOWN_CHUNK_TYPE;
	chunk->flags = 0;
	chunk->length = htons(sizeof(struct sctp_shutdown_chunk));
	if (cum_tsn == -1) {
		chunk->cum_tsn = htonl(0);
		flags |= FLAG_SHUTDOWN_CHUNK_CUM_TSN_NOCHECK;
	} else {
		chunk->cum_tsn = htonl((u32)cum_tsn);
	}

	item = sctp_chunk_list_item_new((struct sctp_chunk *)chunk,
	                                (u32)sizeof(struct sctp_shutdown_chunk), 
	                                flags);
	return item;
}

struct sctp_chunk_list_item *
sctp_shutdown_ack_chunk_new(u8 flags)
{
	struct sctp_chunk_list_item *item;
	struct sctp_shutdown_ack_chunk *chunk;

	chunk = malloc(sizeof(struct sctp_shutdown_ack_chunk));
	assert(chunk != NULL);
	chunk->type = SCTP_SHUTDOWN_ACK_CHUNK_TYPE;
	chunk->flags = flags;
	chunk->length = htons(sizeof(struct sctp_shutdown_ack_chunk));
	item = sctp_chunk_list_item_new((struct sctp_chunk *)chunk,
	                                (u32)sizeof(struct sctp_shutdown_ack_chunk), 
	                                0);
	return item;
}

struct sctp_chunk_list_item *
sctp_error_chunk_new(u8 flags)
{
	struct sctp_chunk_list_item *item;
	struct sctp_error_chunk *chunk;

	chunk = malloc(sizeof(struct sctp_error_chunk));
	assert(chunk != NULL);
	chunk->type = SCTP_ERROR_CHUNK_TYPE;
	chunk->flags = flags;
	chunk->length = htons(sizeof(struct sctp_error_chunk));
	item = sctp_chunk_list_item_new((struct sctp_chunk *)chunk,
	                                (u32)sizeof(struct sctp_error_chunk), 
	                                FLAG_CHUNK_LENGTH_NOCHECK | FLAG_CHUNK_VALUE_NOCHECK);
	return item;
}

struct sctp_chunk_list_item *
sctp_cookie_echo_chunk_new(u8 flags)
{
	struct sctp_chunk_list_item *item;
	struct sctp_cookie_echo_chunk *chunk;

	chunk = malloc(sizeof(struct sctp_cookie_echo_chunk));
	assert(chunk != NULL);
	chunk->type = SCTP_COOKIE_ECHO_CHUNK_TYPE;
	chunk->flags = flags;
	chunk->length = htons(sizeof(struct sctp_cookie_echo_chunk));
	item = sctp_chunk_list_item_new((struct sctp_chunk *)chunk,
	                                (u32)sizeof(struct sctp_cookie_echo_chunk), 
	                                FLAG_CHUNK_LENGTH_NOCHECK | FLAG_CHUNK_VALUE_NOCHECK);
	return item;
}

struct sctp_chunk_list_item *
sctp_cookie_ack_chunk_new(u8 flags)
{
	struct sctp_chunk_list_item *item;
	struct sctp_cookie_ack_chunk *chunk;

	chunk = malloc(sizeof(struct sctp_cookie_ack_chunk));
	assert(chunk != NULL);
	chunk->type = SCTP_COOKIE_ACK_CHUNK_TYPE;
	chunk->flags = flags;
	chunk->length = htons(sizeof(struct sctp_cookie_ack_chunk));
	item = sctp_chunk_list_item_new((struct sctp_chunk *)chunk,
	                                (u32)sizeof(struct sctp_cookie_ack_chunk), 
	                                0);
	return item;
}

struct sctp_chunk_list_item *
sctp_ecne_chunk_new(s64 lowest_tsn)
{
	struct sctp_chunk_list_item *item;
	struct sctp_ecne_chunk *chunk;
	u32 flags;

	flags = 0;
	chunk = malloc(sizeof(struct sctp_ecne_chunk));
	assert(chunk != NULL);
	chunk->type = SCTP_ECNE_CHUNK_TYPE;
	chunk->flags = 0;
	chunk->length = htons(sizeof(struct sctp_ecne_chunk));
	if (lowest_tsn == -1) {
		chunk->lowest_tsn = htonl(0);
		flags |= FLAG_ECNE_CHUNK_LOWEST_TSN_NOCHECK;
	} else {
		chunk->lowest_tsn = htonl((u32)lowest_tsn);
	}

	item = sctp_chunk_list_item_new((struct sctp_chunk *)chunk,
	                                (u32)sizeof(struct sctp_ecne_chunk), 
	                                flags);
	return item;
}

struct sctp_chunk_list_item *
sctp_cwr_chunk_new(s64 lowest_tsn)
{
	struct sctp_chunk_list_item *item;
	struct sctp_cwr_chunk *chunk;
	u32 flags;

	flags = 0;
	chunk = malloc(sizeof(struct sctp_cwr_chunk));
	assert(chunk != NULL);
	chunk->type = SCTP_CWR_CHUNK_TYPE;
	chunk->flags = 0;
	chunk->length = htons(sizeof(struct sctp_cwr_chunk));
	if (lowest_tsn == -1) {
		chunk->lowest_tsn = htonl(0);
		flags |= FLAG_CWR_CHUNK_LOWEST_TSN_NOCHECK;
	} else {
		chunk->lowest_tsn = htonl((u32)lowest_tsn);
	}

	item = sctp_chunk_list_item_new((struct sctp_chunk *)chunk,
	                                (u32)sizeof(struct sctp_cwr_chunk), 
	                                flags);
	return item;
}

struct sctp_chunk_list_item *
sctp_shutdown_complete_chunk_new(u8 flags)
{
	struct sctp_chunk_list_item *item;
	struct sctp_shutdown_complete_chunk *chunk;

	chunk = malloc(sizeof(struct sctp_shutdown_complete_chunk));
	assert(chunk != NULL);
	chunk->type = SCTP_SHUTDOWN_COMPLETE_CHUNK_TYPE;
	chunk->flags = flags;
	chunk->length = htons(sizeof(struct sctp_shutdown_complete_chunk));
	item = sctp_chunk_list_item_new((struct sctp_chunk *)chunk,
	                                (u32)sizeof(struct sctp_shutdown_complete_chunk), 
	                                0);
	return item;
}

struct sctp_chunk_list *sctp_chunk_list_new(void)
{
	struct sctp_chunk_list *list;

	list = malloc(sizeof(struct sctp_chunk_list));
	assert(list != NULL);
	list->first = NULL;
	list->last = NULL;
	list->length = 0;
	return list;
}

void sctp_chunk_list_append(struct sctp_chunk_list *list,
			    struct sctp_chunk_list_item *item)
{
	assert(item->next == NULL);
	if (list->last == NULL) {
		assert(list->first == NULL);
		assert(list->length == 0);
		list->first = item;
	} else {
		assert(list->first != NULL);
		list->last->next = item;
	}
	list->last = item;
	list->length += item->length;
}

void sctp_chunk_list_free(struct sctp_chunk_list *list)
{
	struct sctp_chunk_list_item *current_item, *next_item;

	assert(list != NULL);
	current_item = list->first;
	while (current_item != NULL) {
		next_item = current_item->next;
		assert(next_item != NULL || current_item == list->last);
		assert(current_item->chunk != NULL);
		free(current_item);
		current_item = next_item;
	}
	free(list);
}

struct packet *new_sctp_packet(int address_family,
			       enum direction_t direction,
			       enum ip_ecn_t ecn,
			       struct sctp_chunk_list *list,
			       char **error)
{
	struct packet *packet;  /* the newly-allocated result packet */
	struct header *sctp_header;  /* the SCTP header info */
	struct sctp_chunk_list_item *item;
	/* Calculate lengths in bytes of all sections of the packet */
	const int ip_option_bytes = 0;
	const int ip_header_bytes = (ip_header_min_len(address_family) +
				     ip_option_bytes);
	const int sctp_header_bytes = sizeof(struct sctp_common_header);
	const int sctp_chunk_bytes = list->length;
	const int ip_bytes =
		 ip_header_bytes + sctp_header_bytes + sctp_chunk_bytes;
	bool overbook = false;

	/* Sanity-check all the various lengths */
	if (ip_option_bytes & 0x3) {
		asprintf(error, "IP options are not padded correctly "
			 "to ensure IP header is a multiple of 4 bytes: "
			 "%d excess bytes", ip_option_bytes & 0x3);
		return NULL;
	}
	assert((ip_header_bytes & 0x3) == 0);

	if (ip_bytes > MAX_SCTP_DATAGRAM_BYTES) {
		asprintf(error, "SCTP packet too large");
		return NULL;
	}

	if (direction == DIRECTION_INBOUND) {
		for (item = list->first; item != NULL; item = item->next) {
			switch (item->chunk->type) {
			case SCTP_DATA_CHUNK_TYPE:
				if (item->flags & FLAG_CHUNK_FLAGS_NOCHECK) {
					asprintf(error,
						 "chunk flags must be specified for inbound packets");
					return NULL;
				}
				if (item->flags & FLAG_CHUNK_LENGTH_NOCHECK) {
					asprintf(error,
						 "chunk length must be specified for inbound packets");
					return NULL;
				}				
				if (item->flags & FLAG_DATA_CHUNK_TSN_NOCHECK) {
					asprintf(error,
						 "TSN must be specified for inbound packets");
					return NULL;
				}
				if (item->flags & FLAG_DATA_CHUNK_SID_NOCHECK) {
					asprintf(error,
						 "SID must be specified for inbound packets");
					return NULL;
				}
				if (item->flags & FLAG_DATA_CHUNK_SSN_NOCHECK) {
					asprintf(error,
						 "SSN must be specified for inbound packets");
					return NULL;
				}
				if (item->flags & FLAG_DATA_CHUNK_PPID_NOCHECK) {
					asprintf(error,
						 "PPID must be specified for inbound packets");
					return NULL;
				}	
				break;
			case SCTP_INIT_CHUNK_TYPE:
				if (item->flags & FLAG_INIT_CHUNK_A_RWND_NOCHECK) {
					asprintf(error,
						 "A_RWND must be specified for inbound packets");
					return NULL;
				}
				if (item->flags & FLAG_INIT_CHUNK_OS_NOCHECK) {
					asprintf(error,
						 "OS must be specified for inbound packets");
					return NULL;
				}
				if (item->flags & FLAG_INIT_CHUNK_IS_NOCHECK) {
					asprintf(error,
						 "IS must be specified for inbound packets");
					return NULL;
				}
				break;
			case SCTP_INIT_ACK_CHUNK_TYPE:
				if (item->flags & FLAG_INIT_ACK_CHUNK_A_RWND_NOCHECK) {
					asprintf(error,
						 "A_RWND must be specified for inbound packets");
					return NULL;
				}
				if (item->flags & FLAG_INIT_ACK_CHUNK_OS_NOCHECK) {
					asprintf(error,
						 "OS must be specified for inbound packets");
					return NULL;
				}
				if (item->flags & FLAG_INIT_ACK_CHUNK_IS_NOCHECK) {
					asprintf(error,
						 "IS must be specified for inbound packets");
					return NULL;
				}
				break;
			case SCTP_SACK_CHUNK_TYPE:
				if (item->flags & FLAG_SACK_CHUNK_CUM_TSN_NOCHECK) {
					asprintf(error,
						 "CUM_TSN must be specified for inbound packets");
					return NULL;
				}
				if (item->flags & FLAG_SACK_CHUNK_A_RWND_NOCHECK) {
					asprintf(error,
						 "A_RWND must be specified for inbound packets");
					return NULL;
				}				
				if (item->flags & FLAG_SACK_CHUNK_GAP_BLOCKS_NOCHECK) {
					asprintf(error,
						 "GAP_BLOCKS must be specified for inbound packets");
					return NULL;
				}
				if (item->flags & FLAG_SACK_CHUNK_DUP_TSNS_NOCHECK) {
					asprintf(error,
						 "DUP_TSNS must be specified for inbound packets");
					return NULL;
				}
				break;
			case SCTP_HEARTBEAT_CHUNK_TYPE:
				break;
			case SCTP_HEARTBEAT_ACK_CHUNK_TYPE:
				break;
			case SCTP_ABORT_CHUNK_TYPE:
				if (item->flags & FLAG_CHUNK_LENGTH_NOCHECK) {
					asprintf(error,
						 "error causes must be specified for inbound packets");
					return NULL;
				}				
				break;
			case SCTP_SHUTDOWN_CHUNK_TYPE:
				if (item->flags & FLAG_SHUTDOWN_CHUNK_CUM_TSN_NOCHECK) {
					asprintf(error,
						 "TSN must be specified for inbound packets");
					return NULL;
				}
				break;
			case SCTP_SHUTDOWN_ACK_CHUNK_TYPE:
				break;
			case SCTP_ERROR_CHUNK_TYPE:
				if (item->flags & FLAG_CHUNK_LENGTH_NOCHECK) {
					asprintf(error,
						 "error causes must be specified for inbound packets");
					return NULL;
				}				
				break;
			case SCTP_COOKIE_ECHO_CHUNK_TYPE:
				overbook = true;
				break;
			case SCTP_COOKIE_ACK_CHUNK_TYPE:
				break;
			case SCTP_ECNE_CHUNK_TYPE:
				if (item->flags & FLAG_ECNE_CHUNK_LOWEST_TSN_NOCHECK) {
					asprintf(error,
						 "LOWEST_TSN must be specified for inbound packets");
					return NULL;
				}
				break;
			case SCTP_CWR_CHUNK_TYPE:
				if (item->flags & FLAG_CWR_CHUNK_LOWEST_TSN_NOCHECK) {
					asprintf(error,
						 "LOWEST_TSN must be specified for inbound packets");
					return NULL;
				}
				break;
			case SCTP_SHUTDOWN_COMPLETE_CHUNK_TYPE:
				break;
			default:
				asprintf(error, "Unknown chunk type 0x%02x", item->chunk->type);
				return NULL;
			}
		}
	}
	
	/* Allocate and zero out a packet object of the desired size */
	packet = packet_new(overbook ? MAX_SCTP_DATAGRAM_BYTES : ip_bytes);
	memset(packet->buffer, 0, overbook ? MAX_SCTP_DATAGRAM_BYTES : ip_bytes);

	packet->direction = direction;
	packet->flags = 0;
	packet->ecn = ecn;

	/* Set IP header fields */
	set_packet_ip_header(packet, address_family, ip_bytes, ecn,
			     IPPROTO_SCTP);

	sctp_header = packet_append_header(packet, HEADER_SCTP, sctp_header_bytes);
	sctp_header->total_bytes = sctp_header_bytes + sctp_chunk_bytes;

	/* Find the start of the SCTP common header of the packet */
	packet->sctp = (struct sctp_common_header *) (ip_start(packet) + ip_header_bytes);
	u8 *sctp_chunk_start = (u8 *) (packet->sctp + 1);

	/* Set SCTP header fields */
	packet->sctp->src_port = htons(0);
	packet->sctp->dst_port = htons(0);
	packet->sctp->v_tag = htonl(0);
	packet->sctp->crc32c = htonl(0);

	for (item = list->first; item != NULL; item = item->next) {
		DEBUGP("Copy in a chunk of length %d\n", item->length);
		memcpy(sctp_chunk_start, item->chunk, item->length);
		DEBUGP("Old location: %p\n", (void *)item->chunk);
		free(item->chunk);
		item->chunk = (struct sctp_chunk *)sctp_chunk_start;
		DEBUGP("New location: %p\n", (void *)item->chunk);
		sctp_chunk_start += item->length;
	}
	free(packet->chunk_list);
	packet->chunk_list = list;
	packet->ip_bytes = ip_bytes;
	return packet;
}
