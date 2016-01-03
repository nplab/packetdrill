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
 * - Add support for error causes
 */

struct sctp_byte_list *
sctp_byte_list_new(void)
{
	struct sctp_byte_list *list;

	list = malloc(sizeof(struct sctp_byte_list));
	assert(list != NULL);
	list->first = NULL;
	list->last = NULL;
	list->nr_entries = 0;
	return list;
}

void
sctp_byte_list_append(struct sctp_byte_list *list,
                      struct sctp_byte_list_item *item)
{
	assert(item->next == NULL);
	if (list->last == NULL) {
		assert(list->first == NULL);
		assert(list->nr_entries == 0);
		list->first = item;
	} else {
		assert(list->first != NULL);
		list->last->next = item;
	}
	list->last = item;
	list->nr_entries++;
}

void
sctp_byte_list_free(struct sctp_byte_list *list)
{
	struct sctp_byte_list_item *current_item, *next_item;

	if (list == NULL) {
		return;
	}
	current_item = list->first;
	while (current_item != NULL) {
		assert(list->nr_entries > 0);
		next_item = current_item->next;
		assert(next_item != NULL || current_item == list->last);
		free(current_item);
		current_item = next_item;
		list->nr_entries--;
	}
	assert(list->nr_entries == 0);
	free(list);
}

struct sctp_byte_list_item *
sctp_byte_list_item_new(u8 byte)
{
	struct sctp_byte_list_item *item;

	item = malloc(sizeof(struct sctp_byte_list_item));
	assert(item != NULL);
	item->next = NULL;
	item->byte = byte;
	return item;
}

struct sctp_sack_block_list *
sctp_sack_block_list_new(void)
{
	struct sctp_sack_block_list *list;

	list = malloc(sizeof(struct sctp_sack_block_list));
	assert(list != NULL);
	list->first = NULL;
	list->last = NULL;
	list->nr_entries = 0;
	return list;
}

void
sctp_sack_block_list_append(struct sctp_sack_block_list *list,
                            struct sctp_sack_block_list_item *item)
{
	assert(item->next == NULL);
	if (list->last == NULL) {
		assert(list->first == NULL);
		assert(list->nr_entries == 0);
		list->first = item;
	} else {
		assert(list->first != NULL);
		list->last->next = item;
	}
	list->last = item;
	list->nr_entries++;
}

void
sctp_sack_block_list_free(struct sctp_sack_block_list *list)
{
	struct sctp_sack_block_list_item *current_item, *next_item;

	if (list == NULL) {
		return;
	}
	current_item = list->first;
	while (current_item != NULL) {
		assert(list->nr_entries > 0);
		next_item = current_item->next;
		assert(next_item != NULL || current_item == list->last);
		free(current_item);
		current_item = next_item;
		list->nr_entries--;
	}
	assert(list->nr_entries == 0);
	free(list);
}

struct sctp_sack_block_list_item *
sctp_sack_block_list_item_gap_new(u16 start, u16 end)
{
	struct sctp_sack_block_list_item *item;

	item = malloc(sizeof(struct sctp_sack_block_list_item));
	assert(item != NULL);
	item->next = NULL;
	item->block.gap.start = start;
	item->block.gap.end = end;
	return item;
}

struct sctp_sack_block_list_item *
sctp_sack_block_list_item_dup_new(u32 tsn)
{
	struct sctp_sack_block_list_item *item;

	item = malloc(sizeof(struct sctp_sack_block_list_item));
	assert(item != NULL);
	item->next = NULL;
	item->block.tsn = tsn;
	return item;
}

struct sctp_address_type_list *
sctp_address_type_list_new(void)
{
	struct sctp_address_type_list *list;

	list = malloc(sizeof(struct sctp_address_type_list));
	assert(list != NULL);
	list->first = NULL;
	list->last = NULL;
	list->nr_entries = 0;
	return list;
}

void
sctp_address_type_list_append(struct sctp_address_type_list *list,
			      struct sctp_address_type_list_item *item)
{
	assert(item->next == NULL);
	if (list->last == NULL) {
		assert(list->first == NULL);
		assert(list->nr_entries == 0);
		list->first = item;
	} else {
		assert(list->first != NULL);
		list->last->next = item;
	}
	list->last = item;
	list->nr_entries++;
}

void
sctp_address_type_list_free(struct sctp_address_type_list *list)
{
	struct sctp_address_type_list_item *current_item, *next_item;

	if (list == NULL) {
		return;
	}
	current_item = list->first;
	while (current_item != NULL) {
		assert(list->nr_entries > 0);
		next_item = current_item->next;
		assert(next_item != NULL || current_item == list->last);
		free(current_item);
		current_item = next_item;
		list->nr_entries--;
	}
	assert(list->nr_entries == 0);
	free(list);
}

struct sctp_address_type_list_item *
sctp_address_type_list_item_new(u16 address_type)
{
	struct sctp_address_type_list_item *item;

	item = malloc(sizeof(struct sctp_address_type_list_item));
	assert(item != NULL);
	item->next = NULL;
	item->address_type = address_type;
	return item;
}

struct sctp_parameter_type_list *
sctp_parameter_type_list_new(void)
{
	struct sctp_parameter_type_list *list;

	list = malloc(sizeof(struct sctp_parameter_type_list));
	assert(list != NULL);
	list->first = NULL;
	list->last = NULL;
	list->nr_entries = 0;
	return list;
}

void
sctp_parameter_type_list_append(struct sctp_parameter_type_list *list,
			        struct sctp_parameter_type_list_item *item)
{
	assert(item->next == NULL);
	if (list->last == NULL) {
		assert(list->first == NULL);
		assert(list->nr_entries == 0);
		list->first = item;
	} else {
		assert(list->first != NULL);
		list->last->next = item;
	}
	list->last = item;
	list->nr_entries++;
}

void
sctp_parameter_type_list_free(struct sctp_parameter_type_list *list)
{
	struct sctp_parameter_type_list_item *current_item, *next_item;

	if (list == NULL) {
		return;
	}
	current_item = list->first;
	while (current_item != NULL) {
		assert(list->nr_entries > 0);
		next_item = current_item->next;
		assert(next_item != NULL || current_item == list->last);
		free(current_item);
		current_item = next_item;
		list->nr_entries--;
	}
	assert(list->nr_entries == 0);
	free(list);
}

struct sctp_parameter_type_list_item *
sctp_parameter_type_list_item_new(u16 parameter_type)
{
	struct sctp_parameter_type_list_item *item;

	item = malloc(sizeof(struct sctp_parameter_type_list_item));
	assert(item != NULL);
	item->next = NULL;
	item->parameter_type = parameter_type;
	return item;
}

struct sctp_chunk_list_item *
sctp_chunk_list_item_new(struct sctp_chunk *chunk, u32 length, u32 flags,
                         struct sctp_parameter_list *parameter_list,
                         struct sctp_cause_list *cause_list)
{
	struct sctp_chunk_list_item *item;

	item = malloc(sizeof(struct sctp_chunk_list_item));
	assert(item != NULL);
	item->next = NULL;
	item->chunk = chunk;
	item->parameter_list = parameter_list;
	item->cause_list = cause_list;
	item->length = length;
	item->flags = flags;
	return item;
}

struct sctp_chunk_list_item *
sctp_generic_chunk_new(s64 type, s64 flgs, s64 len,
                       struct sctp_byte_list *bytes)
{
	struct sctp_chunk *chunk;
	struct sctp_byte_list_item *item;
	u32 flags;
	u16 length, padding_length, i;

	flags = 0;
	if (bytes == NULL) {
		flags |= FLAG_CHUNK_VALUE_NOCHECK;
	}
	if (len == -1) {
		flags |= FLAG_CHUNK_LENGTH_NOCHECK;
		length = (u16)sizeof(struct sctp_chunk);
	} else {
		length = (u16)len;
	}
	padding_length = length % 4;
	if (padding_length > 0) {
		padding_length = 4 - padding_length;
	}
	chunk = malloc(length + padding_length);
	assert(chunk != NULL);
	if (type == -1) {
		chunk->type = 0;
		flags |= FLAG_CHUNK_TYPE_NOCHECK;
	} else {
		chunk->type = (u8)type;
	}
	if (flgs == -1) {
		chunk->flags = 0;
		flags |= FLAG_CHUNK_FLAGS_NOCHECK;
	} else {
		 chunk->flags = (u8)flgs;
	}
	chunk->length = htons(length);
	if (bytes != NULL) {
		for (i = 0, item = bytes->first;
		     item != NULL;
		     i++, item = item->next) {
			chunk->value[i] = item->byte;
		}
	} else {
		memset(chunk->value, 0, length - sizeof(struct sctp_chunk));
	}
	memset(chunk->value + (length - sizeof(struct sctp_chunk)),
	       0, padding_length);
	return sctp_chunk_list_item_new(chunk,
	                                length + padding_length,
	                                flags,
	                                sctp_parameter_list_new(),
	                                sctp_cause_list_new());
}

struct sctp_chunk_list_item *
sctp_data_chunk_new(s64 flgs, s64 len, s64 tsn, s64 sid, s64 ssn, s64 ppid)
{
	struct sctp_data_chunk *chunk;
	u32 flags;
	u16 length, padding_length;

	flags = 0;
	if (len == -1) {
		length = (u16)sizeof(struct sctp_data_chunk);
	} else {
		length = (u16)len;
	}
	padding_length = length % 4;
	if (padding_length > 0) {
		padding_length = 4 - padding_length;
	}
	chunk = malloc(length + padding_length);
	assert(chunk != NULL);
	chunk->type = SCTP_DATA_CHUNK_TYPE;
	if (flgs == -1) {
		chunk->flags = 0;
		flags |= FLAG_CHUNK_FLAGS_NOCHECK;
	} else {
		 chunk->flags = (u8)flgs;
	}
	chunk->length = htons(length);
	if (len == -1) {
		flags |= FLAG_CHUNK_LENGTH_NOCHECK;
		flags |= FLAG_CHUNK_VALUE_NOCHECK;
	}
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
		chunk->ppid = htonl(0);
		flags |= FLAG_DATA_CHUNK_PPID_NOCHECK;
	} else {
		chunk->ppid = htonl((u32)ppid);
	}
	memset(chunk->data, 0,
	       length + padding_length - sizeof(struct sctp_data_chunk));
	return sctp_chunk_list_item_new((struct sctp_chunk *)chunk,
	                                length + padding_length, flags,
	                                sctp_parameter_list_new(),
	                                sctp_cause_list_new());
}

struct sctp_chunk_list_item *
sctp_init_chunk_new(s64 flgs, s64 tag, s64 a_rwnd, s64 os, s64 is, s64 tsn,
                    struct sctp_parameter_list *list)
{
	struct sctp_init_chunk *chunk;
	struct sctp_parameter_list_item *item;
	u32 flags;
	u16 offset, chunk_length, chunk_padding_length, parameter_padding_length;

	flags = 0;
	chunk_length = sizeof(struct sctp_init_chunk);
	if (list != NULL) {
		chunk_length += list->length;
	} else {
		flags |= FLAG_CHUNK_LENGTH_NOCHECK;
		flags |= FLAG_INIT_CHUNK_OPT_PARAM_NOCHECK;
		list = sctp_parameter_list_new();
	}
	chunk_padding_length = chunk_length % 4;
	if (chunk_padding_length > 0) {
		chunk_padding_length = 4 - chunk_padding_length;
	}
	chunk = malloc(chunk_length + chunk_padding_length);
	assert(chunk != NULL);
	chunk->type = SCTP_INIT_CHUNK_TYPE;
	if (flgs == -1) {
		chunk->flags = 0;
		flags |= FLAG_CHUNK_FLAGS_NOCHECK;
	} else {
		chunk->flags = (u8)flgs;
	}
	chunk->length = htons(chunk_length);
	if (tag == -1) {
		chunk->initiate_tag = htonl(0);
		flags |= FLAG_INIT_CHUNK_TAG_NOCHECK;
	} else {
		chunk->initiate_tag = htonl((u32)tag);
	}
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
	if (tsn == -1) {
		chunk->initial_tsn = htonl(0);
		flags |= FLAG_INIT_CHUNK_TSN_NOCHECK;
	} else {
		chunk->initial_tsn = htonl((u32)tsn);
	}
	offset = 0;
	for (item = list->first; item != NULL; item = item->next) {
		parameter_padding_length = item->length % 4;
		if (parameter_padding_length > 0) {
			parameter_padding_length = 4 - parameter_padding_length;
		}
		memcpy(chunk->parameter + offset,
		       item->parameter,
		       item->length + parameter_padding_length);
		free(item->parameter);
		item->parameter = (struct sctp_parameter *)(chunk->parameter + offset);
		if (item->flags & FLAG_PARAMETER_LENGTH_NOCHECK) {
			flags |= FLAG_CHUNK_LENGTH_NOCHECK;
		}
		offset += item->length + parameter_padding_length;
	}
	return sctp_chunk_list_item_new((struct sctp_chunk *)chunk,
	                                chunk_length + chunk_padding_length,
	                                flags, list, sctp_cause_list_new());
}

struct sctp_chunk_list_item *
sctp_init_ack_chunk_new(s64 flgs, s64 tag, s64 a_rwnd, s64 os, s64 is, s64 tsn,
                        struct sctp_parameter_list *list)
{
	struct sctp_init_ack_chunk *chunk;
	struct sctp_parameter_list_item *item;
	u32 flags;
	u16 offset, chunk_length, chunk_padding_length, parameter_padding_length;

	flags = 0;
	chunk_length = sizeof(struct sctp_init_ack_chunk);
	if (list != NULL) {
		chunk_length += list->length;
	} else {
		flags |= FLAG_CHUNK_LENGTH_NOCHECK;
		flags |= FLAG_INIT_ACK_CHUNK_OPT_PARAM_NOCHECK;
		list = sctp_parameter_list_new();
	}
	chunk_padding_length = chunk_length % 4;
	if (chunk_padding_length > 0) {
		chunk_padding_length = 4 - chunk_padding_length;
	}
	chunk = malloc(chunk_length + chunk_padding_length);
	assert(chunk != NULL);
	chunk->type = SCTP_INIT_ACK_CHUNK_TYPE;
	if (flgs == -1) {
		chunk->flags = 0;
		flags |= FLAG_CHUNK_FLAGS_NOCHECK;
	} else {
		chunk->flags = (u8)flgs;
	}
	chunk->length = htons(chunk_length);
	if (tag == -1) {
		chunk->initiate_tag = htonl(0);
		flags |= FLAG_INIT_ACK_CHUNK_TAG_NOCHECK;
	} else {
		chunk->initiate_tag = htonl((u32)tag);
	}
	if (a_rwnd == -1) {
		chunk->a_rwnd = htonl(0);
		flags |= FLAG_INIT_ACK_CHUNK_A_RWND_NOCHECK;
	} else {
		chunk->a_rwnd = htonl((u32)a_rwnd);
	}
	if (os == -1) {
		chunk->os = htons(0);
		flags |= FLAG_INIT_ACK_CHUNK_OS_NOCHECK;
	} else {
		chunk->os = htons((u16)os);
	}
	if (is == -1) {
		chunk->is = htons(0);
		flags |= FLAG_INIT_ACK_CHUNK_IS_NOCHECK;
	} else {
		chunk->is = htons((u16)is);
	}
	if (tsn == -1) {
		chunk->initial_tsn = htonl(0);
		flags |= FLAG_INIT_ACK_CHUNK_TSN_NOCHECK;
	} else {
		chunk->initial_tsn = htonl((u32)tsn);
	}
	offset = 0;
	for (item = list->first; item != NULL; item = item->next) {
		parameter_padding_length = item->length % 4;
		if (parameter_padding_length > 0) {
			parameter_padding_length = 4 - parameter_padding_length;
		}
		memcpy(chunk->parameter + offset,
		       item->parameter,
		       item->length + parameter_padding_length);
		free(item->parameter);
		item->parameter = (struct sctp_parameter *)(chunk->parameter + offset);
		if (item->flags & FLAG_PARAMETER_LENGTH_NOCHECK) {
			flags |= FLAG_CHUNK_LENGTH_NOCHECK;
		}
		offset += item->length + parameter_padding_length;
	}
	return sctp_chunk_list_item_new((struct sctp_chunk *)chunk,
	                                chunk_length + chunk_padding_length,
	                                flags, list, sctp_cause_list_new());
}

struct sctp_chunk_list_item *
sctp_sack_chunk_new(s64 flgs, s64 cum_tsn, s64 a_rwnd,
                    struct sctp_sack_block_list *gaps,
                    struct sctp_sack_block_list *dups)
{
	struct sctp_sack_chunk *chunk;
	struct sctp_sack_block_list_item *item;
	u32 flags;
	u32 length;
	u16 i, nr_gaps, nr_dups;

	flags = 0;
	length = sizeof(struct sctp_sack_chunk);
	if (gaps == NULL) {
		nr_gaps = 0;
		flags |= FLAG_CHUNK_LENGTH_NOCHECK;
		flags |= FLAG_SACK_CHUNK_GAP_BLOCKS_NOCHECK;
	} else {
		nr_gaps = gaps->nr_entries;
		length += nr_gaps * sizeof(union sctp_sack_block);
	}
	if (dups == NULL) {
		nr_dups = 0;
		flags |= FLAG_CHUNK_LENGTH_NOCHECK;
		flags |= FLAG_SACK_CHUNK_DUP_TSNS_NOCHECK;
	} else {
		nr_dups = dups->nr_entries;
		length += nr_dups * sizeof(union sctp_sack_block);
	}
	assert(is_valid_u16(length));
	assert(length % 4 == 0);
	chunk = malloc(length);
	assert(chunk != NULL);
	chunk->type = SCTP_SACK_CHUNK_TYPE;
	if (flgs == -1) {
		chunk->flags = 0;
		flags |= FLAG_CHUNK_FLAGS_NOCHECK;
	} else {
		chunk->flags = (u8)flgs;
	}
	chunk->length = htons(length);
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
	chunk->nr_gap_blocks = htons(nr_gaps);
	chunk->nr_dup_tsns = htons(nr_dups);

	if (gaps != NULL) {
		for (i = 0, item = gaps->first;
		     (i < nr_gaps) && (item != NULL);
		     i++, item = item->next) {
			chunk->block[i].gap.start = htons(item->block.gap.start);
			chunk->block[i].gap.end = htons(item->block.gap.end);
		}
		assert((i == nr_gaps) && (item == NULL));
	}
	if (dups != NULL) {
		for (i = 0, item = dups->first;
		     (i < nr_dups) && (item != NULL);
		     i++, item = item->next) {
			chunk->block[i + nr_gaps].tsn= htonl(item->block.tsn);
		}
		assert((i == nr_dups) && (item == NULL));
	}
	return sctp_chunk_list_item_new((struct sctp_chunk *)chunk,
	                                length, flags,
	                                sctp_parameter_list_new(),
	                                sctp_cause_list_new());
}

struct sctp_chunk_list_item *
sctp_heartbeat_chunk_new(s64 flgs, struct sctp_parameter_list_item *info)
{
	struct sctp_heartbeat_chunk *chunk;
	u32 flags;
	u16 chunk_length, padding_length;

	flags = 0;
	assert(info == NULL ||
	       info->length + sizeof(struct sctp_heartbeat_chunk) <= MAX_SCTP_CHUNK_BYTES);
	chunk_length = sizeof(struct sctp_heartbeat_chunk);
	if (info != NULL) {
		chunk_length += info->length;
		if (info->flags & FLAG_PARAMETER_LENGTH_NOCHECK) {
			flags |= FLAG_CHUNK_LENGTH_NOCHECK;
		}
		if (info->flags & FLAG_PARAMETER_VALUE_NOCHECK) {
			flags |= FLAG_CHUNK_VALUE_NOCHECK;
		}
	} else {
		flags |= FLAG_CHUNK_LENGTH_NOCHECK;
		flags |= FLAG_CHUNK_VALUE_NOCHECK;
	}
	padding_length = chunk_length % 4;
	if (padding_length > 0) {
		padding_length = 4 - padding_length;
	}
	chunk = malloc(chunk_length + padding_length);
	assert(chunk != NULL);
	chunk->type = SCTP_HEARTBEAT_CHUNK_TYPE;
	if (flgs == -1) {
		chunk->flags = 0;
		flags |= FLAG_CHUNK_FLAGS_NOCHECK;
	} else {
		chunk->flags = (u8)flgs;
	}
	chunk->length = htons(chunk_length);
	memcpy(chunk->value, info->parameter, info->length);
	memset(chunk->value + info->length, 0, padding_length);
	free(info->parameter);
	free(info);
	return sctp_chunk_list_item_new((struct sctp_chunk *)chunk,
	                                chunk_length + padding_length,
	                                flags, sctp_parameter_list_new(),
	                                sctp_cause_list_new());
}

struct sctp_chunk_list_item *
sctp_heartbeat_ack_chunk_new(s64 flgs, struct sctp_parameter_list_item *info)
{
	struct sctp_heartbeat_ack_chunk *chunk;
	u32 flags;
	u16 chunk_length, padding_length;

	flags = 0;
	assert(info == NULL ||
	       info->length + sizeof(struct sctp_heartbeat_ack_chunk) <= MAX_SCTP_CHUNK_BYTES);
	chunk_length = sizeof(struct sctp_heartbeat_ack_chunk);
	if (info != NULL) {
		chunk_length += info->length;
		if (info->flags & FLAG_PARAMETER_LENGTH_NOCHECK) {
			flags |= FLAG_CHUNK_LENGTH_NOCHECK;
		}
		if (info->flags & FLAG_PARAMETER_VALUE_NOCHECK) {
			flags |= FLAG_CHUNK_VALUE_NOCHECK;
		}
	} else {
		flags |= FLAG_CHUNK_LENGTH_NOCHECK;
		flags |= FLAG_CHUNK_VALUE_NOCHECK;
	}
	padding_length = chunk_length % 4;
	if (padding_length > 0) {
		padding_length = 4 - padding_length;
	}
	chunk = malloc(chunk_length + padding_length);
	assert(chunk != NULL);
	chunk->type = SCTP_HEARTBEAT_ACK_CHUNK_TYPE;
	if (flgs == -1) {
		chunk->flags = 0;
		flags |= FLAG_CHUNK_FLAGS_NOCHECK;
	} else {
		chunk->flags = (u8)flgs;
	}
	chunk->length = htons(chunk_length);
	memcpy(chunk->value, info->parameter, info->length);
	memset(chunk->value + info->length, 0, padding_length);
	free(info->parameter);
	free(info);
	return sctp_chunk_list_item_new((struct sctp_chunk *)chunk,
	                                chunk_length + padding_length,
	                                flags, sctp_parameter_list_new(),
	                                sctp_cause_list_new());
}

struct sctp_chunk_list_item *
sctp_abort_chunk_new(s64 flgs, struct sctp_cause_list *list)
{
	struct sctp_abort_chunk *chunk;
	struct sctp_cause_list_item *item;
	u32 flags;
	u16 offset, chunk_length, chunk_padding_length, cause_padding_length;

	flags = 0;
	chunk_length = sizeof(struct sctp_abort_chunk);
	if (list != NULL) {
		chunk_length += list->length;
	} else {
		flags |= FLAG_CHUNK_LENGTH_NOCHECK;
		flags |= FLAG_ERROR_CHUNK_OPT_CAUSES_NOCHECK;
		list = sctp_cause_list_new();
	}
	chunk_padding_length = chunk_length % 4;
	if (chunk_padding_length > 0) {
		chunk_padding_length = 4 - chunk_padding_length;
	}
	chunk = malloc(chunk_length + chunk_padding_length);
	assert(chunk != NULL);
	chunk->type = SCTP_ABORT_CHUNK_TYPE;
	if (flgs == -1) {
		chunk->flags = 0;
		flags |= FLAG_CHUNK_FLAGS_NOCHECK;
	} else {
		chunk->flags = (u8)flgs;
	}
	chunk->length = htons(chunk_length);
	offset = 0;
	for (item = list->first; item != NULL; item = item->next) {
		cause_padding_length = item->length % 4;
		if (cause_padding_length > 0) {
			cause_padding_length = 4 - cause_padding_length;
		}
		memcpy(chunk->cause + offset,
		       item->cause,
		       item->length + cause_padding_length);
		free(item->cause);
		item->cause = (struct sctp_cause *)(chunk->cause + offset);
		if ((item->flags & FLAG_CAUSE_CODE_NOCHECK) ||
		    (item->flags & FLAG_CAUSE_INFORMATION_NOCHECK)) {
			flags |= FLAG_CHUNK_VALUE_NOCHECK;
		}
		if (item->flags & FLAG_CAUSE_LENGTH_NOCHECK) {
			flags |= FLAG_CHUNK_LENGTH_NOCHECK;
		}
		offset += item->length + cause_padding_length;
	}
	return sctp_chunk_list_item_new((struct sctp_chunk *)chunk,
	                                chunk_length + chunk_padding_length,
	                                flags, sctp_parameter_list_new(), list);
}

struct sctp_chunk_list_item *
sctp_shutdown_chunk_new(s64 flgs, s64 cum_tsn)
{
	struct sctp_shutdown_chunk *chunk;
	u32 flags;

	flags = 0;
	chunk = malloc(sizeof(struct sctp_shutdown_chunk));
	assert(chunk != NULL);
	chunk->type = SCTP_SHUTDOWN_CHUNK_TYPE;
	if (flgs == -1) {
		chunk->flags = 0;
		flags |= FLAG_CHUNK_FLAGS_NOCHECK;
	} else {
		chunk->flags = (u8)flgs;
	}
	chunk->length = htons(sizeof(struct sctp_shutdown_chunk));
	if (cum_tsn == -1) {
		chunk->cum_tsn = htonl(0);
		flags |= FLAG_SHUTDOWN_CHUNK_CUM_TSN_NOCHECK;
	} else {
		chunk->cum_tsn = htonl((u32)cum_tsn);
	}

	return sctp_chunk_list_item_new((struct sctp_chunk *)chunk,
	                                (u32)sizeof(struct sctp_shutdown_chunk),
	                                flags, sctp_parameter_list_new(),
	                                sctp_cause_list_new());
}

struct sctp_chunk_list_item *
sctp_shutdown_ack_chunk_new(s64 flgs)
{
	struct sctp_shutdown_ack_chunk *chunk;
	u32 flags;

	flags = 0;
	chunk = malloc(sizeof(struct sctp_shutdown_ack_chunk));
	assert(chunk != NULL);
	chunk->type = SCTP_SHUTDOWN_ACK_CHUNK_TYPE;
	if (flgs == -1) {
		chunk->flags = 0;
		flags |= FLAG_CHUNK_FLAGS_NOCHECK;
	} else {
		chunk->flags = (u8)flgs;
	}
	chunk->length = htons(sizeof(struct sctp_shutdown_ack_chunk));
	return sctp_chunk_list_item_new((struct sctp_chunk *)chunk,
	                                (u32)sizeof(struct sctp_shutdown_ack_chunk),
	                                flags, sctp_parameter_list_new(),
	                                sctp_cause_list_new());
}

struct sctp_chunk_list_item *
sctp_error_chunk_new(s64 flgs, struct sctp_cause_list *list)
{
	struct sctp_error_chunk *chunk;
	struct sctp_cause_list_item *item;
	u32 flags;
	u16 offset, chunk_length, chunk_padding_length, cause_padding_length;

	flags = 0;
	chunk_length = sizeof(struct sctp_error_chunk);
	if (list != NULL) {
		chunk_length += list->length;
	} else {
		flags |= FLAG_CHUNK_LENGTH_NOCHECK;
		flags |= FLAG_ERROR_CHUNK_OPT_CAUSES_NOCHECK;
		list = sctp_cause_list_new();
	}
	chunk_padding_length = chunk_length % 4;
	if (chunk_padding_length > 0) {
		chunk_padding_length = 4 - chunk_padding_length;
	}
	chunk = malloc(chunk_length + chunk_padding_length);
	assert(chunk != NULL);
	chunk->type = SCTP_ERROR_CHUNK_TYPE;
	if (flgs == -1) {
		chunk->flags = 0;
		flags |= FLAG_CHUNK_FLAGS_NOCHECK;
	} else {
		chunk->flags = (u8)flgs;
	}
	chunk->length = htons(chunk_length);
	offset = 0;
	for (item = list->first; item != NULL; item = item->next) {
		cause_padding_length = item->length % 4;
		if (cause_padding_length > 0) {
			cause_padding_length = 4 - cause_padding_length;
		}
		memcpy(chunk->cause + offset,
		       item->cause,
		       item->length + cause_padding_length);
		free(item->cause);
		item->cause = (struct sctp_cause *)(chunk->cause + offset);
		if ((item->flags & FLAG_CAUSE_CODE_NOCHECK) ||
		    (item->flags & FLAG_CAUSE_INFORMATION_NOCHECK)) {
			flags |= FLAG_CHUNK_VALUE_NOCHECK;
		}
		if (item->flags & FLAG_CAUSE_LENGTH_NOCHECK) {
			flags |= FLAG_CHUNK_LENGTH_NOCHECK;
		}
		offset += item->length + cause_padding_length;
	}
	return sctp_chunk_list_item_new((struct sctp_chunk *)chunk,
	                                chunk_length + chunk_padding_length,
	                                flags, sctp_parameter_list_new(), list);
}

struct sctp_chunk_list_item *
sctp_cookie_echo_chunk_new(s64 flgs, s64 len, struct sctp_byte_list *cookie)
{
	struct sctp_cookie_echo_chunk *chunk;
	struct sctp_byte_list_item *item;
	u32 flags;
	u16 chunk_length, cookie_length, padding_length, i;

	assert((len == -1) ||
	       (is_valid_u16(len) &&
	        len >= sizeof(struct sctp_cookie_echo_chunk)));
	assert((len != -1) || (cookie == NULL));
	flags = 0;
	if (len == -1) {
		cookie_length = 0;
		flags |= FLAG_CHUNK_LENGTH_NOCHECK;
	} else {
		assert(len <= MAX_SCTP_CHUNK_BYTES - sizeof(struct sctp_cookie_echo_chunk));
		cookie_length = len - sizeof(struct sctp_cookie_echo_chunk);
	}
	chunk_length = cookie_length + sizeof(struct sctp_cookie_echo_chunk);
	padding_length = chunk_length % 4;
	if (padding_length > 0) {
		padding_length = 4 - padding_length;
	}
	chunk = malloc(chunk_length + padding_length);
	assert(chunk != NULL);
	chunk->type = SCTP_COOKIE_ECHO_CHUNK_TYPE;
	if (flgs == -1) {
		chunk->flags = 0;
		flags |= FLAG_CHUNK_FLAGS_NOCHECK;
	} else {
		chunk->flags = (u8)flgs;
	}
	chunk->length = htons(chunk_length);
	if (cookie != NULL) {
		for (i = 0, item = cookie->first;
		     item != NULL;
		     i++, item = item->next) {
			chunk->cookie[i] = item->byte;
		}
	} else {
		flags |= FLAG_CHUNK_VALUE_NOCHECK;
		memset(chunk->cookie, 'A', cookie_length);
	}
	/* Clear the padding */
	memset(chunk->cookie + cookie_length, 0, padding_length);
	return sctp_chunk_list_item_new((struct sctp_chunk *)chunk,
	                                chunk_length + padding_length,
	                                flags, sctp_parameter_list_new(),
	                                sctp_cause_list_new());
}

struct sctp_chunk_list_item *
sctp_cookie_ack_chunk_new(s64 flgs)
{
	struct sctp_cookie_ack_chunk *chunk;
	u32 flags;

	flags = 0;
	chunk = malloc(sizeof(struct sctp_cookie_ack_chunk));
	assert(chunk != NULL);
	chunk->type = SCTP_COOKIE_ACK_CHUNK_TYPE;
	if (flgs == -1) {
		chunk->flags = 0;
		flags |= FLAG_CHUNK_FLAGS_NOCHECK;
	} else {
		chunk->flags = (u8)flgs;
	}
	chunk->length = htons(sizeof(struct sctp_cookie_ack_chunk));
	return sctp_chunk_list_item_new((struct sctp_chunk *)chunk,
	                                (u32)sizeof(struct sctp_cookie_ack_chunk),
	                                flags, sctp_parameter_list_new(),
	                                sctp_cause_list_new());
}

struct sctp_chunk_list_item *
sctp_ecne_chunk_new(s64 flgs, s64 lowest_tsn)
{
	struct sctp_ecne_chunk *chunk;
	u32 flags;

	flags = 0;
	chunk = malloc(sizeof(struct sctp_ecne_chunk));
	assert(chunk != NULL);
	chunk->type = SCTP_ECNE_CHUNK_TYPE;
	if (flgs == -1) {
		chunk->flags = 0;
		flags |= FLAG_CHUNK_FLAGS_NOCHECK;
	} else {
		chunk->flags = (u8)flgs;
	}
	chunk->length = htons(sizeof(struct sctp_ecne_chunk));
	if (lowest_tsn == -1) {
		chunk->lowest_tsn = htonl(0);
		flags |= FLAG_ECNE_CHUNK_LOWEST_TSN_NOCHECK;
	} else {
		chunk->lowest_tsn = htonl((u32)lowest_tsn);
	}

	return sctp_chunk_list_item_new((struct sctp_chunk *)chunk,
	                                (u32)sizeof(struct sctp_ecne_chunk),
	                                flags, sctp_parameter_list_new(),
	                                sctp_cause_list_new());
}

struct sctp_chunk_list_item *
sctp_cwr_chunk_new(s64 flgs, s64 lowest_tsn)
{
	struct sctp_cwr_chunk *chunk;
	u32 flags;

	flags = 0;
	chunk = malloc(sizeof(struct sctp_cwr_chunk));
	assert(chunk != NULL);
	chunk->type = SCTP_CWR_CHUNK_TYPE;
	if (flgs == -1) {
		chunk->flags = 0;
		flags |= FLAG_CHUNK_FLAGS_NOCHECK;
	} else {
		chunk->flags = (u8)flgs;
	}
	chunk->length = htons(sizeof(struct sctp_cwr_chunk));
	if (lowest_tsn == -1) {
		chunk->lowest_tsn = htonl(0);
		flags |= FLAG_CWR_CHUNK_LOWEST_TSN_NOCHECK;
	} else {
		chunk->lowest_tsn = htonl((u32)lowest_tsn);
	}

	return sctp_chunk_list_item_new((struct sctp_chunk *)chunk,
	                                (u32)sizeof(struct sctp_cwr_chunk),
	                                flags, sctp_parameter_list_new(),
	                                sctp_cause_list_new());
}

struct sctp_chunk_list_item *
sctp_shutdown_complete_chunk_new(s64 flgs)
{
	struct sctp_shutdown_complete_chunk *chunk;
	u32 flags;

	flags = 0;
	chunk = malloc(sizeof(struct sctp_shutdown_complete_chunk));
	assert(chunk != NULL);
	chunk->type = SCTP_SHUTDOWN_COMPLETE_CHUNK_TYPE;
	if (flgs == -1) {
		chunk->flags = 0;
		flags |= FLAG_CHUNK_FLAGS_NOCHECK;
	} else {
		chunk->flags = (u8)flgs;
	}
	chunk->length = htons(sizeof(struct sctp_shutdown_complete_chunk));
	return sctp_chunk_list_item_new((struct sctp_chunk *)chunk,
	                                (u32)sizeof(struct sctp_shutdown_complete_chunk),
	                                flags, sctp_parameter_list_new(),
	                                sctp_cause_list_new());
}

struct sctp_chunk_list_item *
sctp_i_data_chunk_new(s64 flgs, s64 len, s64 tsn, s64 sid, s64 res, s64 mid,
                      s64 ppid, s64 fsn)
{
	struct sctp_i_data_chunk *chunk;
	u32 flags;
	u16 length, padding_length;

	flags = 0;
	if (len == -1) {
		length = (u16)sizeof(struct sctp_i_data_chunk);
	} else {
		length = (u16)len;
	}
	padding_length = length % 4;
	if (padding_length > 0) {
		padding_length = 4 - padding_length;
	}
	chunk = malloc(length + padding_length);
	assert(chunk != NULL);
	chunk->type = SCTP_I_DATA_CHUNK_TYPE;
	if (flgs == -1) {
		chunk->flags = 0;
		flags |= FLAG_CHUNK_FLAGS_NOCHECK;
	} else {
		 chunk->flags = (u8)flgs;
	}
	chunk->length = htons(length);
	if (len == -1) {
		flags |= FLAG_CHUNK_LENGTH_NOCHECK;
		flags |= FLAG_CHUNK_VALUE_NOCHECK;
	}
	if (tsn == -1) {
		chunk->tsn = htonl(0);
		flags |= FLAG_I_DATA_CHUNK_TSN_NOCHECK;
	} else {
		chunk->tsn = htonl((u32)tsn);
	}
	if (sid == -1) {
		chunk->sid = htons(0);
		flags |= FLAG_I_DATA_CHUNK_SID_NOCHECK;
	} else {
		chunk->sid = htons((u16)sid);
	}
	if (res == -1) {
		chunk->res = htons(0);
		flags |= FLAG_I_DATA_CHUNK_RES_NOCHECK;
	} else {
		chunk->res = htons((u16)res);
	}
	if (mid == -1) {
		chunk->mid = htonl(0);
		flags |= FLAG_I_DATA_CHUNK_MID_NOCHECK;
	} else {
		chunk->mid = htonl((u32)mid);
	}
	if (ppid == -1) {
		flags |= FLAG_I_DATA_CHUNK_PPID_NOCHECK;
	} else {
		chunk->field.ppid = htonl((u32)ppid);
	}
	if (fsn == -1) {
		flags |= FLAG_I_DATA_CHUNK_FSN_NOCHECK;
	} else {
		chunk->field.fsn = htonl((u32)fsn);
	}
	if (ppid == -1 && fsn == -1) {
		chunk->field.ppid = htonl(0);
	}
	memset(chunk->data, 0,
	       length + padding_length - sizeof(struct sctp_i_data_chunk));
	return sctp_chunk_list_item_new((struct sctp_chunk *)chunk,
	                                length + padding_length, flags,
	                                sctp_parameter_list_new(),
	                                sctp_cause_list_new());
}

struct sctp_chunk_list_item *
sctp_pad_chunk_new(s64 flgs, s64 len, u8* padding)
{
	struct sctp_pad_chunk *chunk;
	u32 flags;
	u16 chunk_length, padding_length, chunk_padding_length;

	assert((len == -1) || is_valid_u16(len));
	assert((len != -1) || (padding == NULL));
	flags = 0;
	if (len == -1) {
		padding_length = 0;
		flags |= FLAG_CHUNK_LENGTH_NOCHECK;
	} else {
		assert(len <= MAX_SCTP_CHUNK_BYTES - sizeof(struct sctp_pad_chunk));
		padding_length = len - sizeof(struct sctp_pad_chunk);
	}
	chunk_length = padding_length + sizeof(struct sctp_pad_chunk);
	chunk_padding_length = chunk_length % 4;
	if (chunk_padding_length > 0) {
		chunk_padding_length = 4 - chunk_padding_length;
	}
	chunk = malloc(chunk_length + chunk_padding_length);
	assert(chunk != NULL);
	chunk->type = SCTP_PAD_CHUNK_TYPE;
	if (flgs == -1) {
		chunk->flags = 0;
		flags |= FLAG_CHUNK_FLAGS_NOCHECK;
	} else {
		chunk->flags = (u8)flgs;
	}
	chunk->length = htons(chunk_length);
	if (padding != NULL) {
		memcpy(chunk->padding_data, padding, padding_length);
	} else {
		flags |= FLAG_CHUNK_VALUE_NOCHECK;
		memset(chunk->padding_data, 'P', padding_length);
	}
	/* Clear the padding */
	memset(chunk->padding_data + padding_length, 0, chunk_padding_length);
	return sctp_chunk_list_item_new((struct sctp_chunk *)chunk,
	                                chunk_length + chunk_padding_length,
	                                flags, sctp_parameter_list_new(),
	                                sctp_cause_list_new());
}

struct sctp_chunk_list *
sctp_chunk_list_new(void)
{
	struct sctp_chunk_list *list;

	list = malloc(sizeof(struct sctp_chunk_list));
	assert(list != NULL);
	list->first = NULL;
	list->last = NULL;
	list->length = 0;
	return list;
}

void
sctp_chunk_list_append(struct sctp_chunk_list *list,
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

void
sctp_chunk_list_free(struct sctp_chunk_list *list)
{
	struct sctp_chunk_list_item *current_item, *next_item;
	
	if (list == NULL) {
		return;
	}
	
	current_item = list->first;
	while (current_item != NULL) {
		next_item = current_item->next;
		assert(next_item != NULL || current_item == list->last);
		assert(current_item->parameter_list);
		sctp_parameter_list_free(current_item->parameter_list);
		assert(current_item->cause_list);
		sctp_cause_list_free(current_item->cause_list);
		free(current_item);
		current_item = next_item;
	}
	free(list);
}

struct sctp_parameter_list_item *
sctp_parameter_list_item_new(struct sctp_parameter *parameter, u32 length, u32 flags)
{
	struct sctp_parameter_list_item *item;

	item = malloc(sizeof(struct sctp_parameter_list_item));
	assert(item != NULL);
	item->next = NULL;
	item->parameter = parameter;
	item->length = length;
	item->flags = flags;
	return item;
}

struct sctp_parameter_list_item *
sctp_generic_parameter_new(s64 type, s64 len, struct sctp_byte_list *bytes)
{
	struct sctp_parameter *parameter;
	struct sctp_byte_list_item *item;
	u32 flags;
	u16 parameter_length, value_length, padding_length, i;

	flags = 0;
	if (bytes == NULL) {
		flags |= FLAG_PARAMETER_VALUE_NOCHECK;
	}
	if (len == -1) {
		parameter_length = (u16)sizeof(struct sctp_parameter);
		flags |= FLAG_PARAMETER_LENGTH_NOCHECK;
	} else {
		parameter_length = (u16)len;
	}
	value_length = parameter_length - sizeof(struct sctp_parameter);
	padding_length = parameter_length % 4;
	if (padding_length > 0) {
		padding_length = 4 - padding_length;
	}
	parameter = malloc(parameter_length + padding_length);
	assert(parameter != NULL);
	if (type == -1) {
		parameter->type = 0;
		flags |= FLAG_PARAMETER_TYPE_NOCHECK;
	} else {
		parameter->type = htons((u16)type);
	}
	parameter->length = htons(parameter_length);
	if (bytes != NULL) {
		for (i = 0, item = bytes->first;
		     item != NULL;
		     i++, item = item->next) {
			parameter->value[i] = item->byte;
		}
	} else {
		memset(parameter->value, 0, value_length);
	}
	/* Clear the padding */
	memset(parameter->value + value_length, 0, padding_length);
	return sctp_parameter_list_item_new(parameter, parameter_length, flags);
}

struct sctp_parameter_list_item *
sctp_heartbeat_information_parameter_new(s64 len, struct sctp_byte_list *bytes)
{
	return sctp_generic_parameter_new(SCTP_HEARTBEAT_INFORMATION_PARAMETER_TYPE, len, bytes);
}

struct sctp_parameter_list_item *
sctp_ipv4_address_parameter_new(struct in_addr *addr)
{
	struct sctp_ipv4_address_parameter *parameter;
	u32 flags;

	flags = 0;
	parameter = malloc(sizeof(struct sctp_ipv4_address_parameter));
	assert(parameter != NULL);
	parameter->type = htons(SCTP_IPV4_ADDRESS_PARAMETER_TYPE);
	parameter->length = htons(sizeof(struct sctp_ipv4_address_parameter));
	if (addr == NULL) {
		parameter->addr.s_addr = htonl(INADDR_ANY);
		flags |= FLAG_PARAMETER_VALUE_NOCHECK;
	} else {
		parameter->addr = *addr;
	}
	return sctp_parameter_list_item_new((struct sctp_parameter *)parameter,
	                                    sizeof(struct sctp_ipv4_address_parameter),
	                                    flags);
}

struct sctp_parameter_list_item *
sctp_ipv6_address_parameter_new(struct in6_addr *addr)
{
	struct sctp_ipv6_address_parameter *parameter;
	u32 flags;

	flags = 0;
	parameter = malloc(sizeof(struct sctp_ipv6_address_parameter));
	assert(parameter != NULL);
	parameter->type = htons(SCTP_IPV6_ADDRESS_PARAMETER_TYPE);
	parameter->length = htons(sizeof(struct sctp_ipv6_address_parameter));
	if (addr == NULL) {
		parameter->addr = in6addr_any;
		flags |= FLAG_PARAMETER_VALUE_NOCHECK;
	} else {
		parameter->addr = *addr;
	}
	return sctp_parameter_list_item_new((struct sctp_parameter *)parameter,
	                                    sizeof(struct sctp_ipv6_address_parameter),
	                                    flags);
}

struct sctp_parameter_list_item *
sctp_state_cookie_parameter_new(s64 len, u8 *cookie)
{
	struct sctp_state_cookie_parameter *parameter;
	u32 flags;
	u16 parameter_length, cookie_length, padding_length;

	assert((len == -1) || is_valid_u16(len));
	assert((len != -1) || (cookie == NULL));
	flags = 0;
	if (len == -1) {
		cookie_length = 0;
		flags |= FLAG_PARAMETER_LENGTH_NOCHECK;
	} else {
		assert(len <= MAX_SCTP_PARAMETER_BYTES - sizeof(struct sctp_state_cookie_parameter));
		cookie_length = len - sizeof(struct sctp_state_cookie_parameter);
	}
	parameter_length = cookie_length + sizeof(struct sctp_state_cookie_parameter);
	padding_length = parameter_length % 4;
	if (padding_length > 0) {
		padding_length = 4 - padding_length;
	}
	parameter = malloc(parameter_length + padding_length);
	assert(parameter != NULL);
	parameter->type = htons(SCTP_STATE_COOKIE_PARAMETER_TYPE);
	parameter->length = htons(parameter_length);
	if (cookie != NULL) {
		memcpy(parameter->cookie, cookie, cookie_length);
	} else {
		flags |= FLAG_PARAMETER_VALUE_NOCHECK;
		memset(parameter->cookie, 'A', cookie_length);
	}
	/* Clear the padding */
	memset(parameter->cookie + cookie_length, 0, padding_length);
	return sctp_parameter_list_item_new((struct sctp_parameter *)parameter,
	                                    parameter_length, flags);
}

struct sctp_parameter_list_item *
sctp_unrecognized_parameters_parameter_new(struct sctp_parameter_list *list)
{
	struct sctp_unrecognized_parameter_parameter *parameter;
	struct sctp_parameter_list_item *item;
	u32 flags;
	u16 parameter_length, padding_length, offset;

	assert(list == NULL ||
	       (list->length <
	        MAX_SCTP_PARAMETER_BYTES - sizeof(struct sctp_unrecognized_parameter_parameter)));
	flags = 0;
	parameter_length = sizeof(struct sctp_unrecognized_parameter_parameter);
	if (list != NULL) {
		parameter_length += list->length;
	} else {
		flags |= FLAG_PARAMETER_LENGTH_NOCHECK;
		flags |= FLAG_PARAMETER_VALUE_NOCHECK;
	}
	padding_length = parameter_length % 4;
	if (padding_length > 0) {
		padding_length = 4 - padding_length;
	}
	parameter = malloc(parameter_length + padding_length);
	assert(parameter != NULL);
	parameter->type = htons(SCTP_UNRECOGNIZED_PARAMETER_PARAMETER_TYPE);
	parameter->length = htons(parameter_length);
	if (list != NULL) {
		offset = 0;
		for (item = list->first; item != NULL; item = item->next) {
			padding_length = item->length % 4;
			if (padding_length > 0) {
				padding_length = 4 - padding_length;
			}
			memcpy(parameter->value + offset, item->parameter, item->length + padding_length);
			if (item->flags & FLAG_PARAMETER_LENGTH_NOCHECK) {
				flags |= FLAG_PARAMETER_LENGTH_NOCHECK;
			}
			if (item->flags & FLAG_PARAMETER_VALUE_NOCHECK) {
				flags |= FLAG_PARAMETER_VALUE_NOCHECK;
			}
			offset += item->length + padding_length;
		}
	}
	return sctp_parameter_list_item_new((struct sctp_parameter *)parameter,
	                                    parameter_length, flags);
}

struct sctp_parameter_list_item *
sctp_cookie_preservative_parameter_new(s64 increment)
{
	struct sctp_cookie_preservative_parameter *parameter;
	u32 flags;

	flags = 0;
	parameter = malloc(sizeof(struct sctp_cookie_preservative_parameter));
	assert(parameter != NULL);
	parameter->type = htons(SCTP_COOKIE_PRESERVATIVE_PARAMETER_TYPE);
	parameter->length = htons(sizeof(struct sctp_cookie_preservative_parameter));
	if (increment == -1) {
		parameter->increment = htonl(0);
		flags |= FLAG_PARAMETER_VALUE_NOCHECK;
	} else {
		assert(is_valid_u32(increment));
		parameter->increment = htonl((u32)increment);
	}
	return sctp_parameter_list_item_new((struct sctp_parameter *)parameter,
	                                    sizeof(struct sctp_cookie_preservative_parameter),
	                                    flags);
}

struct sctp_parameter_list_item *
sctp_hostname_address_parameter_new(char *hostname)
{
	struct sctp_hostname_address_parameter *parameter;
	u32 flags;
	u16 length, name_length, padding_length;

	/* RFC 4960 requires that the hostname is NUL terminated */
	assert(hostname == NULL ||
	       (strlen(hostname) + 1 <=
	        MAX_SCTP_PARAMETER_BYTES - sizeof(struct sctp_hostname_address_parameter)));
	flags = 0;
	if (hostname == NULL) {
		name_length = 1;
	} else {
		name_length = strlen(hostname) + 1;
	}
	length = name_length + sizeof(struct sctp_hostname_address_parameter);
	padding_length = length % 4;
	if (padding_length > 0) {
		padding_length = 4 - padding_length;
	}
	parameter = malloc(length + padding_length);
	assert(parameter != NULL);
	parameter->type = htons(SCTP_HOSTNAME_ADDRESS_PARAMETER_TYPE);
	parameter->length = htons(length);
	if (hostname == NULL) {
		parameter->hostname[0] = '\0';
		flags |= FLAG_PARAMETER_LENGTH_NOCHECK;
		flags |= FLAG_PARAMETER_VALUE_NOCHECK;
	} else {
		strcpy(parameter->hostname, hostname);
	}
	memset(parameter->hostname + name_length, 0, padding_length);
	return sctp_parameter_list_item_new((struct sctp_parameter *)parameter,
	                                    length, flags);
}

struct sctp_parameter_list_item *
sctp_supported_address_types_parameter_new(struct sctp_address_type_list *list)
{
	struct sctp_supported_address_types_parameter *parameter;

	u32 flags;
	u16 i, parameter_length, padding_length;
	struct sctp_address_type_list_item *item;

	flags = 0;
	parameter_length = sizeof(struct sctp_supported_address_types_parameter);
	if (list == NULL) {
		flags |= FLAG_PARAMETER_LENGTH_NOCHECK;
		flags |= FLAG_PARAMETER_VALUE_NOCHECK;
	} else {
		assert(list->nr_entries <=
		       (MAX_SCTP_PARAMETER_BYTES - sizeof(struct sctp_supported_address_types_parameter)) / sizeof(u16));
		parameter_length += list->nr_entries * sizeof(u16);
	}
	padding_length = parameter_length % 4;
	if (padding_length > 0) {
		padding_length = 4 - padding_length;
	}
	assert(padding_length == 0 || padding_length == 2);
	parameter = malloc(parameter_length + padding_length);
	assert(parameter != NULL);
	parameter->type = htons(SCTP_SUPPORTED_ADDRESS_TYPES_PARAMETER_TYPE);
	parameter->length = htons(parameter_length);
	if (list != NULL) {
		for (i = 0, item = list->first;
		     (i < list->nr_entries) && (item != NULL);
		     i++, item = item->next) {
			parameter->address_type[i] = htons(item->address_type);
		}
		assert((i == list->nr_entries) && (item == NULL));
	}
	if (padding_length == 2) {
		parameter->address_type[list->nr_entries] = htons(0);
	}
	return sctp_parameter_list_item_new((struct sctp_parameter *)parameter,
	                                    parameter_length, flags);
}

struct sctp_parameter_list_item *
sctp_supported_extensions_parameter_new(struct sctp_byte_list *list)
{
	struct sctp_supported_extensions_parameter *parameter;

	u32 flags;
	u16 i, parameter_length, padding_length;
	struct sctp_byte_list_item *item;

	flags = 0;
	parameter_length = sizeof(struct sctp_supported_extensions_parameter);
	if (list == NULL) {
		flags |= FLAG_PARAMETER_LENGTH_NOCHECK;
		flags |= FLAG_PARAMETER_VALUE_NOCHECK;
	} else {
		assert(list->nr_entries <=
		       (MAX_SCTP_PARAMETER_BYTES - sizeof(struct sctp_supported_extensions_parameter)) / sizeof(u8));
		parameter_length += list->nr_entries * sizeof(u8);
	}
	padding_length = parameter_length % 4;
	if (padding_length > 0) {
		padding_length = 4 - padding_length;
	}
	assert(padding_length < 4);
	parameter = malloc(parameter_length + padding_length);
	assert(parameter != NULL);
	parameter->type = htons(SCTP_SUPPORTED_EXTENSIONS_PARAMETER_TYPE);
	parameter->length = htons(parameter_length);
	if (list != NULL) {
		for (i = 0, item = list->first;
		     (i < list->nr_entries) && (item != NULL);
		     i++, item = item->next) {
			parameter->chunk_type[i] = item->byte;
		}
		assert((i == list->nr_entries) && (item == NULL));
	}
	memset(parameter->chunk_type + list->nr_entries, 0, padding_length);
	return sctp_parameter_list_item_new((struct sctp_parameter *)parameter,
	                                    parameter_length, flags);
}

struct sctp_parameter_list_item *
sctp_adaptation_indication_parameter_new(s64 val)
{
	u32 flags;
	struct sctp_adaptation_indication_parameter *parameter;
	u16 parameter_length;

	flags = 0;
	parameter_length = sizeof(struct sctp_adaptation_indication_parameter);

	parameter = malloc(parameter_length);
	assert(parameter != NULL);
	memset(parameter, 0, parameter_length);

	parameter->type = htons(SCTP_ADAPTATION_INDICATION_PARAMETER_TYPE);
	parameter->length = htons(parameter_length);
	if (val == -1) {
		parameter->adaptation_code_point = htonl(0);
		flags |= FLAG_PARAMETER_VALUE_NOCHECK;
	} else {
		assert(is_valid_u32(val));
		parameter->adaptation_code_point = htonl((u32)val);
	}
	return sctp_parameter_list_item_new((struct sctp_parameter *)parameter,
	                                    parameter_length, flags);
}

struct sctp_parameter_list_item *
sctp_pad_parameter_new(s64 len, u8 *padding)
{
	struct sctp_pad_parameter *parameter;
	u32 flags;
	u16 parameter_length, padding_length, parameter_padding_length;

	assert((len == -1) || is_valid_u16(len));
	assert((len != -1) || (padding == NULL));
	flags = 0;
	if (len == -1) {
		padding_length = 0;
		flags |= FLAG_PARAMETER_LENGTH_NOCHECK;
	} else {
		assert(len <= MAX_SCTP_PARAMETER_BYTES - sizeof(struct sctp_pad_parameter));
		padding_length = len - sizeof(struct sctp_pad_parameter);
	}
	parameter_length = padding_length + sizeof(struct sctp_pad_parameter);
	parameter_padding_length = parameter_length % 4;
	if (parameter_padding_length > 0) {
		parameter_padding_length = 4 - parameter_padding_length;
	}
	parameter = malloc(parameter_length + parameter_padding_length);
	assert(parameter != NULL);
	parameter->type = htons(SCTP_PAD_PARAMETER_TYPE);
	parameter->length = htons(parameter_length);
	if (padding != NULL) {
		memcpy(parameter->padding_data, padding, padding_length);
	} else {
		/* flags |= FLAG_PARAMETER_VALUE_NOCHECK; */
		memset(parameter->padding_data, 'P', padding_length);
	}
	/* Clear the padding */
	memset(parameter->padding_data + padding_length, 0, parameter_padding_length);
	return sctp_parameter_list_item_new((struct sctp_parameter *)parameter,
	                                    parameter_length, flags);
}

struct sctp_parameter_list_item *
sctp_ecn_capable_parameter_new(void)
{
	struct sctp_ecn_capable_parameter *parameter;

	parameter = malloc(sizeof(struct sctp_ecn_capable_parameter));
	assert(parameter != NULL);
	parameter->type = htons(SCTP_ECN_CAPABLE_PARAMETER_TYPE);
	parameter->length = htons(sizeof(struct sctp_ecn_capable_parameter));
	return sctp_parameter_list_item_new((struct sctp_parameter *)parameter,
	                                    sizeof(struct sctp_ecn_capable_parameter),
	                                    0);
}

struct sctp_parameter_list *
sctp_parameter_list_new(void)
{
	struct sctp_parameter_list *list;

	list = malloc(sizeof(struct sctp_parameter_list));
	assert(list != NULL);
	list->first = NULL;
	list->last = NULL;
	list->length = 0;
	return list;
}

void
sctp_parameter_list_append(struct sctp_parameter_list *list,
                           struct sctp_parameter_list_item *item)
{
	u16 padding_length;

	assert(item->next == NULL);
	padding_length = list->length % 4;
	if (padding_length > 0) {
		padding_length = 4 - padding_length;
	}
	list->length += padding_length;
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

void
sctp_parameter_list_free(struct sctp_parameter_list *list)
{
	struct sctp_parameter_list_item *current_item, *next_item;

	assert(list != NULL);
	current_item = list->first;
	while (current_item != NULL) {
		next_item = current_item->next;
		assert(next_item != NULL || current_item == list->last);
		free(current_item);
		current_item = next_item;
	}
	free(list);
}

struct sctp_cause_list_item *
sctp_cause_list_item_new(struct sctp_cause *cause, u32 length, u32 flags)
{
	struct sctp_cause_list_item *item;

	item = malloc(sizeof(struct sctp_cause_list_item));
	assert(item != NULL);
	item->next = NULL;
	item->cause = cause;
	item->length = length;
	item->flags = flags;
	return item;
}

struct sctp_cause_list_item *
sctp_generic_cause_new(s64 code, s64 len, struct sctp_byte_list *bytes)
{
	struct sctp_cause *cause;
	struct sctp_byte_list_item *item;
	u32 flags;
	u16 cause_length, information_length, padding_length, i;

	flags = 0;
	if (bytes == NULL) {
		flags |= FLAG_CAUSE_INFORMATION_NOCHECK;
	}
	if (len == -1) {
		cause_length = (u16)sizeof(struct sctp_cause);
		flags |= FLAG_CAUSE_LENGTH_NOCHECK;
	} else {
		cause_length = (u16)len;
	}
	information_length = cause_length - sizeof(struct sctp_cause);
	padding_length = cause_length % 4;
	if (padding_length > 0) {
		padding_length = 4 - padding_length;
	}
	cause = malloc(cause_length + padding_length);
	assert(cause != NULL);
	if (code == -1) {
		cause->code = 0;
		flags |= FLAG_CAUSE_CODE_NOCHECK;
	} else {
		cause->code = htons((u16)code);
	}
	cause->length = htons(cause_length);
	if (bytes != NULL) {
		for (i = 0, item = bytes->first;
		     item != NULL;
		     i++, item = item->next) {
			cause->information[i] = item->byte;
		}
	} else {
		memset(cause->information, 0, information_length);
	}
	/* Clear the padding */
	memset(cause->information + information_length, 0, padding_length);
	return sctp_cause_list_item_new(cause, cause_length, flags);
}

struct sctp_cause_list_item *
sctp_invalid_stream_identifier_cause_new(s64 sid)
{
	struct sctp_invalid_stream_identifier_cause *cause;
	u32 flags;

	flags = 0;
	cause = malloc(sizeof(struct sctp_invalid_stream_identifier_cause));
	assert(cause != NULL);
	cause->code = htons(SCTP_INVALID_STREAM_IDENTIFIER_CAUSE_CODE);
	cause->length = htons(sizeof(struct sctp_invalid_stream_identifier_cause));
	if (sid == -1) {
		cause->sid = htonl(0);
		flags |= FLAG_CAUSE_INFORMATION_NOCHECK;
	} else {
		assert(is_valid_u16(sid));
		cause->sid = htons((u16)sid);
	}
	cause->reserved = htons(0);
	return sctp_cause_list_item_new((struct sctp_cause *)cause,
	                                sizeof(struct sctp_invalid_stream_identifier_cause),
	                                flags);
}

struct sctp_cause_list_item *
sctp_missing_mandatory_parameter_cause_new(struct sctp_parameter_type_list *list)
{
	struct sctp_missing_mandatory_parameter_cause *cause;

	u32 flags;
	u16 i, cause_length, padding_length;
	struct sctp_parameter_type_list_item *item;

	flags = 0;
	cause_length = sizeof(struct sctp_missing_mandatory_parameter_cause);
	if (list == NULL) {
		flags |= FLAG_CAUSE_LENGTH_NOCHECK;
		flags |= FLAG_CAUSE_INFORMATION_NOCHECK;
	} else {
		assert(list->nr_entries <=
		       (MAX_SCTP_PARAMETER_BYTES - sizeof(struct sctp_missing_mandatory_parameter_cause)) / sizeof(u16));
		cause_length += list->nr_entries * sizeof(u16);
	}
	padding_length = cause_length % 4;
	if (padding_length > 0) {
		padding_length = 4 - padding_length;
	}
	assert(padding_length == 0 || padding_length == 2);
	cause = malloc(cause_length + padding_length);
	assert(cause != NULL);
	cause->code = htons(SCTP_MISSING_MANDATORY_PARAMETER_CAUSE_CODE);
	cause->length = htons(cause_length);
	cause->nr_parameters = htonl(list->nr_entries);
	if (list != NULL) {
		for (i = 0, item = list->first;
		     (i < list->nr_entries) && (item != NULL);
		     i++, item = item->next) {
			cause->parameter_type[i] = htons(item->parameter_type);
		}
		assert((i == list->nr_entries) && (item == NULL));
	}
	if (padding_length == 2) {
		cause->parameter_type[list->nr_entries] = htons(0);
	}
	return sctp_cause_list_item_new((struct sctp_cause *)cause,
	                                cause_length, flags);
}

struct sctp_cause_list_item *
sctp_stale_cookie_error_cause_new(s64 staleness)
{
	struct sctp_stale_cookie_error_cause *cause;
	u32 flags;

	flags = 0;
	cause = malloc(sizeof(struct sctp_stale_cookie_error_cause));
	assert(cause != NULL);
	cause->code = htons(SCTP_STALE_COOKIE_ERROR_CAUSE_CODE);
	cause->length = htons(sizeof(struct sctp_stale_cookie_error_cause));
	if (staleness == -1) {
		cause->staleness = htonl(0);
		flags |= FLAG_CAUSE_INFORMATION_NOCHECK;
	} else {
		assert(is_valid_u32(staleness));
		cause->staleness = htonl((u32)staleness);
	}
	return sctp_cause_list_item_new((struct sctp_cause *)cause,
	                                sizeof(struct sctp_stale_cookie_error_cause),
	                                flags);
}

struct sctp_cause_list_item *
sctp_out_of_resources_cause_new(void)
{
	struct sctp_out_of_resources_cause *cause;

	cause = malloc(sizeof(struct sctp_out_of_resources_cause));
	assert(cause != NULL);
	cause->code = htons(SCTP_OUT_OF_RESOURCES_CAUSE_CODE);
	cause->length = htons(sizeof(struct sctp_out_of_resources_cause));
	return sctp_cause_list_item_new((struct sctp_cause *)cause,
	                                sizeof(struct sctp_out_of_resources_cause),
	                                0);
}

struct sctp_cause_list_item *
sctp_unresolvable_address_cause_new(struct sctp_parameter_list_item *item)
{
	struct sctp_unresolvable_address_cause *cause;
	u32 flags;
	u16 length, padding_length;

	assert(item == NULL ||
	       (item->length <=
	        MAX_SCTP_CAUSE_BYTES - sizeof(struct sctp_unresolvable_address_cause)));
	flags = 0;
	length = sizeof(struct sctp_unresolvable_address_cause);
	if (item != NULL) {
		length += item->length;
	}
	padding_length = length % 4;
	if (padding_length > 0) {
		padding_length = 4 - padding_length;
	}
	cause = malloc(length + padding_length);
	assert(cause != NULL);
	cause->code = htons(SCTP_UNRESOLVABLE_ADDRESS_CAUSE_CODE);
	cause->length = htons(length);
	if (item == NULL) {
		flags |= FLAG_CAUSE_LENGTH_NOCHECK;
		flags |= FLAG_CAUSE_INFORMATION_NOCHECK;
	} else {
		if ((item->flags & FLAG_PARAMETER_TYPE_NOCHECK) ||
		    (item->flags & FLAG_PARAMETER_VALUE_NOCHECK)) {
			flags |= FLAG_CAUSE_INFORMATION_NOCHECK;
		}
		if (item->flags & FLAG_PARAMETER_LENGTH_NOCHECK) {
			flags |= FLAG_CAUSE_LENGTH_NOCHECK;
		}
		memcpy(cause->parameter, item->parameter, item->length);
	}
	memset(cause->parameter + item->length, 0, padding_length);
	free(item);
	return sctp_cause_list_item_new((struct sctp_cause *)cause,
	                                length, flags);
}

struct sctp_cause_list_item *
sctp_unrecognized_chunk_type_cause_new(struct sctp_chunk_list_item *item)
{
	struct sctp_unrecognized_chunk_type_cause *cause;
	u32 flags;
	u16 length, padding_length;

	assert(item == NULL ||
	       (item->length <=
	        MAX_SCTP_CAUSE_BYTES - sizeof(struct sctp_unrecognized_chunk_type_cause)));
	flags = 0;
	length = sizeof(struct sctp_unrecognized_chunk_type_cause);
	if (item != NULL) {
		length += item->length;
	}
	padding_length = length % 4;
	if (padding_length > 0) {
		padding_length = 4 - padding_length;
	}
	cause = malloc(length + padding_length);
	assert(cause != NULL);
	cause->code = htons(SCTP_UNRECOGNIZED_CHUNK_TYPE_CAUSE_CODE);
	cause->length = htons(length);
	if (item == NULL) {
		flags |= FLAG_CAUSE_LENGTH_NOCHECK;
		flags |= FLAG_CAUSE_INFORMATION_NOCHECK;
	} else {
		if ((item->flags & FLAG_CHUNK_TYPE_NOCHECK) ||
		    (item->flags & FLAG_CHUNK_FLAGS_NOCHECK) ||
		    (item->flags & FLAG_CHUNK_VALUE_NOCHECK)) {
			flags |= FLAG_CAUSE_INFORMATION_NOCHECK;
		}
		if (item->flags & FLAG_CHUNK_LENGTH_NOCHECK) {
			flags |= FLAG_CAUSE_LENGTH_NOCHECK;
		}
		memcpy(cause->chunk, item->chunk, item->length);
	}
	memset(cause->chunk + item->length, 0, padding_length);
	free(item);
	return sctp_cause_list_item_new((struct sctp_cause *)cause,
	                                length, flags);
}

struct sctp_cause_list_item *
sctp_invalid_mandatory_parameter_cause_new(void)
{
	struct sctp_invalid_mandatory_parameter_cause *cause;

	cause = malloc(sizeof(struct sctp_invalid_mandatory_parameter_cause));
	assert(cause != NULL);
	cause->code = htons(SCTP_INVALID_MANDATORY_PARAMETER_CAUSE_CODE);
	cause->length = htons(sizeof(struct sctp_invalid_mandatory_parameter_cause));
	return sctp_cause_list_item_new((struct sctp_cause *)cause,
	                                sizeof(struct sctp_invalid_mandatory_parameter_cause),
	                                0);
}

struct sctp_cause_list_item *
sctp_unrecognized_parameters_cause_new(struct sctp_parameter_list *list)
{
	struct sctp_unrecognized_parameters_cause *cause;
	struct sctp_parameter_list_item *item;
	u32 flags;
	u16 cause_length, padding_length, offset;

	assert(list == NULL ||
	       (list->length <
	        MAX_SCTP_PARAMETER_BYTES - sizeof(struct sctp_unrecognized_parameters_cause)));
	flags = 0;
	cause_length = sizeof(struct sctp_unrecognized_parameters_cause);
	if (list != NULL) {
		cause_length += list->length;
	} else {
		flags |= FLAG_CAUSE_LENGTH_NOCHECK;
		flags |= FLAG_CAUSE_INFORMATION_NOCHECK;
	}
	padding_length = cause_length % 4;
	if (padding_length > 0) {
		padding_length = 4 - padding_length;
	}
	cause = malloc(cause_length + padding_length);
	assert(cause != NULL);
	cause->code = htons(SCTP_UNRECOGNIZED_PARAMETERS_CAUSE_CODE);
	cause->length = htons(cause_length);
	if (list != NULL) {
		offset = 0;
		for (item = list->first; item != NULL; item = item->next) {
			padding_length = item->length % 4;
			if (padding_length > 0) {
				padding_length = 4 - padding_length;
			}
			memcpy(cause->parameters + offset, item->parameter, item->length + padding_length);
			if (item->flags & FLAG_PARAMETER_LENGTH_NOCHECK) {
				flags |= FLAG_CAUSE_LENGTH_NOCHECK;
			}
			if (item->flags & FLAG_PARAMETER_VALUE_NOCHECK) {
				flags |= FLAG_CAUSE_INFORMATION_NOCHECK;
			}
			offset += item->length + padding_length;
		}
	}
	return sctp_cause_list_item_new((struct sctp_cause *)cause,
	                                cause_length, flags);
}

struct sctp_cause_list_item *
sctp_no_user_data_cause_new(s64 tsn)
{
	struct sctp_no_user_data_cause *cause;
	u32 flags;

	flags = 0;
	cause = malloc(sizeof(struct sctp_no_user_data_cause));
	assert(cause != NULL);
	cause->code = htons(SCTP_NO_USER_DATA_CAUSE_CODE);
	cause->length = htons(sizeof(struct sctp_no_user_data_cause));
	if (tsn == -1) {
		cause->tsn = htonl(0);
		flags |= FLAG_CAUSE_INFORMATION_NOCHECK;
	} else {
		assert(is_valid_u32(tsn));
		cause->tsn = htonl((u32)tsn);
	}
	return sctp_cause_list_item_new((struct sctp_cause *)cause,
	                                sizeof(struct sctp_no_user_data_cause),
	                                flags);
}

struct sctp_cause_list_item *
sctp_cookie_received_while_shutdown_cause_new(void)
{
	struct sctp_cookie_received_while_shutdown_cause *cause;

	cause = malloc(sizeof(struct sctp_cookie_received_while_shutdown_cause));
	assert(cause != NULL);
	cause->code = htons(SCTP_COOKIE_RECEIVED_WHILE_SHUTDOWN_CAUSE_CODE);
	cause->length = htons(sizeof(struct sctp_cookie_received_while_shutdown_cause));
	return sctp_cause_list_item_new((struct sctp_cause *)cause,
	                                sizeof(struct sctp_cookie_received_while_shutdown_cause),
	                                0);
}

struct sctp_cause_list_item *
sctp_restart_with_new_addresses_cause_new(struct sctp_parameter_list *list)
{
	struct sctp_restart_with_new_addresses_cause *cause;
	struct sctp_parameter_list_item *item;
	u32 flags;
	u16 cause_length, padding_length, offset;

	assert(list == NULL ||
	       (list->length <
	        MAX_SCTP_PARAMETER_BYTES - sizeof(struct sctp_restart_with_new_addresses_cause)));
	flags = 0;
	cause_length = sizeof(struct sctp_restart_with_new_addresses_cause);
	if (list != NULL) {
		cause_length += list->length;
	} else {
		flags |= FLAG_CAUSE_LENGTH_NOCHECK;
		flags |= FLAG_CAUSE_INFORMATION_NOCHECK;
	}
	padding_length = cause_length % 4;
	if (padding_length > 0) {
		padding_length = 4 - padding_length;
	}
	cause = malloc(cause_length + padding_length);
	assert(cause != NULL);
	cause->code = htons(SCTP_RESTART_WITH_NEW_ADDRESSES_CAUSE_CODE);
	cause->length = htons(cause_length);
	if (list != NULL) {
		offset = 0;
		for (item = list->first; item != NULL; item = item->next) {
			padding_length = item->length % 4;
			if (padding_length > 0) {
				padding_length = 4 - padding_length;
			}
			memcpy(cause->addresses + offset, item->parameter, item->length + padding_length);
			if (item->flags & FLAG_PARAMETER_LENGTH_NOCHECK) {
				flags |= FLAG_CAUSE_LENGTH_NOCHECK;
			}
			if (item->flags & FLAG_PARAMETER_VALUE_NOCHECK) {
				flags |= FLAG_CAUSE_INFORMATION_NOCHECK;
			}
			offset += item->length + padding_length;
		}
	}
	return sctp_cause_list_item_new((struct sctp_cause *)cause,
	                                cause_length, flags);
}

struct sctp_cause_list_item *
sctp_user_initiated_abort_cause_new(char *info)
{
	struct sctp_user_initiated_abort_cause *cause;
	u32 flags;
	u16 length, info_length, padding_length;

	assert(info == NULL ||
	       (strlen(info) <=
	        MAX_SCTP_PARAMETER_BYTES - sizeof(struct sctp_user_initiated_abort_cause)));
	flags = 0;
	if (info == NULL) {
		info_length = 0;
	} else {
		info_length = strlen(info);
	}
	length = info_length + sizeof(struct sctp_user_initiated_abort_cause);
	padding_length = length % 4;
	if (padding_length > 0) {
		padding_length = 4 - padding_length;
	}
	cause = malloc(length + padding_length);
	assert(cause != NULL);
	cause->code = htons(SCTP_USER_INITIATED_ABORT_CAUSE_CODE);
	cause->length = htons(length);
	if (info == NULL) {
		flags |= FLAG_CAUSE_LENGTH_NOCHECK;
		flags |= FLAG_CAUSE_INFORMATION_NOCHECK;
	} else {
		memcpy(cause->information, info, info_length);
	}
	memset(cause->information + info_length, 0, padding_length);
	return sctp_cause_list_item_new((struct sctp_cause *)cause,
	                                length, flags);
}

struct sctp_cause_list_item *
sctp_protocol_violation_cause_new(char *info)
{
	struct sctp_protocol_violation_cause *cause;
	u32 flags;
	u16 length, info_length, padding_length;

	assert(info == NULL ||
	       (strlen(info) <=
	        MAX_SCTP_PARAMETER_BYTES - sizeof(struct sctp_protocol_violation_cause)));
	flags = 0;
	if (info == NULL) {
		info_length = 0;
	} else {
		info_length = strlen(info);
	}
	length = info_length + sizeof(struct sctp_protocol_violation_cause);
	padding_length = length % 4;
	if (padding_length > 0) {
		padding_length = 4 - padding_length;
	}
	cause = malloc(length + padding_length);
	assert(cause != NULL);
	cause->code = htons(SCTP_PROTOCOL_VIOLATION_CAUSE_CODE);
	cause->length = htons(length);
	if (info == NULL) {
		flags |= FLAG_CAUSE_LENGTH_NOCHECK;
		flags |= FLAG_CAUSE_INFORMATION_NOCHECK;
	} else {
		memcpy(cause->information, info, info_length);
	}
	memset(cause->information + info_length, 0, padding_length);
	return sctp_cause_list_item_new((struct sctp_cause *)cause,
	                                length, flags);
}

struct sctp_cause_list *
sctp_cause_list_new(void)
{
	struct sctp_cause_list *list;

	list = malloc(sizeof(struct sctp_cause_list));
	assert(list != NULL);
	list->first = NULL;
	list->last = NULL;
	list->length = 0;
	return list;
}

void
sctp_cause_list_append(struct sctp_cause_list *list,
                       struct sctp_cause_list_item *item)
{
	u16 padding_length;

	assert(item->next == NULL);
	padding_length = list->length % 4;
	if (padding_length > 0) {
		padding_length = 4 - padding_length;
	}
	list->length += padding_length;
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

void
sctp_cause_list_free(struct sctp_cause_list *list)
{
	struct sctp_cause_list_item *current_item, *next_item;

	assert(list != NULL);
	current_item = list->first;
	while (current_item != NULL) {
		next_item = current_item->next;
		assert(next_item != NULL || current_item == list->last);
		free(current_item);
		current_item = next_item;
	}
	free(list);
}

struct packet *
new_sctp_packet(int address_family,
                enum direction_t direction,
                enum ip_ecn_t ecn,
                s64 tag,
                bool bad_crc32c,
                struct sctp_chunk_list *list,
                char **error)
{
	struct packet *packet;  /* the newly-allocated result packet */
	struct header *sctp_header;  /* the SCTP header info */
	struct sctp_chunk_list_item *chunk_item;
	struct sctp_parameter_list_item *parameter_item;
	struct sctp_cause_list_item *cause_item;
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
		for (chunk_item = list->first;
		     chunk_item != NULL;
		     chunk_item = chunk_item->next) {
			for (parameter_item = chunk_item->parameter_list->first;
			     parameter_item != NULL;
			     parameter_item = parameter_item->next) {
				if (ntohs(parameter_item->parameter->type) ==
				    SCTP_STATE_COOKIE_PARAMETER_TYPE) {
					continue;
				}
				if (parameter_item->flags & FLAG_PARAMETER_LENGTH_NOCHECK) {
					asprintf(error,
						 "parameter length must be specified for inbound packets");
					return NULL;
				}
				if (parameter_item->flags & FLAG_PARAMETER_VALUE_NOCHECK) {
					asprintf(error,
						 "parameter value must be specified for inbound packets");
					return NULL;
				}
			}
			for (cause_item = chunk_item->cause_list->first;
			     cause_item != NULL;
			     cause_item = cause_item->next) {
				if (cause_item->flags & FLAG_CAUSE_LENGTH_NOCHECK) {
					asprintf(error,
						 "cause length must be specified for inbound packets");
					return NULL;
				}
				if (cause_item->flags & FLAG_CAUSE_INFORMATION_NOCHECK) {
					asprintf(error,
						 "cause information must be specified for inbound packets");
					return NULL;
				}
			}
			switch (chunk_item->chunk->type) {
			case SCTP_DATA_CHUNK_TYPE:
				if (chunk_item->flags & FLAG_CHUNK_FLAGS_NOCHECK) {
					asprintf(error,
						 "chunk flags must be specified for inbound packets");
					return NULL;
				}
				if (chunk_item->flags & FLAG_CHUNK_LENGTH_NOCHECK) {
					asprintf(error,
						 "chunk length must be specified for inbound packets");
					return NULL;
				}
				if (chunk_item->flags & FLAG_DATA_CHUNK_TSN_NOCHECK) {
					asprintf(error,
						 "TSN must be specified for inbound packets");
					return NULL;
				}
				if (chunk_item->flags & FLAG_DATA_CHUNK_SID_NOCHECK) {
					asprintf(error,
						 "SID must be specified for inbound packets");
					return NULL;
				}
				if (chunk_item->flags & FLAG_DATA_CHUNK_SSN_NOCHECK) {
					asprintf(error,
						 "SSN must be specified for inbound packets");
					return NULL;
				}
				if (chunk_item->flags & FLAG_DATA_CHUNK_PPID_NOCHECK) {
					asprintf(error,
						 "PPID must be specified for inbound packets");
					return NULL;
				}
				break;
			case SCTP_INIT_CHUNK_TYPE:
				if (chunk_item->flags & FLAG_INIT_CHUNK_TAG_NOCHECK) {
					asprintf(error,
						 "TAG must be specified for inbound packets");
					return NULL;
				}
				if (chunk_item->flags & FLAG_INIT_CHUNK_A_RWND_NOCHECK) {
					asprintf(error,
						 "A_RWND must be specified for inbound packets");
					return NULL;
				}
				if (chunk_item->flags & FLAG_INIT_CHUNK_OS_NOCHECK) {
					asprintf(error,
						 "OS must be specified for inbound packets");
					return NULL;
				}
				if (chunk_item->flags & FLAG_INIT_CHUNK_IS_NOCHECK) {
					asprintf(error,
						 "IS must be specified for inbound packets");
					return NULL;
				}
				if (chunk_item->flags & FLAG_INIT_CHUNK_OPT_PARAM_NOCHECK) {
					asprintf(error,
						 "list of optional parameters must be specified for inbound packets");
					return NULL;
				}
				break;
			case SCTP_INIT_ACK_CHUNK_TYPE:
				if (chunk_item->flags & FLAG_INIT_ACK_CHUNK_TAG_NOCHECK) {
					asprintf(error,
						 "TAG must be specified for inbound packets");
					return NULL;
				}
				if (chunk_item->flags & FLAG_INIT_ACK_CHUNK_A_RWND_NOCHECK) {
					asprintf(error,
						 "A_RWND must be specified for inbound packets");
					return NULL;
				}
				if (chunk_item->flags & FLAG_INIT_ACK_CHUNK_OS_NOCHECK) {
					asprintf(error,
						 "OS must be specified for inbound packets");
					return NULL;
				}
				if (chunk_item->flags & FLAG_INIT_ACK_CHUNK_IS_NOCHECK) {
					asprintf(error,
						 "IS must be specified for inbound packets");
					return NULL;
				}
				if (chunk_item->flags & FLAG_INIT_ACK_CHUNK_OPT_PARAM_NOCHECK) {
					asprintf(error,
						 "list of optional parameters must be specified for inbound packets");
					return NULL;
				}
				break;
			case SCTP_SACK_CHUNK_TYPE:
				if (chunk_item->flags & FLAG_SACK_CHUNK_CUM_TSN_NOCHECK) {
					asprintf(error,
						 "CUM_TSN must be specified for inbound packets");
					return NULL;
				}
				if (chunk_item->flags & FLAG_SACK_CHUNK_A_RWND_NOCHECK) {
					asprintf(error,
						 "A_RWND must be specified for inbound packets");
					return NULL;
				}
				if (chunk_item->flags & FLAG_SACK_CHUNK_GAP_BLOCKS_NOCHECK) {
					asprintf(error,
						 "GAP_BLOCKS must be specified for inbound packets");
					return NULL;
				}
				if (chunk_item->flags & FLAG_SACK_CHUNK_DUP_TSNS_NOCHECK) {
					asprintf(error,
						 "DUP_TSNS must be specified for inbound packets");
					return NULL;
				}
				break;
			case SCTP_HEARTBEAT_CHUNK_TYPE:
				break;
			case SCTP_HEARTBEAT_ACK_CHUNK_TYPE:
				overbook = true;
				break;
			case SCTP_ABORT_CHUNK_TYPE:
				if (chunk_item->flags & FLAG_CHUNK_LENGTH_NOCHECK) {
					asprintf(error,
						 "error causes must be specified for inbound packets");
					return NULL;
				}
				break;
			case SCTP_SHUTDOWN_CHUNK_TYPE:
				if (chunk_item->flags & FLAG_SHUTDOWN_CHUNK_CUM_TSN_NOCHECK) {
					asprintf(error,
						 "TSN must be specified for inbound packets");
					return NULL;
				}
				break;
			case SCTP_SHUTDOWN_ACK_CHUNK_TYPE:
				break;
			case SCTP_ERROR_CHUNK_TYPE:
				if (chunk_item->flags & FLAG_CHUNK_LENGTH_NOCHECK) {
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
				if (chunk_item->flags & FLAG_ECNE_CHUNK_LOWEST_TSN_NOCHECK) {
					asprintf(error,
						 "LOWEST_TSN must be specified for inbound packets");
					return NULL;
				}
				break;
			case SCTP_CWR_CHUNK_TYPE:
				if (chunk_item->flags & FLAG_CWR_CHUNK_LOWEST_TSN_NOCHECK) {
					asprintf(error,
						 "LOWEST_TSN must be specified for inbound packets");
					return NULL;
				}
				break;
			case SCTP_SHUTDOWN_COMPLETE_CHUNK_TYPE:
				break;
			case SCTP_PAD_CHUNK_TYPE:
				if (chunk_item->flags & FLAG_CHUNK_LENGTH_NOCHECK) {
					asprintf(error,
						 "chunk length must be specified for inbound packets");
					return NULL;
				}
				break;
			default:
				if (chunk_item->flags & FLAG_CHUNK_TYPE_NOCHECK) {
					asprintf(error,
						 "chunk type must be specified for inbound packets");
					return NULL;
				}
				if (chunk_item->flags & FLAG_CHUNK_FLAGS_NOCHECK) {
					asprintf(error,
						 "chunk flags must be specified for inbound packets");
					return NULL;
				}
				if (chunk_item->flags & FLAG_CHUNK_LENGTH_NOCHECK) {
					asprintf(error,
						 "chunk length must be specified for inbound packets");
					return NULL;
				}
				break;
			}
		}
	} else {
		if (bad_crc32c) {
			asprintf(error,
				 "bad CRC32C can only be requested for inbound packets");
			return NULL;
		}
	}

	/* Allocate and zero out a packet object of the desired size */
	packet = packet_new(overbook ? MAX_SCTP_DATAGRAM_BYTES : ip_bytes);
	memset(packet->buffer, 0, overbook ? MAX_SCTP_DATAGRAM_BYTES : ip_bytes);

	packet->direction = direction;
	packet->flags = 0;
	if (bad_crc32c) {
		packet->flags |= FLAGS_SCTP_BAD_CRC32C;
	}
	if (tag != -1) {
		packet->flags |= FLAGS_SCTP_EXPLICIT_TAG;
	}
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
	packet->sctp->v_tag = htonl((u32)tag);
	packet->sctp->crc32c = htonl(0);

	for (chunk_item = list->first;
	     chunk_item != NULL;
	     chunk_item = chunk_item->next) {
		memcpy(sctp_chunk_start, chunk_item->chunk, chunk_item->length);
		for (parameter_item = chunk_item->parameter_list->first;
		     parameter_item != NULL;
		     parameter_item = parameter_item->next) {
			parameter_item->parameter =
			    (struct sctp_parameter *)(sctp_chunk_start +
			                              ((u8 *)parameter_item->parameter -
			                               (u8 *)chunk_item->chunk));
		}
		for (cause_item = chunk_item->cause_list->first;
		     cause_item != NULL;
		     cause_item = cause_item->next) {
			cause_item->cause =
			    (struct sctp_cause *)(sctp_chunk_start +
			                         ((u8 *)cause_item->cause -
			                          (u8 *)chunk_item->chunk));
		}
		free(chunk_item->chunk);
		chunk_item->chunk = (struct sctp_chunk *)sctp_chunk_start;
		sctp_chunk_start += chunk_item->length;
	}
	free(packet->chunk_list);
	packet->chunk_list = list;
	packet->ip_bytes = ip_bytes;
	return packet;
}

#ifdef DEBUG_LOGGING
static void print_sctp_byte_list(struct sctp_byte_list *list) {
	struct sctp_byte_list_item *item;

	for (item = list->first; item != NULL; item = item->next) {
		DEBUGP("0x%.2x,", item->byte);
	}
}
#endif

struct packet *
new_sctp_generic_packet(int address_family,
                enum direction_t direction,
                enum ip_ecn_t ecn,
                s64 tag,
                bool bad_crc32c,
                struct sctp_byte_list *bytes,
                char **error) {
	struct packet *packet;  /* the newly-allocated result packet */
	struct header *sctp_header;  /* the SCTP header info */
	struct sctp_byte_list_item *item = NULL;
	/* Calculate lengths in bytes of all sections of the packet */
	const int ip_option_bytes = 0;
	const int ip_header_bytes = (ip_header_min_len(address_family) +
				     ip_option_bytes);
	const int sctp_header_bytes = sizeof(struct sctp_common_header);
	const int sctp_chunk_bytes = bytes->nr_entries;
	const int ip_bytes =
		 ip_header_bytes + sctp_header_bytes + sctp_chunk_bytes;
	bool overbook = false;
	u16 i;

#ifdef DEBUG_LOGGING
	print_sctp_byte_list(bytes);
#endif

	if (direction == DIRECTION_OUTBOUND) {
		asprintf(error,
			"generic packets can only be specified as inbound.");
		return NULL;
	}

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

	/* Allocate and zero out a packet object of the desired size */
	packet = packet_new(overbook ? MAX_SCTP_DATAGRAM_BYTES : ip_bytes);
	memset(packet->buffer, 0, overbook ? MAX_SCTP_DATAGRAM_BYTES : ip_bytes);

	packet->direction = direction;
	packet->flags = FLAGS_SCTP_GENERIC_PACKET;
	if (bad_crc32c) {
		packet->flags |= FLAGS_SCTP_BAD_CRC32C;
	}
	if (tag != -1) {
		packet->flags |= FLAGS_SCTP_EXPLICIT_TAG;
	}
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
	packet->sctp->v_tag = htonl((u32)tag);
	packet->sctp->crc32c = htonl(0);

	for (i = 0, item = bytes->first; item != NULL; i++, item = item->next) {
		sctp_chunk_start[i] = item->byte;
	}

	packet->chunk_list = NULL;
	packet->ip_bytes = ip_bytes;
	return packet;
}