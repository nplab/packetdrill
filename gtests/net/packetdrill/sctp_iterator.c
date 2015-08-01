/*
 * Copyright 2013 Google Inc.
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
 * Implementation for module to allow iteration over SCTP chunks and
 * parameters in wire format.
 */

#include "sctp_iterator.h"

#include <stdlib.h>
#include <string.h>
#include "packet.h"

static struct sctp_chunk *get_current_chunk(struct sctp_chunks_iterator *iter,
					    char **error)
{
	struct sctp_chunk *chunk;
	u16 chunk_length;

	if (iter->current_chunk == iter->packet_end)
		iter->current_chunk = NULL;
	else if (iter->current_chunk + sizeof(struct sctp_chunk) >
		 iter->packet_end) {
		asprintf(error, "Partial SCTP chunk not allowed");
		iter->current_chunk = NULL;
	} else {
		chunk = (struct sctp_chunk *)iter->current_chunk;
		chunk_length = ntohs(chunk->length);
		if (iter->current_chunk + chunk_length > iter->packet_end) {
			asprintf(error,
				 "Partial SCTP chunk (type 0x%02x, length %u) not allowed",
				 chunk->type, chunk_length);
			iter->current_chunk = NULL;
		}
	}
	return (struct sctp_chunk *)iter->current_chunk;
}

struct sctp_chunk *sctp_chunks_begin(struct packet *packet,
				     struct sctp_chunks_iterator *iter,
				     char **error)
{
	assert(*error == NULL);
	memset(iter, 0, sizeof(*iter));
	iter->current_chunk = packet_payload(packet);
	iter->packet_end = packet_end(packet);
	return get_current_chunk(iter, error);
}

struct sctp_chunk *sctp_chunks_next(struct sctp_chunks_iterator *iter,
				    char **error)
{
	u16 chunk_length, padding_length;
	struct sctp_chunk *current_chunk;

	if (*error) printf("!!!%s!!!\n", *error);
	assert(*error == NULL);
	current_chunk = (struct sctp_chunk *)iter->current_chunk;
	chunk_length = ntohs(current_chunk->length);
	padding_length = chunk_length & 0x0003;
	if (padding_length > 0)
		padding_length = 4 - padding_length;
	assert(chunk_length >= sizeof(struct sctp_chunk));
	assert(padding_length < 4);
	iter->current_chunk += chunk_length;
	if (iter->packet_end - iter->current_chunk < padding_length)
		iter->current_chunk = iter->packet_end;
	else
		iter->current_chunk += padding_length;
	return get_current_chunk(iter, error);
}

static struct sctp_parameter *
get_current_parameter(struct sctp_parameters_iterator *iter,
		      char **error)
{
	struct sctp_parameter *parameter;
	u16 parameter_length;

	if (iter->current_parameter == iter->end)
		iter->current_parameter = NULL;
	else if (iter->current_parameter + sizeof(struct sctp_parameter) >
		 iter->end) {
		asprintf(error, "Partial SCTP parameter not allowed");
		iter->current_parameter = NULL;
	} else {
		parameter = (struct sctp_parameter *)iter->current_parameter;
		parameter_length = ntohs(parameter->length);
		if (iter->current_parameter + parameter_length > iter->end) {
			asprintf(error,
				 "Partial SCTP parameter (type 0x%04x, length %u) not allowed",
				 ntohs(parameter->type), parameter_length);
			iter->current_parameter = NULL;
		}
	}
	return (struct sctp_parameter *)iter->current_parameter;
}

struct sctp_parameter *
sctp_parameters_begin(u8 *begin,
		      u16 length,
		      struct sctp_parameters_iterator *iter,
		      char **error)
{
	assert(*error == NULL);
	memset(iter, 0, sizeof(*iter));
	iter->current_parameter = begin;
	iter->end = begin + length;
	return get_current_parameter(iter, error);
}

struct sctp_parameter *
sctp_parameters_next(struct sctp_parameters_iterator *iter,
		     char **error)
{
	u16 parameter_length, padding_length;
	struct sctp_parameter *current_parameter;

	assert(*error == NULL);
	current_parameter = (struct sctp_parameter *)iter->current_parameter;
	parameter_length = ntohs(current_parameter->length);
	padding_length = parameter_length & 0x0003;
	if (padding_length > 0)
		padding_length = 4 - padding_length;
	assert(parameter_length >= sizeof(struct sctp_parameter));
	assert(padding_length < 4);
	iter->current_parameter += parameter_length;
	if (iter->end - iter->current_parameter < padding_length)
		iter->current_parameter = iter->end;
	else
		iter->current_parameter += padding_length;
	return get_current_parameter(iter, error);
}

static struct sctp_cause *get_current_cause(struct sctp_causes_iterator *iter,
					    char **error)
{
	struct sctp_cause *cause;
	u16 cause_length;

	if (iter->current_cause == iter->chunk_end)
		iter->current_cause = NULL;
	else if (iter->current_cause + sizeof(struct sctp_cause) >
		 iter->chunk_end) {
		asprintf(error, "Partial SCTP cause not allowed");
		iter->current_cause = NULL;
	} else {
		cause = (struct sctp_cause *)iter->current_cause;
		cause_length = ntohs(cause->length);
		if (iter->current_cause + cause_length > iter->chunk_end) {
			asprintf(error,
				 "Partial SCTP cause (code 0x%04x, length %u) not allowed",
				 ntohs(cause->code), cause_length);
			iter->current_cause = NULL;
		}
	}
	return (struct sctp_cause *)iter->current_cause;
}

struct sctp_cause *sctp_causes_begin(struct sctp_chunk *chunk,
				     u16 offset,
				     struct sctp_causes_iterator *iter,
				     char **error)
{
	assert(*error == NULL);
	memset(iter, 0, sizeof(*iter));
	iter->current_cause = (u8 *)chunk + offset;
	iter->chunk_end = (u8 *)chunk + ntohs(chunk->length);
	return get_current_cause(iter, error);
}

struct sctp_cause *sctp_causes_next(struct sctp_causes_iterator *iter,
				    char **error)
{
	u16 cause_length, padding_length;
	struct sctp_cause *current_cause;

	assert(*error == NULL);
	current_cause = (struct sctp_cause *)iter->current_cause;
	cause_length = ntohs(current_cause->length);
	padding_length = cause_length & 0x0003;
	if (padding_length > 0)
		padding_length = 4 - padding_length;
	assert(cause_length >= sizeof(struct sctp_cause));
	assert(padding_length < 4);
	iter->current_cause += cause_length;
	if (iter->chunk_end - iter->current_cause < padding_length)
		iter->current_cause = iter->chunk_end;
	else
		iter->current_cause += padding_length;
	return get_current_cause(iter, error);
}
