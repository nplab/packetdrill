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
 * Interface for a module to allow iteration over TCP options in wire format.
 */

#ifndef __SCTP_ITERATOR_H__
#define __SCTP_ITERATOR_H__

#include "types.h"

#include "packet.h"

/* Internal state for an iterator for SCTP chunks in wire format. */
struct sctp_chunks_iterator {
	u8 *current_chunk;
	u8 *packet_end;
};

/* Internal state for an iterator for SCTP parameters in wire format. */
struct sctp_parameters_iterator {
	u8 *current_parameter;
	u8 *end;
};

/* Internal state for an iterator for SCTP causes in wire format. */
struct sctp_causes_iterator {
	u8 *current_cause;
	u8 *chunk_end;
};

/* Initialize the iterator to iterate over the SCTP chunks in the
 * given packet. Return a pointer to the first chunk in the packet,
 * or NULL if there are none.
 */
extern struct sctp_chunk *sctp_chunks_begin(
	struct packet *packet,
	struct sctp_chunks_iterator *iter,
	char **error);

/* Return a pointer to the next chunk in the packet, or NULL if there
 * are no more. On failure returns NULL and sets error message.
 */
extern struct sctp_chunk *sctp_chunks_next(
	struct sctp_chunks_iterator *iter,
	char **error);

/* Initialize the iterator to iterate over the SCTP parameters in the
 * given chunk. Return a pointer to the first parameter in the chunk,
 * or NULL if there are none or an error is present. This the error case
 * *error is not NULL.
 */
extern struct sctp_parameter *sctp_parameters_begin(
	u8 *begin,
	u16 length,
	struct sctp_parameters_iterator *iter,
	char **error);

/* Return a pointer to the next parameter in the chunk, or NULL if there
 * are no more. On failure returns NULL and sets error message.
 */
extern struct sctp_parameter *sctp_parameters_next(
	struct sctp_parameters_iterator *iter,
	char **error);

/* Initialize the iterator to iterate over the SCTP causes in the
 * given chunk. Return a pointer to the first cause in the chunk,
 * or NULL if there are none or an error is present. This the error case
 * *error is not NULL.
 */
extern struct sctp_cause *sctp_causes_begin(
	struct sctp_chunk *chunk,
	u16 offset,
	struct sctp_causes_iterator *iter,
	char **error);

/* Return a pointer to the next cause in the chunk, or NULL if there
 * are no more. On failure returns NULL and sets error message.
 */
extern struct sctp_cause *sctp_causes_next(
	struct sctp_causes_iterator *iter,
	char **error);

#endif /* __SCTP_ITERATOR_H__ */
