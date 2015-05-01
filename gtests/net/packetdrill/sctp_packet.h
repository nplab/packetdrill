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
 * Interface for module for formatting SCTP packets.
 */

#ifndef __SCTP_PACKET_H__
#define __SCTP_PACKET_H__

#include "types.h"
#include "packet.h"
#include "sctp.h"

struct sctp_chunk_list_item {
	struct sctp_chunk_list_item *next;
	struct sctp_chunk *chunk;
	/* total length in bytes */
	u32 length;
	/* metadata */
	u32 flags;
};

struct sctp_chunk_list {
	struct sctp_chunk_list_item *first;
	struct sctp_chunk_list_item *last;
	/* length in bytes */
	u32 length;
};

#define FLAG_CHUNK_TYPE_NOCHECK                 0x00000001
#define FLAG_CHUNK_FLAGS_NOCHECK                0x00000002
#define FLAG_CHUNK_LENGTH_NOCHECK               0x00000004
#define FLAG_CHUNK_VALUE_NOCHECK                0x00000008

struct sctp_chunk_list_item *
sctp_chunk_list_item_new(struct sctp_chunk *chunk, u32 length, u32 flags);

#define FLAG_DATA_CHUNK_TSN_NOCHECK             0x00000100
#define FLAG_DATA_CHUNK_SID_NOCHECK             0x00000200
#define FLAG_DATA_CHUNK_SSN_NOCHECK             0x00000400
#define FLAG_DATA_CHUNK_PPID_NOCHECK            0x00000800

struct sctp_chunk_list_item *
sctp_data_chunk_new(s64 tsn, s64 sid, s64 ssn, s64 ppid);

#define FLAG_INIT_CHUNK_A_RWND_NOCHECK          0x00000100
#define FLAG_INIT_CHUNK_OS_NOCHECK              0x00000200
#define FLAG_INIT_CHUNK_IS_NOCHECK              0x00000400

struct sctp_chunk_list_item *
sctp_init_chunk_new(s64 tag, s64 a_rwnd, s64 os, s64 is, s64 tsn);

#define FLAG_INIT_ACK_CHUNK_A_RWND_NOCHECK      0x00000100
#define FLAG_INIT_ACK_CHUNK_OS_NOCHECK          0x00000200
#define FLAG_INIT_ACK_CHUNK_IS_NOCHECK          0x00000400

struct sctp_chunk_list_item *
sctp_init_ack_chunk_new(s64 tag, s64 a_rwnd, s64 os, s64 is, s64 tsn);

#define FLAG_SACK_CHUNK_CUM_TSN_NOCHECK         0x00000100
#define FLAG_SACK_CHUNK_A_RWND_NOCHECK          0x00000200
#define FLAG_SACK_CHUNK_GAP_BLOCKS_NOCHECK      0x00000400
#define FLAG_SACK_CHUNK_DUP_TSNS_NOCHECK        0x00000800

struct sctp_chunk_list_item *
sctp_sack_chunk_new(s64 cum_tsn, s64 a_rwnd);

struct sctp_chunk_list_item *
sctp_heartbeat_chunk_new(u8 flags);

struct sctp_chunk_list_item *
sctp_heartbeat_ack_chunk_new(u8 flags);

struct sctp_chunk_list_item *
sctp_abort_chunk_new(u8 flags);

#define FLAG_SHUTDOWN_CHUNK_CUM_TSN_NOCHECK     0x00000100

struct sctp_chunk_list_item *
sctp_shutdown_chunk_new(s64 cum_tsn);

struct sctp_chunk_list_item *
sctp_shutdown_ack_chunk_new(u8 flags);

struct sctp_chunk_list_item *
sctp_error_chunk_new(u8 flags);

struct sctp_chunk_list_item *
sctp_cookie_echo_chunk_new(u8 flags);

struct sctp_chunk_list_item *
sctp_cookie_ack_chunk_new(u8 flags);

#define FLAG_ECNE_CHUNK_LOWEST_TSN_NOCHECK      0x00000100

struct sctp_chunk_list_item *
sctp_ecne_chunk_new(s64 lowest_tsn);

#define FLAG_CWR_CHUNK_LOWEST_TSN_NOCHECK       0x00000100

struct sctp_chunk_list_item *
sctp_cwr_chunk_new(s64 lowest_tsn);

struct sctp_chunk_list_item *
sctp_shutdown_complete_chunk_new(u8 flags);

struct sctp_chunk_list *sctp_chunk_list_new(void);

void sctp_chunk_list_append(struct sctp_chunk_list *list,
			    struct sctp_chunk_list_item *item);

void sctp_chunk_list_free(struct sctp_chunk_list *list);

/* Create and initialize a new struct packet containing a SCTP packet.
 * On success, returns a newly-allocated packet. On failure, returns NULL
 * and fills in *error with an error message.
 */
extern struct packet *new_sctp_packet(int address_family,
				      enum direction_t direction,
				      enum ip_ecn_t ecn,
				      struct sctp_chunk_list *chunk_list,
				      char **error);
#endif /* __SCTP_PACKET_H__ */
