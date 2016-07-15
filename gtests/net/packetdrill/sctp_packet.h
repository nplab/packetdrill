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

struct sctp_byte_list_item {
	struct sctp_byte_list_item *next;
	u8 byte;
};

struct sctp_byte_list {
	struct sctp_byte_list_item *first;
	struct sctp_byte_list_item *last;
	u16 nr_entries;
};

struct sctp_byte_list *
sctp_byte_list_new(void);

void
sctp_byte_list_append(struct sctp_byte_list *list,
                      struct sctp_byte_list_item *item);

void
sctp_byte_list_free(struct sctp_byte_list *list);

struct sctp_byte_list_item *
sctp_byte_list_item_new(u8 byte);

struct sctp_u16_list_item {
	struct sctp_u16_list_item *next;
	u16 value;
};

struct sctp_u16_list {
	struct sctp_u16_list_item *first;
	struct sctp_u16_list_item *last;
	u16 nr_entries;
};

struct sctp_u16_list *
sctp_u16_list_new(void);

void
sctp_u16_list_append(struct sctp_u16_list *list,
		     struct sctp_u16_list_item *item);

void
sctp_u16_list_free(struct sctp_u16_list *list);

struct sctp_u16_list_item *
sctp_u16_list_item_new(u16 val);

struct sctp_sack_block_list_item {
	struct sctp_sack_block_list_item *next;
	union sctp_sack_block block;
};

struct sctp_sack_block_list {
	struct sctp_sack_block_list_item *first;
	struct sctp_sack_block_list_item *last;
	u16 nr_entries;
};

struct sctp_sack_block_list *
sctp_sack_block_list_new(void);

void
sctp_sack_block_list_append(struct sctp_sack_block_list *list,
			    struct sctp_sack_block_list_item *item);

void
sctp_sack_block_list_free(struct sctp_sack_block_list *list);

struct sctp_sack_block_list_item *
sctp_sack_block_list_item_gap_new(u16 start, u16 end);

struct sctp_sack_block_list_item *
sctp_sack_block_list_item_dup_new(u32 tsn);

struct sctp_address_type_list_item {
	struct sctp_address_type_list_item *next;
	u16 address_type;
};

struct sctp_address_type_list {
	struct sctp_address_type_list_item *first;
	struct sctp_address_type_list_item *last;
	u16 nr_entries;
};

struct sctp_address_type_list *
sctp_address_type_list_new(void);

void
sctp_address_type_list_append(struct sctp_address_type_list *list,
			      struct sctp_address_type_list_item *item);

void
sctp_address_type_list_free(struct sctp_address_type_list *list);

struct sctp_address_type_list_item *
sctp_address_type_list_item_new(u16 address_type);

struct sctp_parameter_type_list_item {
	struct sctp_parameter_type_list_item *next;
	u16 parameter_type;
};

struct sctp_parameter_type_list {
	struct sctp_parameter_type_list_item *first;
	struct sctp_parameter_type_list_item *last;
	u16 nr_entries;
};

struct sctp_parameter_type_list *
sctp_parameter_type_list_new(void);

void
sctp_parameter_type_list_append(struct sctp_parameter_type_list *list,
			        struct sctp_parameter_type_list_item *item);

void
sctp_parameter_type_list_free(struct sctp_parameter_type_list *list);

struct sctp_parameter_type_list_item *
sctp_parameter_type_list_item_new(u16 parameter_type);

struct sctp_parameter_list_item {
	struct sctp_parameter_list_item *next;
	struct sctp_parameter *parameter;
	/* total length in bytes */
	u32 length;
	/* metadata */
	u32 flags;
};

struct sctp_parameter_list {
	struct sctp_parameter_list_item *first;
	struct sctp_parameter_list_item *last;
	/* length in bytes excluding the padding of the last parameter*/
	u32 length;
};

struct sctp_cause_list_item {
	struct sctp_cause_list_item *next;
	struct sctp_cause *cause;
	/* total length in bytes */
	u32 length;
	/* metadata */
	u32 flags;
};

struct sctp_cause_list {
	struct sctp_cause_list_item *first;
	struct sctp_cause_list_item *last;
	/* length in bytes excluding the padding of the last cause*/
	u32 length;
};

struct sctp_chunk_list_item {
	struct sctp_chunk_list_item *next;
	struct sctp_chunk *chunk;
	struct sctp_parameter_list *parameter_list;
	struct sctp_cause_list *cause_list;
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

struct sctp_chunk_list_item *
sctp_chunk_list_item_new(struct sctp_chunk *chunk, u32 length, u32 flags,
                         struct sctp_parameter_list *parameter_list,
                         struct sctp_cause_list *cause_list);

#define FLAG_CHUNK_TYPE_NOCHECK                 0x00000001
#define FLAG_CHUNK_FLAGS_NOCHECK                0x00000002
#define FLAG_CHUNK_LENGTH_NOCHECK               0x00000004
#define FLAG_CHUNK_VALUE_NOCHECK                0x00000008

struct sctp_chunk_list_item *
sctp_generic_chunk_new(s64 type, s64 flgs, s64 len,
                       struct sctp_byte_list *bytes);

#define FLAG_DATA_CHUNK_TSN_NOCHECK             0x00000100
#define FLAG_DATA_CHUNK_SID_NOCHECK             0x00000200
#define FLAG_DATA_CHUNK_SSN_NOCHECK             0x00000400
#define FLAG_DATA_CHUNK_PPID_NOCHECK            0x00000800

struct sctp_chunk_list_item *
sctp_data_chunk_new(s64 flgs, s64 len, s64 tsn, s64 sid, s64 ssn, s64 ppid);

#define FLAG_INIT_CHUNK_TAG_NOCHECK             0x00000100
#define FLAG_INIT_CHUNK_A_RWND_NOCHECK          0x00000200
#define FLAG_INIT_CHUNK_OS_NOCHECK              0x00000400
#define FLAG_INIT_CHUNK_IS_NOCHECK              0x00000800
#define FLAG_INIT_CHUNK_TSN_NOCHECK             0x00001000
#define FLAG_INIT_CHUNK_OPT_PARAM_NOCHECK       0x00002000

struct sctp_chunk_list_item *
sctp_init_chunk_new(s64 flgs, s64 tag, s64 a_rwnd, s64 os, s64 is, s64 tsn,
                    struct sctp_parameter_list *parameters);

#define FLAG_INIT_ACK_CHUNK_TAG_NOCHECK         0x00000100
#define FLAG_INIT_ACK_CHUNK_A_RWND_NOCHECK      0x00000200
#define FLAG_INIT_ACK_CHUNK_OS_NOCHECK          0x00000400
#define FLAG_INIT_ACK_CHUNK_IS_NOCHECK          0x00000800
#define FLAG_INIT_ACK_CHUNK_TSN_NOCHECK         0x00001000
#define FLAG_INIT_ACK_CHUNK_OPT_PARAM_NOCHECK   0x00002000

struct sctp_chunk_list_item *
sctp_init_ack_chunk_new(s64 flgs, s64 tag, s64 a_rwnd, s64 os, s64 is, s64 tsn,
                        struct sctp_parameter_list *parameters);

#define FLAG_SACK_CHUNK_CUM_TSN_NOCHECK         0x00000100
#define FLAG_SACK_CHUNK_A_RWND_NOCHECK          0x00000200
#define FLAG_SACK_CHUNK_GAP_BLOCKS_NOCHECK      0x00000400
#define FLAG_SACK_CHUNK_DUP_TSNS_NOCHECK        0x00000800

struct sctp_chunk_list_item *
sctp_sack_chunk_new(s64 flgs, s64 cum_tsn, s64 a_rwnd,
                    struct sctp_sack_block_list *gaps,
                    struct sctp_sack_block_list *dups);

#define FLAG_NR_SACK_CHUNK_CUM_TSN_NOCHECK         0x00000100
#define FLAG_NR_SACK_CHUNK_A_RWND_NOCHECK          0x00000200
#define FLAG_NR_SACK_CHUNK_GAP_BLOCKS_NOCHECK      0x00000400
#define FLAG_NR_SACK_CHUNK_NR_GAP_BLOCKS_NOCHECK   0x00000800
#define FLAG_NR_SACK_CHUNK_DUP_TSNS_NOCHECK        0x00001000

struct sctp_chunk_list_item *
sctp_nr_sack_chunk_new(s64 flgs, s64 cum_tsn, s64 a_rwnd,
                    struct sctp_sack_block_list *gaps,
		    struct sctp_sack_block_list *nr_gaps,
                    struct sctp_sack_block_list *dups);

struct sctp_chunk_list_item *
sctp_heartbeat_chunk_new(s64 flgs, struct sctp_parameter_list_item *info);

struct sctp_chunk_list_item *
sctp_heartbeat_ack_chunk_new(s64 flgs, struct sctp_parameter_list_item *info);

#define FLAG_ABORT_CHUNK_OPT_CAUSES_NOCHECK     0x00000100

struct sctp_chunk_list_item *
sctp_abort_chunk_new(s64 flgs, struct sctp_cause_list *causes);

#define FLAG_SHUTDOWN_CHUNK_CUM_TSN_NOCHECK     0x00000100

struct sctp_chunk_list_item *
sctp_shutdown_chunk_new(s64 flgs, s64 cum_tsn);

struct sctp_chunk_list_item *
sctp_shutdown_ack_chunk_new(s64 flgs);

#define FLAG_ERROR_CHUNK_OPT_CAUSES_NOCHECK     0x00000100

struct sctp_chunk_list_item *
sctp_error_chunk_new(s64 flgs, struct sctp_cause_list *causes);

struct sctp_chunk_list_item *
sctp_cookie_echo_chunk_new(s64 flgs, s64 len, struct sctp_byte_list *cookie);

struct sctp_chunk_list_item *
sctp_cookie_ack_chunk_new(s64 flgs);

#define FLAG_ECNE_CHUNK_LOWEST_TSN_NOCHECK      0x00000100

struct sctp_chunk_list_item *
sctp_ecne_chunk_new(s64 flgs, s64 lowest_tsn);

#define FLAG_CWR_CHUNK_LOWEST_TSN_NOCHECK       0x00000100

struct sctp_chunk_list_item *
sctp_cwr_chunk_new(s64 flgs, s64 lowest_tsn);

struct sctp_chunk_list_item *
sctp_shutdown_complete_chunk_new(s64 flgs);

#define FLAG_I_DATA_CHUNK_TSN_NOCHECK           0x00000100
#define FLAG_I_DATA_CHUNK_SID_NOCHECK           0x00000200
#define FLAG_I_DATA_CHUNK_RES_NOCHECK           0x00000400
#define FLAG_I_DATA_CHUNK_MID_NOCHECK           0x00000800
#define FLAG_I_DATA_CHUNK_PPID_NOCHECK          0x00001000
#define FLAG_I_DATA_CHUNK_FSN_NOCHECK           0x00002000

struct sctp_chunk_list_item *
sctp_i_data_chunk_new(s64 flgs, s64 len, s64 tsn, s64 sid, s64 res, s64 mid,
                      s64 ppid, s64 fsn);

struct sctp_chunk_list_item *
sctp_pad_chunk_new(s64 flgs, s64 len, u8* padding);

struct sctp_chunk_list_item *
sctp_reconfig_chunk_new(s64 flgs, struct sctp_parameter_list *parameters);

struct sctp_chunk_list *
sctp_chunk_list_new(void);

void
sctp_chunk_list_append(struct sctp_chunk_list *list,
                       struct sctp_chunk_list_item *item);

void
sctp_chunk_list_free(struct sctp_chunk_list *list);

#define FLAG_PARAMETER_TYPE_NOCHECK				0x00000001
#define FLAG_PARAMETER_LENGTH_NOCHECK				0x00000002
#define FLAG_PARAMETER_VALUE_NOCHECK				0x00000004

struct sctp_parameter_list_item *
sctp_parameter_list_item_new(struct sctp_parameter *parameter,
                             u32 length, u32 flags);

struct sctp_parameter_list_item *
sctp_generic_parameter_new(s64 type, s64 len, struct sctp_byte_list *bytes);

struct sctp_parameter_list_item *
sctp_heartbeat_information_parameter_new(s64 len, struct sctp_byte_list *bytes);

struct sctp_parameter_list_item *
sctp_ipv4_address_parameter_new(struct in_addr *addr);

struct sctp_parameter_list_item *
sctp_ipv6_address_parameter_new(struct in6_addr *addr);

struct sctp_parameter_list_item *
sctp_state_cookie_parameter_new(s64 len, u8 *cookie);

struct sctp_parameter_list_item *
sctp_unrecognized_parameters_parameter_new(struct sctp_parameter_list *list);

struct sctp_parameter_list_item *
sctp_cookie_preservative_parameter_new(s64 increment);

struct sctp_parameter_list_item *
sctp_hostname_address_parameter_new(char *hostname);

struct sctp_parameter_list_item *
sctp_supported_address_types_parameter_new(struct sctp_address_type_list *list);

struct sctp_parameter_list_item *
sctp_ecn_capable_parameter_new(void);

struct sctp_parameter_list_item *
sctp_forward_tsn_supported_parameter_new();

struct sctp_parameter_list_item *
sctp_pad_parameter_new(s64 len, u8 *padding);

struct sctp_parameter_list_item *
sctp_adaptation_indication_parameter_new(s64 val);

struct sctp_parameter_list_item *
sctp_supported_extensions_parameter_new(struct sctp_byte_list *list);

struct sctp_parameter_list_item *
sctp_pad_parameter_new(s64 len, u8 *padding);

#define FLAG_RECONFIG_REQ_SN_NOCHECK                            0x00000010
#define FLAG_RECONFIG_RESP_SN_NOCHECK                           0x00000020
#define FLAG_RECONFIG_LAST_TSN_NOCHECK                          0x00000040

struct sctp_parameter_list_item *
sctp_outgoing_ssn_reset_request_parameter_new(s64 reqsn, s64 respsn, s64 last_tsn, struct sctp_u16_list *sids);

struct sctp_parameter_list_item *
sctp_incoming_ssn_reset_request_parameter_new(s64 reqsn, struct sctp_u16_list *sids);

struct sctp_parameter_list_item *
sctp_ssn_tsn_reset_request_parameter_new(s64 reqsn);

#define FLAG_RECONFIG_RESULT_NOCHECK                            0x00000010
#define FLAG_RECONFIG_SENDER_NEXT_TSN_NOCHECK                   0x00000040
#define FLAG_RECONFIG_RECEIVER_NEXT_TSN_NOCHECK                 0x00000080

struct sctp_parameter_list_item *
sctp_reconfig_response_parameter_new(s64 respsn, s64 result, s64 sender_next_tsn, s64 receiver_next_tsn);

#define FLAG_RECONFIG_NUMBER_OF_NEW_STREAMS_NOCHECK		0x00000080

struct sctp_parameter_list_item *
sctp_add_outgoing_streams_request_parameter_new(s64 reqsn, s32 number_of_new_streams);

struct sctp_parameter_list_item *
sctp_add_incoming_streams_request_parameter_new(s64 reqsn, s32 number_of_new_streams);

struct sctp_parameter_list_item *
sctp_generic_reconfig_request_parameter_new(s32 type, s32 len, s64 reqsn, struct sctp_byte_list *payload);

struct sctp_parameter_list *
sctp_parameter_list_new(void);

void
sctp_parameter_list_append(struct sctp_parameter_list *list,
                           struct sctp_parameter_list_item *item);

void
sctp_parameter_list_free(struct sctp_parameter_list *list);

struct sctp_cause_list_item *
sctp_cause_list_item_new(struct sctp_cause *cause,
                         u32 length, u32 flags);

#define FLAG_CAUSE_CODE_NOCHECK					0x00000001
#define FLAG_CAUSE_LENGTH_NOCHECK				0x00000002
#define FLAG_CAUSE_INFORMATION_NOCHECK				0x00000004

struct sctp_cause_list_item *
sctp_generic_cause_new(s64 code, s64 len, struct sctp_byte_list *bytes);

struct sctp_cause_list_item *
sctp_invalid_stream_identifier_cause_new(s64 sid);

struct sctp_cause_list_item *
sctp_missing_mandatory_parameter_cause_new(struct sctp_parameter_type_list *list);

struct sctp_cause_list_item *
sctp_stale_cookie_error_cause_new(s64 staleness);

struct sctp_cause_list_item *
sctp_out_of_resources_cause_new(void);

struct sctp_cause_list_item *
sctp_unresolvable_address_cause_new(struct sctp_parameter_list_item *item);

struct sctp_cause_list_item *
sctp_unrecognized_chunk_type_cause_new(struct sctp_chunk_list_item *item);

struct sctp_cause_list_item *
sctp_invalid_mandatory_parameter_cause_new(void);

struct sctp_cause_list_item *
sctp_unrecognized_parameters_cause_new(struct sctp_parameter_list *list);

struct sctp_cause_list_item *
sctp_no_user_data_cause_new(s64 tsn);

struct sctp_cause_list_item *
sctp_cookie_received_while_shutdown_cause_new(void);

struct sctp_cause_list_item *
sctp_restart_with_new_addresses_cause_new(struct sctp_parameter_list *list);

struct sctp_cause_list_item *
sctp_user_initiated_abort_cause_new(char *info);

struct sctp_cause_list_item *
sctp_protocol_violation_cause_new(char *info);

struct sctp_cause_list *
sctp_cause_list_new(void);

void
sctp_cause_list_append(struct sctp_cause_list *list,
                       struct sctp_cause_list_item *item);

void
sctp_cause_list_free(struct sctp_cause_list *list);

/* Create and initialize a new struct packet containing a SCTP packet.
 * On success, returns a newly-allocated packet. On failure, returns NULL
 * and fills in *error with an error message.
 */
extern struct packet *new_sctp_packet(int address_family,
				      enum direction_t direction,
				      enum ip_ecn_t ecn,
				      s64 tag,
				      bool bad_crc32c,
				      struct sctp_chunk_list *chunk_list,
				      char **error);

struct packet *
new_sctp_generic_packet(int address_family,
                enum direction_t direction,
                enum ip_ecn_t ecn,
                s64 tag,
                bool bad_crc32c,
                struct sctp_byte_list *bytes,
                char **error);
#endif /* __SCTP_PACKET_H__ */
