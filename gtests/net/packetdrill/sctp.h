/*
 * Copyright 2013 Michael Tuexen.
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
 * Our own SCTP header declarations, so we have something that's
 * portable and somewhat more readable than a typical system header
 * file.
 */

#ifndef __SCTP_HEADERS_H__
#define __SCTP_HEADERS_H__

#include "types.h"

/* SCTP common header. See RFC 4960. */
struct sctp_common_header {
	__be16	src_port;
	__be16	dst_port;
	__be32	v_tag;
	__be32  crc32c;
} __packed;

#define SCTP_DATA_CHUNK_TYPE				0x00
#define SCTP_INIT_CHUNK_TYPE				0x01
#define SCTP_INIT_ACK_CHUNK_TYPE			0x02
#define SCTP_SACK_CHUNK_TYPE				0x03
#define SCTP_HEARTBEAT_CHUNK_TYPE			0x04
#define SCTP_HEARTBEAT_ACK_CHUNK_TYPE			0x05
#define SCTP_ABORT_CHUNK_TYPE				0x06
#define SCTP_SHUTDOWN_CHUNK_TYPE			0x07
#define SCTP_SHUTDOWN_ACK_CHUNK_TYPE			0x08
#define SCTP_ERROR_CHUNK_TYPE				0x09
#define SCTP_COOKIE_ECHO_CHUNK_TYPE			0x0a
#define SCTP_COOKIE_ACK_CHUNK_TYPE			0x0b
#define SCTP_ECNE_CHUNK_TYPE				0x0c
#define SCTP_CWR_CHUNK_TYPE				0x0d
#define SCTP_SHUTDOWN_COMPLETE_CHUNK_TYPE		0x0e
#define SCTP_I_DATA_CHUNK_TYPE				0x40
#define SCTP_RECONFIG_CHUNK_TYPE			0x82
#define SCTP_PAD_CHUNK_TYPE				0x84

#define MAX_SCTP_CHUNK_BYTES	0xffff

struct sctp_chunk {
	__u8 type;
	__u8 flags;
	__be16 length;
	__u8 value[];
} __packed;

#define SCTP_DATA_CHUNK_I_BIT				0x08
#define SCTP_DATA_CHUNK_U_BIT				0x04
#define SCTP_DATA_CHUNK_B_BIT				0x02
#define SCTP_DATA_CHUNK_E_BIT				0x01

struct sctp_data_chunk {
	__u8 type;
	__u8 flags;
	__be16 length;
	__be32 tsn;
	__be16 sid;
	__be16 ssn;
	__be32 ppid;
	__u8 data[];
} __packed;

#define SCTP_INIT_CHUNK_PARAMETER_OFFSET		20

struct sctp_init_chunk {
	__u8 type;
	__u8 flags;
	__be16 length;
	__be32 initiate_tag;
	__be32 a_rwnd;
	__be16 os;
	__be16 is;
	__be32 initial_tsn;
	__u8 parameter[];
} __packed;

struct sctp_init_ack_chunk {
	__u8 type;
	__u8 flags;
	__be16 length;
	__be32 initiate_tag;
	__be32 a_rwnd;
	__be16 os;
	__be16 is;
	__be32 initial_tsn;
	__u8 parameter[];
} __packed;

union sctp_sack_block {
	struct {
		__be16 start;
		__be16 end;
	} gap;
	u32 tsn;
} __packed;

struct sctp_sack_chunk {
	__u8 type;
	__u8 flags;
	__be16 length;
	__be32 cum_tsn;
	__be32 a_rwnd;
	__be16 nr_gap_blocks;
	__be16 nr_dup_tsns;
	union sctp_sack_block block[];
} __packed;

struct sctp_heartbeat_chunk {
	__u8 type;
	__u8 flags;
	__be16 length;
	__u8 value[];
} __packed;

struct sctp_heartbeat_ack_chunk {
	__u8 type;
	__u8 flags;
	__be16 length;
	__u8 value[];
} __packed;

#define SCTP_ABORT_CHUNK_T_BIT				0x01
#define SCTP_ABORT_CHUNK_CAUSE_OFFSET			4

struct sctp_abort_chunk {
	__u8 type;
	__u8 flags;
	__be16 length;
	__u8 cause[];
} __packed;

struct sctp_shutdown_chunk {
	__u8 type;
	__u8 flags;
	__be16 length;
	__be32 cum_tsn;
} __packed;

struct sctp_shutdown_ack_chunk {
	__u8 type;
	__u8 flags;
	__be16 length;
} __packed;

#define SCTP_ERROR_CHUNK_CAUSE_OFFSET			4

struct sctp_error_chunk {
	__u8 type;
	__u8 flags;
	__be16 length;
	__u8 cause[];
} __packed;

struct sctp_cookie_echo_chunk {
	__u8 type;
	__u8 flags;
	__be16 length;
	__u8 cookie[];
} __packed;

struct sctp_cookie_ack_chunk {
	__u8 type;
	__u8 flags;
	__be16 length;
} __packed;

struct sctp_ecne_chunk {
	__u8 type;
	__u8 flags;
	__be16 length;
	__be32 lowest_tsn;
} __packed;

struct sctp_cwr_chunk {
	__u8 type;
	__u8 flags;
	__be16 length;
	__be32 lowest_tsn;
} __packed;

#define SCTP_SHUTDOWN_COMPLETE_CHUNK_T_BIT		0x01

struct sctp_shutdown_complete_chunk {
	__u8 type;
	__u8 flags;
	__be16 length;
} __packed;

#define SCTP_I_DATA_CHUNK_I_BIT				0x08
#define SCTP_I_DATA_CHUNK_U_BIT				0x04
#define SCTP_I_DATA_CHUNK_B_BIT				0x02
#define SCTP_I_DATA_CHUNK_E_BIT				0x01

struct sctp_i_data_chunk {
	__u8 type;
	__u8 flags;
	__be16 length;
	__be32 tsn;
	__be16 sid;
	__be16 res;
	__be32 mid;
	union {
		__be32 ppid;
		__be32 fsn;
	} field;
	__u8 data[];
} __packed;

struct sctp_pad_chunk {
	__u8 type;
	__u8 flags;
	__be16 length;
	__u8 padding_data[];
} __packed;

struct sctp_reconfig_chunk {
	__u8 type;
	__u8 flags;
	__be16 length;
	__u8 parameter[];
} __packed;

#define SCTP_HEARTBEAT_INFORMATION_PARAMETER_TYPE	0x0001
#define SCTP_IPV4_ADDRESS_PARAMETER_TYPE		0x0005
#define SCTP_IPV6_ADDRESS_PARAMETER_TYPE		0x0006
#define SCTP_STATE_COOKIE_PARAMETER_TYPE		0x0007
#define SCTP_UNRECOGNIZED_PARAMETER_PARAMETER_TYPE	0x0008
#define SCTP_COOKIE_PRESERVATIVE_PARAMETER_TYPE		0x0009
#define SCTP_HOSTNAME_ADDRESS_PARAMETER_TYPE		0x000b
#define SCTP_SUPPORTED_ADDRESS_TYPES_PARAMETER_TYPE	0x000c
#define SCTP_OUTGOING_SSN_RESET_REQUEST_PARAMETER_TYPE  0x000d
#define SCTP_INCOMING_SSN_RESET_REQUEST_PARAMETER_TYPE  0x000e
#define SCTP_SSN_TSN_RESET_REQUEST_PARAMETER_TYPE       0x000f
#define SCTP_RECONFIG_RESPONSE_PARAMETER_TYPE           0x0010
#define SCTP_ADD_OUTGOING_STREAMS_REQUEST_PARAMETER_TYPE 0x0011
#define SCTP_ADD_INCOMING_STREAMS_REQUEST_PARAMETER_TYPE 0x0012
#define SCTP_ECN_CAPABLE_PARAMETER_TYPE			0x8000
#define SCTP_SUPPORTED_EXTENSIONS_PARAMETER_TYPE	0x8008
#define SCTP_PAD_PARAMETER_TYPE				0x8005
#define SCTP_Set_Primary_Address			0xc004
#define SCTP_ADAPTATION_INDICATION_PARAMETER_TYPE	0xc006
#define SCTP_FORWARD_TSN_SUPPORTED_PARAMETER_TYPE       0xc000

#define MAX_SCTP_PARAMETER_BYTES			0xffff

struct sctp_parameter {
	__be16 type;
	__be16 length;
	__u8 value[];
} __packed;

struct sctp_heartbeat_information_parameter {
	__be16 type;
	__be16 length;
	__u8 information[];
} __packed;

struct sctp_ipv4_address_parameter {
	__be16 type;
	__be16 length;
	struct in_addr addr;
} __packed;

struct sctp_ipv6_address_parameter {
	__be16 type;
	__be16 length;
	struct in6_addr addr;
} __packed;

struct sctp_state_cookie_parameter {
	__be16 type;
	__be16 length;
	__u8 cookie[];
} __packed;

struct sctp_unrecognized_parameter_parameter {
	__be16 type;
	__be16 length;
	__u8 value[];
} __packed;

struct sctp_cookie_preservative_parameter {
	__be16 type;
	__be16 length;
	__be32 increment;
} __packed;

struct sctp_hostname_address_parameter {
	__be16 type;
	__be16 length;
	char hostname[];
} __packed;

struct sctp_supported_address_types_parameter {
	__be16 type;
	__be16 length;
	__be16 address_type[];
} __packed;

struct sctp_ecn_capable_parameter {
	__be16 type;
	__be16 length;
} __packed;

struct sctp_supported_extensions_parameter {
	__be16 type;
	__be16 length;
	__u8 chunk_type[];
} __packed;

struct sctp_pad_parameter {
	__be16 type;
	__be16 length;
	__be16 padding_data[];
} __packed;

struct sctp_adaptation_indication_parameter {
	__be16 type;
	__be16 length;
	__be32 adaptation_code_point;
} __packed;

struct sctp_outgoing_ssn_reset_request_parameter {
	__be16 type;
	__be16 length;
	__be32 reqsn;
	__be32 respsn;
	__be32 last_tsn;
	__be16 sids[];
} __packed;

struct sctp_incoming_ssn_reset_request_parameter {
	__be16 type;
	__be16 length;
	__be32 reqsn;
	__be16 sids[];
} __packed;

struct sctp_ssn_tsn_reset_request_parameter {
	__be16 type;
	__be16 length;
	__be32 reqsn;
} __packed;

struct sctp_reconfig_response_parameter {
	__be16 type;
	__be16 length;
	__be32 respsn;
	__be32 result;
	__be32 sender_next_tsn;
	__be32 receiver_next_tsn;
} __packed;

struct sctp_add_outgoing_streams_request_parameter {
	__be16 type;
	__be16 length;
	__be32 reqsn;
	__be16 number_of_new_streams;
	__be16 reserved;
} __packed;

struct sctp_add_incoming_streams_request_parameter {
	__be16 type;
	__be16 length;
	__be32 reqsn;
	__be16 number_of_new_streams;
	__be16 reserved;
} __packed;

struct sctp_reconfig_generic_request_parameter {
	__be16 type;
	__be16 length;
	__be32 reqsn;
	__u8 value[];
} __packed;

struct sctp_forward_tsn_supported_parameter {
	__be16 type;
	__be16 length;
} __packed;

#define SCTP_INVALID_STREAM_IDENTIFIER_CAUSE_CODE	0x0001
#define SCTP_MISSING_MANDATORY_PARAMETER_CAUSE_CODE	0x0002
#define SCTP_STALE_COOKIE_ERROR_CAUSE_CODE		0x0003
#define SCTP_OUT_OF_RESOURCES_CAUSE_CODE		0x0004
#define SCTP_UNRESOLVABLE_ADDRESS_CAUSE_CODE		0x0005
#define SCTP_UNRECOGNIZED_CHUNK_TYPE_CAUSE_CODE		0x0006
#define SCTP_INVALID_MANDATORY_PARAMETER_CAUSE_CODE	0x0007
#define SCTP_UNRECOGNIZED_PARAMETERS_CAUSE_CODE		0x0008
#define SCTP_NO_USER_DATA_CAUSE_CODE			0x0009
#define SCTP_COOKIE_RECEIVED_WHILE_SHUTDOWN_CAUSE_CODE	0x000a
#define SCTP_RESTART_WITH_NEW_ADDRESSES_CAUSE_CODE	0x000b
#define SCTP_USER_INITIATED_ABORT_CAUSE_CODE		0x000c
#define SCTP_PROTOCOL_VIOLATION_CAUSE_CODE		0x000d

#define MAX_SCTP_CAUSE_BYTES	0xffff

struct sctp_cause {
	__be16 code;
	__be16 length;
	__u8 information[];
} __packed;

struct sctp_invalid_stream_identifier_cause {
	__be16 code;
	__be16 length;
	__be16 sid;
	__be16 reserved;
} __packed;

struct sctp_missing_mandatory_parameter_cause {
	__be16 code;
	__be16 length;
	__be32 nr_parameters;
	__be16 parameter_type[];
} __packed;

struct sctp_stale_cookie_error_cause {
	__be16 code;
	__be16 length;
	__be32 staleness;
} __packed;

struct sctp_out_of_resources_cause {
	__be16 code;
	__be16 length;
} __packed;

struct sctp_unresolvable_address_cause {
	__be16 code;
	__be16 length;
	__u8 parameter[];
} __packed;

struct sctp_unrecognized_chunk_type_cause {
	__be16 code;
	__be16 length;
	__u8 chunk[];
} __packed;

struct sctp_invalid_mandatory_parameter_cause {
	__be16 code;
	__be16 length;
} __packed;

struct sctp_unrecognized_parameters_cause {
	__be16 code;
	__be16 length;
	__u8 parameters[];
} __packed;

struct sctp_no_user_data_cause {
	__be16 code;
	__be16 length;
	__be32 tsn;
} __packed;

struct sctp_cookie_received_while_shutdown_cause {
	__be16 code;
	__be16 length;
} __packed;

struct sctp_restart_with_new_addresses_cause {
	__be16 code;
	__be16 length;
	__u8 addresses[];
} __packed;

struct sctp_user_initiated_abort_cause {
	__be16 code;
	__be16 length;
	__u8 information[];
} __packed;

struct sctp_protocol_violation_cause {
	__be16 code;
	__be16 length;
	__u8 information[];
} __packed;

#endif /* __SCTP_HEADERS_H__ */
