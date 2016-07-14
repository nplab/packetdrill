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
 * Test for generating human-readable representations of IP packets.
 */

#include "packet_to_string.h"

#include <assert.h>
#include <stdlib.h>
#include <string.h>
#include "ethernet.h"
#include "packet_parser.h"

static void test_sctp_ipv4_packet_to_string(void)
{
	/* An IPv4/SCTP packet. */
	u8 data[] = {
		/* IPv4: */
		0x45, 0x00, 0x00, 0x24, 0x00, 0x00, 0x00, 0x00,
		0xff, 0x84, 0xb5, 0x50, 0x02, 0x02, 0x02, 0x02,
		0x01, 0x01, 0x01, 0x01,
		/* SCTP Common Header: */
		0x04, 0xd2, 0x1f, 0x90, 0x01, 0x02, 0x03, 0x04,
		0x3d, 0x99, 0xbf, 0xe3,
		/* SCTP ABORT Chunk: */
		0x06, 0x01, 0x00, 0x04
	};

	struct packet *packet = packet_new(sizeof(data));

	/* Populate and parse a packet */
	memcpy(packet->buffer, data, sizeof(data));
	char *error = NULL;
	enum packet_parse_result_t result =
		parse_packet(packet, sizeof(data), ETHERTYPE_IP, &error);
	assert(result == PACKET_OK);
	assert(error == NULL);

	int status = 0;
	char *dump = NULL, *expected = NULL;

	/* Test a DUMP_SHORT dump */
	status = packet_to_string(packet, DUMP_SHORT, &dump, &error);
	assert(status == STATUS_OK);
	assert(error == NULL);
	printf("dump = '%s'\n", dump);
	expected =
		"sctp: ABORT[flgs=T]";
	assert(strcmp(dump, expected) == 0);
	free(dump);

	/* Test a DUMP_FULL dump */
	status = packet_to_string(packet, DUMP_FULL, &dump, &error);
	assert(status == STATUS_OK);
	assert(error == NULL);
	printf("dump = '%s'\n", dump);
	expected =
		"2.2.2.2:1234 > 1.1.1.1:8080 "
		"sctp: ABORT[flgs=T]";
	assert(strcmp(dump, expected) == 0);
	free(dump);

	/* Test a DUMP_VERBOSE dump */
	status = packet_to_string(packet, DUMP_VERBOSE, &dump, &error);
	assert(status == STATUS_OK);
	assert(error == NULL);
	printf("dump = '%s'\n", dump);
	expected =
		"2.2.2.2:1234 > 1.1.1.1:8080 "
		"sctp: ABORT[flgs=T]"
		"\n"
		"0x0000: 45 00 00 24 00 00 00 00 ff 84 b5 50 02 02 02 02 " "\n"
		"0x0010: 01 01 01 01 04 d2 1f 90 01 02 03 04 3d 99 bf e3 " "\n"
		"0x0020: 06 01 00 04 " "\n";
	assert(strcmp(dump, expected) == 0);
	free(dump);

	packet_free(packet);
}

static void test_sctp_ipv6_packet_to_string(void)
{
	/* An IPv6/SCTP packet. */
	u8 data[] = {
		/* IPv6 Base Header: */
		0x60, 0x00, 0x00, 0x00, 0x01, 0xd8, 0x84, 0xff,
		0x00, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x22, 0x22,
		0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x11, 0x11,
		/* SCTP Common Header: */
		0x04, 0xd2, 0x1f, 0x90,
		0x01, 0x02, 0x03, 0x04,
		0x6b, 0x44, 0x25, 0xe5,
		/*0x24, 0x25, 0x51, 0x31,*/
		/* SCTP DATA Chunk */
		0x00, 0x0f, 0x00, 0x13,
		0x01, 0x02, 0x03, 0x04,
		0x00, 0xff, 0x01, 0x00,
		0x00, 0x00, 0x00, 0x00,
		0x00, 0x01, 0x02, 0x00,
		/* SCTP INIT Chunk */
		0x01, 0x00, 0x00, 0x68,
		0x00, 0x00, 0x00, 0x01,
		0x00, 0x01, 0x00, 0x00,
		0x00, 0x0f, 0x00, 0x0f,
		0x01, 0x02, 0x03, 0x04,
		0x00, 0x05, 0x00, 0x08,
		0x01, 0x02, 0x03, 0x04,
		0x00, 0x06, 0x00, 0x14,
		0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x01,
		0x00, 0x09, 0x00, 0x08,
		0x00, 0x01, 0x00, 0x00,
		0x00, 0x0b, 0x00, 0x06,
		0x40, 0x41, 0x00, 0x00,
		0x00, 0x0c, 0x00, 0x0a,
		0x00, 0x05, 0x00, 0x06,
		0x00, 0x0b, 0x00, 0x00,
		0x80, 0x00, 0x00, 0x04,
		0xc0, 0x00, 0x00, 0x04,
		0x80, 0x08, 0x00, 0x05,
		0x40, 0x00, 0x00, 0x00,
		0x80, 0x05, 0x00, 0x0c,
		0x50, 0x50, 0x50, 0x50,
		0x50, 0x50, 0x50, 0x50,
		/* SCTP INIT_ACK Chunk */
		0x02, 0x00, 0x00, 0x24,
		0x00, 0x00, 0x00, 0x01,
		0x00, 0x01, 0x00, 0x00,
		0x00, 0x0f, 0x00, 0x0f,
		0x01, 0x02, 0x03, 0x04,
		0x00, 0x07, 0x00, 0x07,
		0x01, 0x02, 0x03, 0x00,
		0x00, 0x08, 0x00, 0x08,
		0x80, 0x01, 0x00, 0x04,
		/* SCTP SACK Chunk */
		0x03, 0x00, 0x00, 0x20,
		0x01, 0x02, 0x03, 0x04,
		0x00, 0x01, 0x00, 0x00,
		0x00, 0x03, 0x00, 0x01,
		0x00, 0x01, 0x00, 0x03,
		0x00, 0x05, 0x00, 0x0f,
		0x10, 0x00, 0x10, 0x14,
		0x01, 0x02, 0x03, 0x04,
		/* SCTP HEARTBEAT Chunk */
		0x04, 0x00, 0x00, 0x0a,
		0x00, 0x01, 0x00, 0x06,
		0x01, 0x02, 0x00, 0x00,
		/* SCTP HEARTBEAT-ACK Chunk */
		0x05, 0x00, 0x00, 0x0a,
		0x00, 0x01, 0x00, 0x06,
		0x01, 0x02, 0x00, 0x00,
		/* SCTP ABORT Chunk: */
		0x06, 0x01, 0x00, 0x04,
		/* SCTP ABORT Chunk: */
		0x06, 0x00, 0x00, 0x80,
		0x00, 0x01, 0x00, 0x08,
		0x00, 0xff, 0x00, 0x00,
		0x00, 0x02, 0x00, 0x0a,
		0x00, 0x00, 0x00, 0x01,
		0x00, 0x07, 0x00, 0x00,
		0x00, 0x03, 0x00, 0x08,
		0x00, 0x01, 0x00, 0x00,
		0x00, 0x04, 0x00, 0x04,
		0x00, 0x05, 0x00, 0x0c,
		0x00, 0x0b, 0x00, 0x06,
		0x40, 0x41, 0x00, 0x00,
		0x00, 0x06, 0x00, 0x0c,
		0xfe, 0x05, 0x00, 0x05,
		0x01, 0x00, 0x00, 0x00,
		0x00, 0x07, 0x00, 0x04,
		0x00, 0x08, 0x00, 0x10,
		0x80, 0x0a, 0x00, 0x04,
		0x80, 0x0b, 0x00, 0x05,
		0x01, 0x00, 0x00, 0x00,
		0x00, 0x09, 0x00, 0x08,
		0x01, 0x02, 0x03, 0x04,
		0x00, 0x0a, 0x00, 0x04,
		0x00, 0x0b, 0x00, 0x14,
		0x00, 0x05, 0x00, 0x08,
		0x01, 0x02, 0x03, 0x04,
		0x00, 0x05, 0x00, 0x08,
		0x02, 0x03, 0x04, 0x05,
		0x00, 0x0c, 0x00, 0x07,
		0x42, 0x59, 0x45, 0x00,
		0x00, 0x0d, 0x00, 0x06,
		0x40, 0x40, 0x00, 0x00,
		/* SCTP SHUTDOWN Chunk */
		0x07, 0x00, 0x00, 0x08,
		0x01, 0x02, 0x03, 0x04,
		/* SCTP SHUTDOWN_ACK Chunk */
		0x08, 0x00, 0x00, 0x04,
		/* SCTP ERROR Chunk */
		0x09, 0x00, 0x00, 0x04,
		/* SCTP COOKIE_ECHO Chunk */
		0x0a, 0x00, 0x00, 0x05,
		0x45, 0x00, 0x00, 0x00,
		/* SCTP COOKIE_ACK Chunk */
		0x0b, 0x00, 0x00, 0x04,
		/* SCTP ECNE Chunk */
		0x0c, 0x00, 0x00, 0x08,
		0x01, 0x02, 0x03, 0x04,
		/* SCTP CWR Chunk */
		0x0d, 0x00, 0x00, 0x08,
		0x01, 0x02, 0x03, 0x04,
		/* SCTP SHUTDOWN_COMPLETE Chunk */
		0x0e, 0x01, 0x00, 0x04,
		/* SCTP I-DATA Chunk */
		0x40, 0x0f, 0x00, 0x17,
		0x00, 0x00, 0x00, 0x04,
		0x00, 0xff, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x01,
		0x00, 0x00, 0x00, 0x00,
		0x00, 0x01, 0x02, 0x00,
		/* SCTP I-DATA Chunk */
		0x40, 0x0d, 0x00, 0x17,
		0x00, 0x00, 0x00, 0x04,
		0x00, 0xff, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x02,
		0x00, 0x00, 0x00, 0x01,
		0x00, 0x01, 0x02, 0x00,
		/* SCTP PAD Chunk */
		0x84, 0x00, 0x00, 0x10,
		0x50, 0x50, 0x50, 0x50,
		0x50, 0x50, 0x50, 0x50,
		0x50, 0x50, 0x50, 0x50
	};

	struct packet *packet = packet_new(sizeof(data));

	/* Populate and parse a packet */
	memcpy(packet->buffer, data, sizeof(data));
	char *error = NULL;
	enum packet_parse_result_t result =
		parse_packet(packet, sizeof(data), ETHERTYPE_IPV6, &error);
	assert(result == PACKET_OK);
	assert(error == NULL);

	int status = 0;
	char *dump = NULL, *expected = NULL;

	/* Test a DUMP_SHORT dump */
	status = packet_to_string(packet, DUMP_SHORT, &dump, &error);
	assert(status == STATUS_OK);
	assert(error == NULL);
	printf("dump = '%s'\n", dump);
	expected =
		"sctp: "
		"DATA[flgs=IUBE, len=19, tsn=16909060, sid=255, ssn=256, ppid=0]; "
		"INIT[flgs=0x00, tag=1, a_rwnd=65536, os=15, is=15, tsn=16909060, "
		     "IPV4_ADDRESS[addr=1.2.3.4], "
		     "IPV6_ADDRESS[addr=::1], "
		     "COOKIE_PRESERVATIVE[incr=65536], "
		     "HOSTNAME_ADDRESS[addr=\"@A\"], "
		     "SUPPORTED_ADDRESS_TYPES[types=[IPv4, IPv6, HOSTNAME]], "
		     "ECN_CAPABLE[], "
		     "FORWARD_TSN_SUPPORTED[], "
		     "SUPPORTED_EXTENSIONS[types=[I-DATA]], "
		     "PAD[len=12, val=...]]; "
		"INIT_ACK[flgs=0x00, tag=1, a_rwnd=65536, os=15, is=15, tsn=16909060, "
			 "STATE_COOKIE[len=7, val=...], "
			 "UNRECOGNIZED_PARAMETER[params=["
			   "PARAMETER[type=0x8001, value=[]]]]]; "
		"SACK[flgs=0x00, cum_tsn=16909060, a_rwnd=65536, "
		     "gaps=[1:3, 5:15, 4096:4116], dups=[16909060]]; "
		"HEARTBEAT[flgs=0x00, HEARTBEAT_INFORMATION[len=6, val=...]]; "
		"HEARTBEAT_ACK[flgs=0x00, HEARTBEAT_INFORMATION[len=6, val=...]]; "
		"ABORT[flgs=T]; "
		"ABORT[flgs=0x00, INVALID_STREAM_IDENTIFIER[sid=255], "
		      "MISSING_MANDATORY_PARAMETER[types=[STATE_COOKIE]], "
		      "STALE_COOKIE_ERROR[staleness=65536], "
		      "OUT_OF_RESOURCES[], "
		      "UNRESOLVABLE_ADDRESS[param=HOSTNAME_ADDRESS[addr=\"@A\"]], "
		      "UNRECOGNIZED_CHUNK_TYPE[chk="
			"CHUNK[type=0xfe, flgs=0x05, value=[0x01]]], "
		      "INVALID_MANDATORY_PARAMETER[], "
		      "UNRECOGNIZED_PARAMETERS["
			"PARAMETER[type=0x800a, value=[]], "
			"PARAMETER[type=0x800b, value=[0x01]]], "
		      "NO_USER_DATA[tsn=16909060], "
		      "COOKIE_RECEIVED_WHILE_SHUTDOWN[], "
		      "RESTART_WITH_NEW_ADDRESSES[IPV4_ADDRESS[addr=1.2.3.4], "
						 "IPV4_ADDRESS[addr=2.3.4.5]], "
		      "USER_INITIATED_ABORT[info=\"BYE\"], "
		      "PROTOCOL_VIOLATION[info=\"@@\"]]; "
		"SHUTDOWN[flgs=0x00, cum_tsn=16909060]; "
		"SHUTDOWN_ACK[flgs=0x00]; "
		"ERROR[flgs=0x00]; "
		"COOKIE_ECHO[flgs=0x00, len=5]; "
		"COOKIE_ACK[flgs=0x00]; "
		"ECNE[flgs=0x00, tsn=16909060]; "
		"CWR[flgs=0x00, tsn=16909060]; "
		"SHUTDOWN_COMPLETE[flgs=T]; "
		"I-DATA[flgs=IUBE, len=23, tsn=4, sid=255, mid=1, ppid=0]; "
		"I-DATA[flgs=IUE, len=23, tsn=4, sid=255, mid=2, fsn=1]; "
		"PAD[flgs=0x00, len=16, val=...]";
	assert(strcmp(dump, expected) == 0);
	free(dump);

	/* Test a DUMP_FULL dump */
	status = packet_to_string(packet, DUMP_FULL, &dump, &error);
	assert(status == STATUS_OK);
	assert(error == NULL);
	printf("dump = '%s'\n", dump);
	expected =
		"2::2222:1234 > 1::1111:8080 "
		"sctp: "
		"DATA[flgs=IUBE, len=19, tsn=16909060, sid=255, ssn=256, ppid=0]; "
		"INIT[flgs=0x00, tag=1, a_rwnd=65536, os=15, is=15, tsn=16909060, "
		     "IPV4_ADDRESS[addr=1.2.3.4], "
		     "IPV6_ADDRESS[addr=::1], "
		     "COOKIE_PRESERVATIVE[incr=65536], "
		     "HOSTNAME_ADDRESS[addr=\"@A\"], "
		     "SUPPORTED_ADDRESS_TYPES[types=[IPv4, IPv6, HOSTNAME]], "
		     "ECN_CAPABLE[], "
		     "FORWARD_TSN_SUPPORTED[], "
		     "SUPPORTED_EXTENSIONS[types=[I-DATA]], "
		     "PAD[len=12, val=...]]; "
		"INIT_ACK[flgs=0x00, tag=1, a_rwnd=65536, os=15, is=15, tsn=16909060, "
			 "STATE_COOKIE[len=7, val=...], "
			 "UNRECOGNIZED_PARAMETER[params=["
			   "PARAMETER[type=0x8001, value=[]]]]]; "
		"SACK[flgs=0x00, cum_tsn=16909060, a_rwnd=65536, "
		     "gaps=[1:3, 5:15, 4096:4116], dups=[16909060]]; "
		"HEARTBEAT[flgs=0x00, HEARTBEAT_INFORMATION[len=6, val=...]]; "
		"HEARTBEAT_ACK[flgs=0x00, HEARTBEAT_INFORMATION[len=6, val=...]]; "
		"ABORT[flgs=T]; "
		"ABORT[flgs=0x00, INVALID_STREAM_IDENTIFIER[sid=255], "
		      "MISSING_MANDATORY_PARAMETER[types=[STATE_COOKIE]], "
		      "STALE_COOKIE_ERROR[staleness=65536], "
		      "OUT_OF_RESOURCES[], "
		      "UNRESOLVABLE_ADDRESS[param=HOSTNAME_ADDRESS[addr=\"@A\"]], "
		      "UNRECOGNIZED_CHUNK_TYPE[chk="
			"CHUNK[type=0xfe, flgs=0x05, value=[0x01]]], "
		      "INVALID_MANDATORY_PARAMETER[], "
		      "UNRECOGNIZED_PARAMETERS["
			"PARAMETER[type=0x800a, value=[]], "
			"PARAMETER[type=0x800b, value=[0x01]]], "
		      "NO_USER_DATA[tsn=16909060], "
		      "COOKIE_RECEIVED_WHILE_SHUTDOWN[], "
		      "RESTART_WITH_NEW_ADDRESSES[IPV4_ADDRESS[addr=1.2.3.4], "
						 "IPV4_ADDRESS[addr=2.3.4.5]], "
		      "USER_INITIATED_ABORT[info=\"BYE\"], "
		      "PROTOCOL_VIOLATION[info=\"@@\"]]; "
		"SHUTDOWN[flgs=0x00, cum_tsn=16909060]; "
		"SHUTDOWN_ACK[flgs=0x00]; "
		"ERROR[flgs=0x00]; "
		"COOKIE_ECHO[flgs=0x00, len=5]; "
		"COOKIE_ACK[flgs=0x00]; "
		"ECNE[flgs=0x00, tsn=16909060]; "
		"CWR[flgs=0x00, tsn=16909060]; "
		"SHUTDOWN_COMPLETE[flgs=T]; "
		"I-DATA[flgs=IUBE, len=23, tsn=4, sid=255, mid=1, ppid=0]; "
		"I-DATA[flgs=IUE, len=23, tsn=4, sid=255, mid=2, fsn=1]; "
		"PAD[flgs=0x00, len=16, val=...]";
	assert(strcmp(dump, expected) == 0);
	free(dump);

	/* Test a DUMP_VERBOSE dump */
	status = packet_to_string(packet, DUMP_VERBOSE, &dump, &error);
	assert(status == STATUS_OK);
	assert(error == NULL);
	printf("dump = '%s'\n", dump);
	expected =
		"2::2222:1234 > 1::1111:8080 "
		"sctp: "
		"DATA[flgs=IUBE, len=19, tsn=16909060, sid=255, ssn=256, ppid=0]; "
		"INIT[flgs=0x00, tag=1, a_rwnd=65536, os=15, is=15, tsn=16909060, "
		     "IPV4_ADDRESS[addr=1.2.3.4], "
		     "IPV6_ADDRESS[addr=::1], "
		     "COOKIE_PRESERVATIVE[incr=65536], "
		     "HOSTNAME_ADDRESS[addr=\"@A\"], "
		     "SUPPORTED_ADDRESS_TYPES[types=[IPv4, IPv6, HOSTNAME]], "
		     "ECN_CAPABLE[], "
		     "FORWARD_TSN_SUPPORTED[], "
		     "SUPPORTED_EXTENSIONS[types=[I-DATA]], "
		     "PAD[len=12, val=...]]; "
		"INIT_ACK[flgs=0x00, tag=1, a_rwnd=65536, os=15, is=15, tsn=16909060, "
			 "STATE_COOKIE[len=7, val=...], "
			 "UNRECOGNIZED_PARAMETER[params=["
			   "PARAMETER[type=0x8001, value=[]]]]]; "
		"SACK[flgs=0x00, cum_tsn=16909060, a_rwnd=65536, "
		     "gaps=[1:3, 5:15, 4096:4116], dups=[16909060]]; "
		"HEARTBEAT[flgs=0x00, HEARTBEAT_INFORMATION[len=6, val=...]]; "
		"HEARTBEAT_ACK[flgs=0x00, HEARTBEAT_INFORMATION[len=6, val=...]]; "
		"ABORT[flgs=T]; "
		"ABORT[flgs=0x00, INVALID_STREAM_IDENTIFIER[sid=255], "
		      "MISSING_MANDATORY_PARAMETER[types=[STATE_COOKIE]], "
		      "STALE_COOKIE_ERROR[staleness=65536], "
		      "OUT_OF_RESOURCES[], "
		      "UNRESOLVABLE_ADDRESS[param=HOSTNAME_ADDRESS[addr=\"@A\"]], "
		      "UNRECOGNIZED_CHUNK_TYPE[chk="
			"CHUNK[type=0xfe, flgs=0x05, value=[0x01]]], "
		      "INVALID_MANDATORY_PARAMETER[], "
		      "UNRECOGNIZED_PARAMETERS["
			"PARAMETER[type=0x800a, value=[]], "
			"PARAMETER[type=0x800b, value=[0x01]]], "
		      "NO_USER_DATA[tsn=16909060], "
		      "COOKIE_RECEIVED_WHILE_SHUTDOWN[], "
		      "RESTART_WITH_NEW_ADDRESSES[IPV4_ADDRESS[addr=1.2.3.4], "
						 "IPV4_ADDRESS[addr=2.3.4.5]], "
		      "USER_INITIATED_ABORT[info=\"BYE\"], "
		      "PROTOCOL_VIOLATION[info=\"@@\"]]; "
		"SHUTDOWN[flgs=0x00, cum_tsn=16909060]; "
		"SHUTDOWN_ACK[flgs=0x00]; "
		"ERROR[flgs=0x00]; "
		"COOKIE_ECHO[flgs=0x00, len=5]; "
		"COOKIE_ACK[flgs=0x00]; "
		"ECNE[flgs=0x00, tsn=16909060]; "
		"CWR[flgs=0x00, tsn=16909060]; "
		"SHUTDOWN_COMPLETE[flgs=T]; "
		"I-DATA[flgs=IUBE, len=23, tsn=4, sid=255, mid=1, ppid=0]; "
		"I-DATA[flgs=IUE, len=23, tsn=4, sid=255, mid=2, fsn=1]; "
		"PAD[flgs=0x00, len=16, val=...]"
		"\n"
		"0x0000: 60 00 00 00 01 d8 84 ff 00 02 00 00 00 00 00 00 " "\n"
		"0x0010: 00 00 00 00 00 00 22 22 00 01 00 00 00 00 00 00 " "\n"
		"0x0020: 00 00 00 00 00 00 11 11 04 d2 1f 90 01 02 03 04 " "\n"
		"0x0030: 6b 44 25 e5 00 0f 00 13 01 02 03 04 00 ff 01 00 " "\n"
		"0x0040: 00 00 00 00 00 01 02 00 01 00 00 68 00 00 00 01 " "\n"
		"0x0050: 00 01 00 00 00 0f 00 0f 01 02 03 04 00 05 00 08 " "\n"
		"0x0060: 01 02 03 04 00 06 00 14 00 00 00 00 00 00 00 00 " "\n"
		"0x0070: 00 00 00 00 00 00 00 01 00 09 00 08 00 01 00 00 " "\n"
		"0x0080: 00 0b 00 06 40 41 00 00 00 0c 00 0a 00 05 00 06 " "\n"
		"0x0090: 00 0b 00 00 80 00 00 04 c0 00 00 04 80 08 00 05 " "\n"
		"0x00a0: 40 00 00 00 80 05 00 0c 50 50 50 50 50 50 50 50 " "\n"
		"0x00b0: 02 00 00 24 00 00 00 01 00 01 00 00 00 0f 00 0f " "\n"
		"0x00c0: 01 02 03 04 00 07 00 07 01 02 03 00 00 08 00 08 " "\n"
		"0x00d0: 80 01 00 04 03 00 00 20 01 02 03 04 00 01 00 00 " "\n"
		"0x00e0: 00 03 00 01 00 01 00 03 00 05 00 0f 10 00 10 14 " "\n"
		"0x00f0: 01 02 03 04 04 00 00 0a 00 01 00 06 01 02 00 00 " "\n"
		"0x0100: 05 00 00 0a 00 01 00 06 01 02 00 00 06 01 00 04 " "\n"
		"0x0110: 06 00 00 80 00 01 00 08 00 ff 00 00 00 02 00 0a " "\n"
		"0x0120: 00 00 00 01 00 07 00 00 00 03 00 08 00 01 00 00 " "\n"
		"0x0130: 00 04 00 04 00 05 00 0c 00 0b 00 06 40 41 00 00 " "\n"
		"0x0140: 00 06 00 0c fe 05 00 05 01 00 00 00 00 07 00 04 " "\n"
		"0x0150: 00 08 00 10 80 0a 00 04 80 0b 00 05 01 00 00 00 " "\n"
		"0x0160: 00 09 00 08 01 02 03 04 00 0a 00 04 00 0b 00 14 " "\n"
		"0x0170: 00 05 00 08 01 02 03 04 00 05 00 08 02 03 04 05 " "\n"
		"0x0180: 00 0c 00 07 42 59 45 00 00 0d 00 06 40 40 00 00 " "\n"
		"0x0190: 07 00 00 08 01 02 03 04 08 00 00 04 09 00 00 04 " "\n"
		"0x01a0: 0a 00 00 05 45 00 00 00 0b 00 00 04 0c 00 00 08 " "\n"
		"0x01b0: 01 02 03 04 0d 00 00 08 01 02 03 04 0e 01 00 04 " "\n"
		"0x01c0: 40 0f 00 17 00 00 00 04 00 ff 00 00 00 00 00 01 " "\n"
		"0x01d0: 00 00 00 00 00 01 02 00 40 0d 00 17 00 00 00 04 " "\n"
		"0x01e0: 00 ff 00 00 00 00 00 02 00 00 00 01 00 01 02 00 " "\n"
		"0x01f0: 84 00 00 10 50 50 50 50 50 50 50 50 50 50 50 50 " "\n";
	printf("expected = '%s'\n", expected);
	assert(strcmp(dump, expected) == 0);
	free(dump);
	packet_free(packet);
}

static void test_tcp_ipv4_packet_to_string(void)
{
	/* An IPv4/GRE/IPv4/TCP packet. */
	u8 data[] = {
		/* IPv4: */
		0x45, 0x00, 0x00, 0x54, 0x00, 0x00, 0x00, 0x00,
		0xff, 0x2f, 0xb5, 0x75, 0x02, 0x02, 0x02, 0x02,
		0x01, 0x01, 0x01, 0x01,
		/* GRE: */
		0x00, 0x00, 0x08, 0x00,
		/* IPv4, TCP: */
		0x45, 0x00, 0x00, 0x3c, 0x00, 0x00, 0x00, 0x00,
		0xff, 0x06, 0x39, 0x11, 0xc0, 0x00, 0x02, 0x01,
		0xc0, 0xa8, 0x00, 0x01, 0xcf, 0x3f, 0x1f, 0x90,
		0x00, 0x00, 0x00, 0x01, 0x83, 0x4d, 0xa5, 0x5b,
		0xa0, 0x10, 0x01, 0x01, 0xdb, 0x2d, 0x00, 0x00,
		0x05, 0x0a, 0x83, 0x4d, 0xab, 0x03, 0x83, 0x4d,
		0xb0, 0xab, 0x08, 0x0a, 0x00, 0x00, 0x01, 0x2c,
		0x60, 0xc2, 0x18, 0x20
	};

	struct packet *packet = packet_new(sizeof(data));

	/* Populate and parse a packet */
	memcpy(packet->buffer, data, sizeof(data));
	char *error = NULL;
	enum packet_parse_result_t result =
		parse_packet(packet, sizeof(data), ETHERTYPE_IP, &error);
	assert(result == PACKET_OK);
	assert(error == NULL);

	int status = 0;
	char *dump = NULL, *expected = NULL;

	/* Test a DUMP_SHORT dump */
	status = packet_to_string(packet, DUMP_SHORT, &dump, &error);
	assert(status == STATUS_OK);
	assert(error == NULL);
	printf("dump = '%s'\n", dump);
	expected =
		"ipv4 2.2.2.2 > 1.1.1.1: gre: "
		". 1:1(0) ack 2202903899 win 257 "
		"<sack 2202905347:2202906795,TS val 300 ecr 1623332896>";
	assert(strcmp(dump, expected) == 0);
	free(dump);

	/* Test a DUMP_FULL dump */
	status = packet_to_string(packet, DUMP_FULL, &dump, &error);
	assert(status == STATUS_OK);
	assert(error == NULL);
	printf("dump = '%s'\n", dump);
	expected =
		"ipv4 2.2.2.2 > 1.1.1.1: gre: "
		"192.0.2.1:53055 > 192.168.0.1:8080 "
		". 1:1(0) ack 2202903899 win 257 "
		"<sack 2202905347:2202906795,TS val 300 ecr 1623332896>";
	assert(strcmp(dump, expected) == 0);
	free(dump);

	/* Test a DUMP_VERBOSE dump */
	status = packet_to_string(packet, DUMP_VERBOSE, &dump, &error);
	assert(status == STATUS_OK);
	assert(error == NULL);
	printf("dump = '%s'\n", dump);
	expected =
		"ipv4 2.2.2.2 > 1.1.1.1: gre: "
		"192.0.2.1:53055 > 192.168.0.1:8080 "
		". 1:1(0) ack 2202903899 win 257 "
		"<sack 2202905347:2202906795,TS val 300 ecr 1623332896>"
		"\n"
		"0x0000: 45 00 00 54 00 00 00 00 ff 2f b5 75 02 02 02 02 " "\n"
		"0x0010: 01 01 01 01 00 00 08 00 45 00 00 3c 00 00 00 00 " "\n"
		"0x0020: ff 06 39 11 c0 00 02 01 c0 a8 00 01 cf 3f 1f 90 " "\n"
		"0x0030: 00 00 00 01 83 4d a5 5b a0 10 01 01 db 2d 00 00 " "\n"
		"0x0040: 05 0a 83 4d ab 03 83 4d b0 ab 08 0a 00 00 01 2c " "\n"
		"0x0050: 60 c2 18 20 " "\n";
	assert(strcmp(dump, expected) == 0);
	free(dump);

	packet_free(packet);
}

static void test_tcp_ipv6_packet_to_string(void)
{
	/* An IPv6/GRE/IPv6/TCP packet. */
	u8 data[] = {
		/* IPv6: */
		0x60, 0x00, 0x00, 0x00, 0x00, 0x4c, 0x2f, 0xff,
		0x00, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x22, 0x22,
		0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x11, 0x11,
		/* GRE: */
		0x00, 0x00, 0x86, 0xdd,
		/* IPv6, TCP: */
		0x60, 0x00, 0x00, 0x00, 0x00, 0x20, 0x06, 0xff,
		0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
		0xfd, 0x3d, 0xfa, 0x7b, 0xd1, 0x7d, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
		0xd3, 0xe2, 0x1f, 0x90, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x80, 0x02, 0x80, 0x18,
		0x06, 0x60, 0x00, 0x00, 0x02, 0x04, 0x03, 0xe8,
		0x04, 0x02, 0x01, 0x01, 0x01, 0x03, 0x03, 0x07
	};

	struct packet *packet = packet_new(sizeof(data));

	/* Populate and parse a packet */
	memcpy(packet->buffer, data, sizeof(data));
	char *error = NULL;
	enum packet_parse_result_t result =
		parse_packet(packet, sizeof(data), ETHERTYPE_IPV6, &error);
	assert(result == PACKET_OK);
	assert(error == NULL);

	int status = 0;
	char *dump = NULL, *expected = NULL;

	/* Test a DUMP_SHORT dump */
	status = packet_to_string(packet, DUMP_SHORT, &dump, &error);
	assert(status == STATUS_OK);
	assert(error == NULL);
	printf("dump = '%s'\n", dump);
	expected =
		"ipv6 2::2222 > 1::1111: gre: "
		"S 0:0(0) win 32792 <mss 1000,sackOK,nop,nop,nop,wscale 7>";
	assert(strcmp(dump, expected) == 0);
	free(dump);

	/* Test a DUMP_FULL dump */
	status = packet_to_string(packet, DUMP_FULL, &dump, &error);
	assert(status == STATUS_OK);
	assert(error == NULL);
	printf("dump = '%s'\n", dump);
	expected =
		"ipv6 2::2222 > 1::1111: gre: "
		"2001:db8::1:54242 > fd3d:fa7b:d17d::1:8080 "
		"S 0:0(0) win 32792 <mss 1000,sackOK,nop,nop,nop,wscale 7>";
	assert(strcmp(dump, expected) == 0);
	free(dump);

	/* Test a DUMP_VERBOSE dump */
	status = packet_to_string(packet, DUMP_VERBOSE, &dump, &error);
	assert(status == STATUS_OK);
	assert(error == NULL);
	printf("dump = '%s'\n", dump);
	expected =
		"ipv6 2::2222 > 1::1111: gre: "
		"2001:db8::1:54242 > fd3d:fa7b:d17d::1:8080 "
		"S 0:0(0) win 32792 <mss 1000,sackOK,nop,nop,nop,wscale 7>\n"
		"0x0000: 60 00 00 00 00 4c 2f ff 00 02 00 00 00 00 00 00 " "\n"
		"0x0010: 00 00 00 00 00 00 22 22 00 01 00 00 00 00 00 00 " "\n"
		"0x0020: 00 00 00 00 00 00 11 11 00 00 86 dd 60 00 00 00 " "\n"
		"0x0030: 00 20 06 ff 20 01 0d b8 00 00 00 00 00 00 00 00 " "\n"
		"0x0040: 00 00 00 01 fd 3d fa 7b d1 7d 00 00 00 00 00 00 " "\n"
		"0x0050: 00 00 00 01 d3 e2 1f 90 00 00 00 00 00 00 00 00 " "\n"
		"0x0060: 80 02 80 18 06 60 00 00 02 04 03 e8 04 02 01 01 " "\n"
		"0x0070: 01 03 03 07 " "\n";
	assert(strcmp(dump, expected) == 0);
	free(dump);

	packet_free(packet);
}

static void test_gre_mpls_tcp_ipv4_packet_to_string(void)
{
	/* An IPv4/GRE/MPLS/IPv4/TCP packet. */
	u8 data[] = {
		/* IPv4: */
		0x45, 0x00, 0x00, 0x54, 0x00, 0x00, 0x40, 0x00,
		0x40, 0x2f, 0xb7, 0xcf, 0xc0, 0xa8, 0x00, 0x01,
		0xc0, 0x00, 0x02, 0x02,
		/* GRE: */
		0x00, 0x00, 0x88, 0x47,
		/* MPLS: */
		0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff,
		/* IPv4, TCP: */
		0x45, 0x00, 0x00, 0x34, 0x86, 0x99, 0x40, 0x00,
		0x40, 0x06, 0x31, 0x80, 0xc0, 0xa8, 0x00, 0x01,
		0xc0, 0x00, 0x02, 0x01, 0x1f, 0x90, 0xdb, 0xcc,
		0x7b, 0x81, 0xc5, 0x7c, 0x00, 0x00, 0x00, 0x01,
		0x80, 0x11, 0x01, 0xc5, 0xa6, 0xa6, 0x00, 0x00,
		0x01, 0x01, 0x08, 0x0a, 0x07, 0x02, 0x08, 0x43,
		0x00, 0x00, 0x00, 0x05
	};

	struct packet *packet = packet_new(sizeof(data));

	/* Populate and parse a packet */
	memcpy(packet->buffer, data, sizeof(data));
	char *error = NULL;
	enum packet_parse_result_t result =
		parse_packet(packet, sizeof(data), ETHERTYPE_IP, &error);
	assert(result == PACKET_OK);
	assert(error == NULL);

	int status = 0;
	char *dump = NULL, *expected = NULL;

	/* Test a DUMP_FULL dump */
	status = packet_to_string(packet, DUMP_FULL, &dump, &error);
	assert(status == STATUS_OK);
	assert(error == NULL);
	printf("dump = '%s'\n", dump);
	expected =
		"ipv4 192.168.0.1 > 192.0.2.2: gre: "
		"mpls (label 0, tc 0, ttl 0) "
		"(label 1048575, tc 7, [S], ttl 255): "
		"192.168.0.1:8080 > 192.0.2.1:56268 "
		"F. 2072102268:2072102268(0) ack 1 win 453 "
		"<nop,nop,TS val 117573699 ecr 5>";
	assert(strcmp(dump, expected) == 0);
	free(dump);

	packet_free(packet);
}

static void test_udplite_ipv4_packet_to_string(void)
{
	/* An IPv4/GRE/IPv4/UDPLite packet. */
	u8 data[] = {
		/* IPv4: */
		0x45, 0x00, 0x00, 0x37, 0x00, 0x00, 0x00, 0x00,
		0xff, 0x2f, 0xb5, 0x92, 0x02, 0x02, 0x02, 0x02,
		0x01, 0x01, 0x01, 0x01,
		/* GRE: */
		0x00, 0x00, 0x08, 0x00,
		/* IPv4, UDPLite: */
		0x45, 0x00, 0x00, 0x1f, 0x00, 0x00, 0x00, 0x00,
		0xff, 0x88, 0xf8, 0xab, 0x01, 0x01, 0x01, 0x01,
		0xc0, 0xa8, 0x00, 0x01, 0x04, 0xd2, 0xeb, 0x35,
		0x00, 0x09, 0x86, 0xaf, 0xc6, 0x45, 0x46
	};

	struct packet *packet = packet_new(sizeof(data));

	/* Populate and parse a packet */
	memcpy(packet->buffer, data, sizeof(data));
	char *error = NULL;
	enum packet_parse_result_t result =
		parse_packet(packet, sizeof(data), ETHERTYPE_IP, &error);
	assert(result == PACKET_OK);
	assert(error == NULL);

	int status = 0;
	char *dump = NULL, *expected = NULL;

	/* Test a DUMP_SHORT dump */
	status = packet_to_string(packet, DUMP_SHORT, &dump, &error);
	assert(status == STATUS_OK);
	assert(error == NULL);
	printf("dump = '%s'\n", dump);
	expected =
		"ipv4 2.2.2.2 > 1.1.1.1: gre: "
		"udplite (3, 9)";
	assert(strcmp(dump, expected) == 0);
	free(dump);

	/* Test a DUMP_FULL dump */
	status = packet_to_string(packet, DUMP_FULL, &dump, &error);
	assert(status == STATUS_OK);
	assert(error == NULL);
	printf("dump = '%s'\n", dump);
	expected =
		"ipv4 2.2.2.2 > 1.1.1.1: gre: "
		"1.1.1.1:1234 > 192.168.0.1:60213 "
		"udplite (3, 9)";
	assert(strcmp(dump, expected) == 0);
	free(dump);

	/* Test a DUMP_VERBOSE dump */
	status = packet_to_string(packet, DUMP_VERBOSE, &dump, &error);
	assert(status == STATUS_OK);
	assert(error == NULL);
	printf("dump = '%s'\n", dump);
	expected =
		"ipv4 2.2.2.2 > 1.1.1.1: gre: "
		"1.1.1.1:1234 > 192.168.0.1:60213 "
		"udplite (3, 9)"
		"\n"
		"0x0000: 45 00 00 37 00 00 00 00 ff 2f b5 92 02 02 02 02 " "\n"
		"0x0010: 01 01 01 01 00 00 08 00 45 00 00 1f 00 00 00 00 " "\n"
		"0x0020: ff 88 f8 ab 01 01 01 01 c0 a8 00 01 04 d2 eb 35 " "\n"
		"0x0030: 00 09 86 af c6 45 46 " "\n";
	assert(strcmp(dump, expected) == 0);
	free(dump);

	packet_free(packet);
}

static void test_udplite_ipv6_packet_to_string(void)
{
	/* An IPv6/GRE/IPv6/UDPLite packet. */
	u8 data[] = {
		/* IPv6: */
		0x60, 0x00, 0x00, 0x00, 0x00, 0x37, 0x2f, 0xff,
		0x00, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x22, 0x22,
		0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x11, 0x11,
		/* GRE: */
		0x00, 0x00, 0x86, 0xdd,
		/* IPv6, UDPLite: */
		0x60, 0x00, 0x00, 0x00, 0x00, 0x0b, 0x88, 0xff,
		0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
		0xfd, 0x3d, 0xfa, 0x7b, 0xd1, 0x7d, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
		0xd3, 0xe2, 0x1f, 0x90, 0x00, 0x09, 0x4e, 0xfd,
		0xc6, 0x45, 0x46
	};

	struct packet *packet = packet_new(sizeof(data));

	/* Populate and parse a packet */
	memcpy(packet->buffer, data, sizeof(data));
	char *error = NULL;
	enum packet_parse_result_t result =
		parse_packet(packet, sizeof(data), ETHERTYPE_IPV6, &error);
	assert(result == PACKET_OK);
	assert(error == NULL);

	int status = 0;
	char *dump = NULL, *expected = NULL;

	/* Test a DUMP_SHORT dump */
	status = packet_to_string(packet, DUMP_SHORT, &dump, &error);
	assert(status == STATUS_OK);
	assert(error == NULL);
	printf("dump = '%s'\n", dump);
	expected =
		"ipv6 2::2222 > 1::1111: gre: "
		"udplite (3, 9)";
	assert(strcmp(dump, expected) == 0);
	free(dump);

	/* Test a DUMP_FULL dump */
	status = packet_to_string(packet, DUMP_FULL, &dump, &error);
	assert(status == STATUS_OK);
	assert(error == NULL);
	printf("dump = '%s'\n", dump);
	expected =
		"ipv6 2::2222 > 1::1111: gre: "
		"2001:db8::1:54242 > fd3d:fa7b:d17d::1:8080 "
		"udplite (3, 9)";
	assert(strcmp(dump, expected) == 0);
	free(dump);

	/* Test a DUMP_VERBOSE dump */
	status = packet_to_string(packet, DUMP_VERBOSE, &dump, &error);
	assert(status == STATUS_OK);
	assert(error == NULL);
	printf("dump = '%s'\n", dump);
	expected =
		"ipv6 2::2222 > 1::1111: gre: "
		"2001:db8::1:54242 > fd3d:fa7b:d17d::1:8080 "
		"udplite (3, 9)\n"
		"0x0000: 60 00 00 00 00 37 2f ff 00 02 00 00 00 00 00 00 " "\n"
		"0x0010: 00 00 00 00 00 00 22 22 00 01 00 00 00 00 00 00 " "\n"
		"0x0020: 00 00 00 00 00 00 11 11 00 00 86 dd 60 00 00 00 " "\n"
		"0x0030: 00 0b 88 ff 20 01 0d b8 00 00 00 00 00 00 00 00 " "\n"
		"0x0040: 00 00 00 01 fd 3d fa 7b d1 7d 00 00 00 00 00 00 " "\n"
		"0x0050: 00 00 00 01 d3 e2 1f 90 00 09 4e fd c6 45 46 " "\n";
	assert(strcmp(dump, expected) == 0);
	free(dump);

	packet_free(packet);
}

int main(void)
{
	test_sctp_ipv4_packet_to_string();
	test_sctp_ipv6_packet_to_string();
	test_tcp_ipv4_packet_to_string();
	test_tcp_ipv6_packet_to_string();
	test_gre_mpls_tcp_ipv4_packet_to_string();
	test_udplite_ipv4_packet_to_string();
	test_udplite_ipv6_packet_to_string();
	return 0;
}
