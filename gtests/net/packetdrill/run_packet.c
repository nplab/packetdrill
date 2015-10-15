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
 * A module to execute a packet command from a test script.
 */

#include "run_packet.h"

#include <arpa/inet.h>
#include <netinet/in.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>
#include "checksum.h"
#include "gre.h"
#include "logging.h"
#include "netdev.h"
#include "packet.h"
#include "packet_checksum.h"
#include "packet_to_string.h"
#include "run.h"
#include "script.h"
#include "sctp_iterator.h"
#include "sctp_packet.h"
#include "tcp_options_iterator.h"
#include "tcp_options_to_string.h"
#include "tcp_packet.h"

/* To avoid issues with TIME_WAIT, FIN_WAIT1, and FIN_WAIT2 we use
 * dynamically-chosen, unique 4-tuples for each test. We implement the
 * picking of unique ports by binding a socket to port 0 and seeing
 * what port we are assigned. Note that we keep the socket fd open for
 * the lifetime of our process to ensure that the port is not
 * reused by a later test.
 */
static u16 ephemeral_port(void)
{
	int fd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	if (fd < 0)
		die_perror("socket");

	struct sockaddr_in addr;
	socklen_t addrlen = sizeof(addr);
	memset(&addr, 0, sizeof(addr));
	addr.sin_family = AF_INET;
	addr.sin_port = 0;		/* let the OS pick the port */
	if (bind(fd, (struct sockaddr *)&addr, addrlen) < 0)
		die_perror("bind");

	memset(&addr, 0, sizeof(addr));
	if (getsockname(fd, (struct sockaddr *)&addr, &addrlen) < 0)
		die_perror("getsockname");
	assert(addr.sin_family == AF_INET);

	if (listen(fd, 1) < 0)
		die_perror("listen");

	return ntohs(addr.sin_port);
}

/* Return the next ephemeral port to use. We want quick results for
 * the very common case where there is only one remote port to use
 * over the course of a test. So we avoid paying the overhead of the
 * several system calls in ephemeral_port() right before injecting an
 * incoming SYN by pre-allocating and caching a single port to use
 * before starting each test.
 */
static u16 next_ephemeral_port(struct state *state)
{
	if (state->packets->next_ephemeral_port >= 0) {
		int port = state->packets->next_ephemeral_port;
		assert(port <= 0xffff);
		state->packets->next_ephemeral_port = -1;
		return port;
	} else {
		return ephemeral_port();
	}
}

/* Add a dump of the given packet to the given error message.
 * Frees *error and replaces it with a version that has the original
 * *error followed by the given type and a hex dump of the given
 * packet.
 */
static void add_packet_dump(char **error, const char *type,
			    struct packet *packet, s64 time_usecs,
			    enum dump_format_t format)
{
	if (packet->ip_bytes != 0) {
		char *old_error = *error;
		char *dump = NULL, *dump_error = NULL;

		packet_to_string(packet, format,
				 &dump, &dump_error);
		asprintf(error, "%s\n%s packet: %9.6f %s%s%s",
			 old_error, type, usecs_to_secs(time_usecs), dump,
			 dump_error ? "\n" : "",
			 dump_error ? dump_error : "");

		free(dump);
		free(dump_error);
		free(old_error);
	}
}

/* For verbose runs, print a short packet dump of all live packets. */
static void verbose_packet_dump(struct state *state, const char *type,
				struct packet *live_packet, s64 time_usecs)
{
	if (state->config->verbose) {
		char *dump = NULL, *dump_error = NULL;

		packet_to_string(live_packet, DUMP_SHORT,
				 &dump, &dump_error);

		printf("%s packet: %9.6f %s%s%s\n",
		       type, usecs_to_secs(time_usecs), dump,
		       dump_error ? "\n" : "",
		       dump_error ? dump_error : "");

		free(dump);
		free(dump_error);
	}
}

/* See if the live packet matches the live 4-tuple of the socket under test. */
static struct socket *find_socket_for_live_packet(
	struct state *state, const struct packet *packet,
	enum direction_t *direction)
{
	struct socket *socket = state->socket_under_test;	/* shortcut */

	DEBUGP("find_connect_for_live_packet\n");
	if (socket == NULL)
		return NULL;

	struct tuple packet_tuple, live_outbound, live_inbound;
	get_packet_tuple(packet, &packet_tuple);
	/* Is packet inbound to the socket under test? */
	socket_get_inbound(&socket->live, &live_inbound);
	if (is_equal_tuple(&packet_tuple, &live_inbound)) {
		*direction = DIRECTION_INBOUND;
		DEBUGP("inbound live packet, socket in state %d\n",
		       socket->state);
		return socket;
	}
	/* Is packet outbound from the socket under test? */
	socket_get_outbound(&socket->live, &live_outbound);
	if (is_equal_tuple(&packet_tuple, &live_outbound)) {
		*direction = DIRECTION_OUTBOUND;
		DEBUGP("outbound live packet, socket in state %d\n",
		       socket->state);
		return socket;
	}
	return NULL;
}

/* See if the socket under test is listening and is willing to receive
 * this incoming SYN packet. If so, create a new child socket, anoint
 * it as the new socket under test, and return a pointer to
 * it. Otherwise, return NULL.
 */
static struct socket *handle_listen_for_script_packet(
	struct state *state, const struct packet *packet,
	enum direction_t direction)
{
	/* Does this packet match this socket? For now we only support
	 * testing one socket at a time, so we merely check whether
	 * the socket is listening. (If we were to support testing
	 * more than one socket at a time then we'd want to check to
	 * see if the address tuples in the packet and socket match.)
	 */
	struct config *config = state->config;
	struct socket *socket = state->socket_under_test;	/* shortcut */
	struct sctp_init_chunk *init;
	struct sctp_chunk_list_item *item;

	bool match = (direction == DIRECTION_INBOUND);
	if (!match)
		return NULL;

	if (config->is_wire_server) {
		/* On wire servers we don't see the system calls, so
		 * we won't have any socket_under_test yet.
		 */
		match = (socket == NULL);
	} else {
		/* In local mode we will certainly know about this socket. */
		match = ((socket != NULL) &&
			 (socket->state == SOCKET_PASSIVE_LISTENING));
	}
	if (!match)
		return NULL;

	if (packet->sctp != NULL) {
		assert(packet->chunk_list != NULL);
		item = packet->chunk_list->first;
		if ((item != NULL) &&
		    (item->chunk->type == SCTP_INIT_CHUNK_TYPE)) {
			init = (struct sctp_init_chunk *)item->chunk;
		} else {
			return NULL;
		}
	}

	/* Create a child passive socket for this incoming SYN packet.
	 * Any further packets in the test script will be directed to
	 * this child socket.
	 */
	socket = socket_new(state);
	state->socket_under_test = socket;
	assert(socket->state == SOCKET_INIT);
	socket->state = SOCKET_PASSIVE_PACKET_RECEIVED;
	socket->address_family = packet_address_family(packet);
	socket->protocol = packet_ip_protocol(packet);

	/* Set script info for this socket using script packet. */
	struct tuple tuple;
	get_packet_tuple(packet, &tuple);
	socket->script.remote		= tuple.src;
	socket->script.local		= tuple.dst;
	if (packet->tcp != NULL) {
		socket->script.remote_isn = ntohl(packet->tcp->seq);
	} else {
		socket->script.remote_initiate_tag = ntohl(init->initiate_tag);
		socket->script.remote_initial_tsn = ntohl(init->initial_tsn);
	}
	socket->script.fd		= -1;

	/* Set up the live info for this socket based
	 * on the script packet and our overall config.
	 */
	socket->live.remote.ip		= config->live_remote_ip;
	socket->live.remote.port	= htons(next_ephemeral_port(state));
	socket->live.local.ip		= config->live_local_ip;
	socket->live.local.port		= htons(config->live_bind_port);
	if (packet->tcp != NULL) {
		socket->live.remote_isn = ntohl(packet->tcp->seq);
	} else {
		socket->live.remote_initiate_tag = ntohl(init->initiate_tag);
		socket->live.remote_initial_tsn = ntohl(init->initial_tsn);
	}
	socket->live.fd			= -1;

	if (DEBUG_LOGGING) {
		char local_string[ADDR_STR_LEN];
		char remote_string[ADDR_STR_LEN];
		DEBUGP("live: local: %s.%d\n",
		       ip_to_string(&socket->live.local.ip, local_string),
		       ntohs(socket->live.local.port));
		DEBUGP("live: remote: %s.%d\n",
		       ip_to_string(&socket->live.remote.ip, remote_string),
		       ntohs(socket->live.remote.port));
		if (packet->tcp != NULL) {
			DEBUGP("live: ISN: %u\n", socket->live.remote_isn);
		} else {
			DEBUGP("live: initiate tag: %u\n", socket->live.remote_initiate_tag);
			DEBUGP("live: initial tsn: %u\n", socket->live.remote_initial_tsn);
		}
	}

	return socket;
}

/* See if the socket under test is a connecting socket that would emit
 * this outgoing script SYN. If so, return a pointer to the socket;
 * otherwise, return NULL.
 */
static struct socket *handle_connect_for_script_packet(
	struct state *state, const struct packet *packet,
	enum direction_t direction)
{
	/* Does this packet match this socket? For now we only support
	 * testing one socket at a time, so we merely check whether
	 * the socket is connecting. (If we were to support testing
	 * more than one socket at a time then we'd want to check to
	 * see if the address tuples in the packet and socket match.)
	 */
	struct config *config = state->config;
	struct socket *socket = state->socket_under_test;	/* shortcut */
	struct sctp_init_chunk *init;
	struct sctp_chunk_list_item *item;
	bool match;

	DEBUGP("handle_connect_for_script_packet\n");
	assert(packet->tcp != NULL || packet->sctp != NULL);
	if (direction != DIRECTION_OUTBOUND)
		return NULL;
	if (packet->tcp != NULL) {
		match = (packet->tcp->syn && !packet->tcp->ack);
	} else {
		assert(packet->chunk_list != NULL);
		item = packet->chunk_list->first;
		if ((item != NULL) &&
		    (item->chunk->type == SCTP_INIT_CHUNK_TYPE)) {
			init = (struct sctp_init_chunk *)item->chunk;
			match = true;
		} else {
			init = NULL;
			match = false;
		}
	}
	if (!match)
		return NULL;

	if (config->is_wire_server) {
		/* On wire servers we don't see the system calls, so
		 * we won't have any socket_under_test yet.
		 */
		match = (socket == NULL);
	} else {
		/* In local mode we will certainly know about this socket. */
		match = ((socket != NULL) &&
			 (socket->state == SOCKET_ACTIVE_CONNECTING));
	}
	if (!match)
		return NULL;

	if (socket == NULL) {
		/* Wire server. Create a socket for this outbound SYN
		 * packet. Any further packets in the test script are
		 * mapped here.
		 */
		socket = socket_new(state);
		state->socket_under_test = socket;
		assert(socket->state == SOCKET_INIT);
		socket->address_family = packet_address_family(packet);
		socket->protocol = packet_ip_protocol(packet);

		socket->script.fd	 = -1;

		socket->live.remote.ip   = config->live_remote_ip;
		socket->live.remote.port = htons(config->live_connect_port);
		socket->live.fd		 = -1;
	}

	/* Fill in the new info about this connection. */
	struct tuple tuple;
	get_packet_tuple(packet, &tuple);
	socket->script.remote		= tuple.dst;
	socket->script.local		= tuple.src;
	if (packet->tcp) {
		socket->state = SOCKET_ACTIVE_SYN_SENT;
		socket->script.local_isn = ntohl(packet->tcp->seq);
	} else {
		DEBUGP("Moving socket in SOCKET_ACTIVE_INIT_SENT\n");
		socket->state = SOCKET_ACTIVE_INIT_SENT;
		socket->script.local_initial_tsn = ntohl(init->initial_tsn);
		socket->script.local_initiate_tag = ntohl(init->initiate_tag);
	}
	return socket;
}

/* Look for a connecting socket that would emit this outgoing live packet. */
static struct socket *find_connect_for_live_packet(
	struct state *state, struct packet *packet,
	enum direction_t *direction)
{
	struct sctp_chunks_iterator iter;
	struct sctp_chunk *chunk;
	struct sctp_init_chunk *init;
	struct tuple tuple;
	char *error;

	DEBUGP("find_connect_for_live_packet\n");
	get_packet_tuple(packet, &tuple);

	*direction = DIRECTION_INVALID;
	struct socket *socket = state->socket_under_test;	/* shortcut */
	if (!socket)
		return NULL;

	bool is_sctp_match =
		(packet->sctp &&
		 (socket->protocol == IPPROTO_SCTP) &&
		 (socket->state == SOCKET_ACTIVE_INIT_SENT));
	bool is_tcp_match =
		(packet->tcp && packet->tcp->syn && !packet->tcp->ack &&
		 (socket->protocol == IPPROTO_TCP) &&
		 (socket->state == SOCKET_ACTIVE_SYN_SENT));
	bool is_udp_match =
		(packet->udp &&
		 (socket->protocol == IPPROTO_UDP) &&
		 (socket->state == SOCKET_ACTIVE_CONNECTING));
	bool is_udplite_match =
		(packet->udplite &&
		 (socket->protocol == IPPROTO_UDPLITE) &&
		 (socket->state == SOCKET_ACTIVE_CONNECTING));
	if (!is_sctp_match && !is_tcp_match &&
	    !is_udp_match && !is_udplite_match)
		return NULL;

	if (!is_equal_ip(&tuple.dst.ip, &socket->live.remote.ip) ||
	    !is_equal_port(tuple.dst.port, socket->live.remote.port))
		return NULL;

	*direction = DIRECTION_OUTBOUND;
	/* Using the details in this outgoing packet, fill in the
	 * new details we've learned about this actively initiated
	 * connection (for which we've seen a connect() call).
	 */
	socket->live.local.ip	= tuple.src.ip;
	socket->live.local.port	= tuple.src.port;

	if (packet->tcp)
		socket->live.local_isn	= ntohl(packet->tcp->seq);
	if (packet->sctp) {
		error = NULL;
		chunk = sctp_chunks_begin(packet, &iter, &error);
		if ((error == NULL) &&
		    (chunk != NULL) &&
		    (chunk->type == SCTP_INIT_CHUNK_TYPE)) {
			init = (struct sctp_init_chunk *)chunk;
			socket->live.local_initiate_tag = ntohl(init->initiate_tag);
			socket->live.local_initial_tsn = ntohl(init->initial_tsn);
		}
	}

	return socket;
}

/* Convert outbound TCP timestamp value from scripted value to live value. */
static int get_outbound_ts_val_mapping(
	struct socket *socket, u32 script_timestamp, u32 *live_timestamp)
{
	DEBUGP("get_outbound_ts_val_mapping\n");
	DEBUGP("ts_val_mapping %u -> ?\n", ntohl(script_timestamp));
	if (hash_map_get(socket->ts_val_map,
				 script_timestamp, live_timestamp))
		return STATUS_OK;
	return STATUS_ERR;
}

/* Store script->live mapping for outbound TCP timestamp value. */
static void set_outbound_ts_val_mapping(
	struct socket *socket, u32 script_timestamp, u32 live_timestamp)
{
	DEBUGP("set_outbound_ts_val_mapping\n");
	DEBUGP("ts_val_mapping %u -> %u\n",
	       ntohl(script_timestamp), ntohl(live_timestamp));
	hash_map_set(socket->ts_val_map,
			     script_timestamp, live_timestamp);
}

/* A helper to find the TCP timestamp option in a packet. Parse the
 * TCP options and fill in packet->tcp_ts_val with the location of the
 * TCP timestamp value field (or NULL if there isn't one), and
 * likewise fill in packet->tcp_ts_ecr with the location of the TCP
 * timestamp echo reply field (or NULL if there isn't one). Returns
 * STATUS_OK on success; on failure returns STATUS_ERR and sets
 * error message.
 */
static int find_tcp_timestamp(struct packet *packet, char **error)
{
	struct tcp_options_iterator iter;
	struct tcp_option *option = NULL;

	packet->tcp_ts_val = NULL;
	packet->tcp_ts_ecr = NULL;
	for (option = tcp_options_begin(packet, &iter); option != NULL;
	     option = tcp_options_next(&iter, error))
		if (option->kind == TCPOPT_TIMESTAMP) {
			packet->tcp_ts_val = &(option->data.time_stamp.val);
			packet->tcp_ts_ecr = &(option->data.time_stamp.ecr);
		}
	return *error ? STATUS_ERR : STATUS_OK;
}

/* A helper to help translate SACK sequence numbers between live and
 * script space. Specifically, it offsets SACK block sequence numbers
 * by the given 'ack_offset'. Returns STATUS_OK on success; on
 * failure returns STATUS_ERR and sets error message.
 */
static int offset_sack_blocks(struct packet *packet,
			      u32 ack_offset, char **error)
{
	struct tcp_options_iterator iter;
	struct tcp_option *option = NULL;
	for (option = tcp_options_begin(packet, &iter); option != NULL;
	     option = tcp_options_next(&iter, error)) {
		if (option->kind == TCPOPT_SACK) {
			int num_blocks = 0;
			if (num_sack_blocks(option->length,
						    &num_blocks, error))
				return STATUS_ERR;
			int i = 0;
			for (i = 0; i < num_blocks; ++i) {
				u32 val;
				val = ntohl(option->data.sack.block[i].left);
				val += ack_offset;
				option->data.sack.block[i].left = htonl(val);
				val = ntohl(option->data.sack.block[i].right);
				val += ack_offset;
				option->data.sack.block[i].right = htonl(val);
			}
		}
	}
	return *error ? STATUS_ERR : STATUS_OK;
}

static int map_inbound_icmp_sctp_packet(
	struct socket *socket, struct packet *live_packet, char **error)
{
	u32 *v_tag = packet_echoed_sctp_v_tag(live_packet);
	*v_tag = htonl(socket->live.remote_initiate_tag);
	return STATUS_OK;
}

/* Rewrite the TCP sequence number echoed by the ICMP packet.
 * The Linux TCP layer ignores ICMP messages with bogus sequence numbers.
 */
static int map_inbound_icmp_tcp_packet(
	struct socket *socket, struct packet *live_packet, char **error)
{
	u32 *seq = packet_echoed_tcp_seq(live_packet);
	bool is_syn = false;
	u32 seq_offset = local_seq_script_to_live_offset(socket, is_syn);
	*seq = htonl(ntohl(*seq) + seq_offset);
	return STATUS_OK;
}

/* UDP headers echoed by ICMP messages need no special rewriting. */
static int map_inbound_icmp_udp_packet(
	struct socket *socket, struct packet *live_packet, char **error)
{
	return STATUS_OK;
}

/* UDPLite headers echoed by ICMP messages need no special rewriting. */
static int map_inbound_icmp_udplite_packet(
	struct socket *socket, struct packet *live_packet, char **error)
{
	return STATUS_OK;
}

static int map_inbound_icmp_packet(
	struct socket *socket, struct packet *live_packet, char **error)
{
	if (packet_echoed_ip_protocol(live_packet) == IPPROTO_SCTP)
		return map_inbound_icmp_sctp_packet(socket, live_packet, error);
	else if (packet_echoed_ip_protocol(live_packet) == IPPROTO_TCP)
		return map_inbound_icmp_tcp_packet(socket, live_packet, error);
	else if (packet_echoed_ip_protocol(live_packet) == IPPROTO_UDP)
		return map_inbound_icmp_udp_packet(socket, live_packet, error);
	else if (packet_echoed_ip_protocol(live_packet) == IPPROTO_UDPLITE)
		return map_inbound_icmp_udplite_packet(socket, live_packet,
						       error);
	else
		assert(!"unsupported layer 4 protocol echoed in ICMP packet");
	return STATUS_ERR;
}

static int map_inbound_sctp_packet(
	struct socket *socket, struct packet *live_packet, char **error)
{
	struct sctp_chunks_iterator iter;
	struct sctp_chunk *chunk;
	struct sctp_data_chunk *data;
	struct sctp_init_chunk *init;
	struct sctp_init_ack_chunk *init_ack;
	struct sctp_sack_chunk *sack;
	struct sctp_abort_chunk *abort;
	struct sctp_shutdown_chunk *shutdown;
	struct sctp_ecne_chunk *ecne;
	struct sctp_cwr_chunk *cwr;
	struct sctp_shutdown_complete_chunk *shutdown_complete;
	struct sctp_i_data_chunk *i_data;
	u32 local_diff, remote_diff;
	u32 v_tag;
	u16 nr_gap_blocks, nr_dup_tsns, i;
	bool reflect_v_tag;
	bool contains_init_chunk;

	reflect_v_tag = false;
	contains_init_chunk = false;

	/* Map the TSNs and the initiate tags in the INIT and INIT-ACK chunk */
	for (chunk = sctp_chunks_begin(live_packet, &iter, error);
	     chunk != NULL;
	     chunk = sctp_chunks_next(&iter, error)) {
		if (*error != NULL) {
			return STATUS_ERR;
		}
		DEBUGP("live remote tsn 0x%08x, script remote tsn 0x%08x\n",
		       socket->live.remote_initial_tsn, socket->script.remote_initial_tsn);
		DEBUGP("live local tsn 0x%08x, script local tsn 0x%08x\n",
		       socket->live.local_initial_tsn, socket->script.local_initial_tsn);
		remote_diff = socket->live.remote_initial_tsn - socket->script.remote_initial_tsn;
		local_diff = socket->live.local_initial_tsn - socket->script.local_initial_tsn;
		switch (chunk->type) {
		case SCTP_DATA_CHUNK_TYPE:
			data = (struct sctp_data_chunk *)chunk;
			data->tsn = htonl(ntohl(data->tsn) + remote_diff);
			break;
		case SCTP_INIT_CHUNK_TYPE:
			init = (struct sctp_init_chunk *)chunk;
			init->initial_tsn = htonl(ntohl(init->initial_tsn) + remote_diff);
			/* XXX: Does this work in all cases? */
			if (ntohl(init->initiate_tag) == socket->script.local_initiate_tag) {
				init->initiate_tag = htonl(socket->live.local_initiate_tag);
			}
			contains_init_chunk = true;
			break;
		case SCTP_INIT_ACK_CHUNK_TYPE:
			init_ack = (struct sctp_init_ack_chunk *)chunk;
			init_ack->initial_tsn = htonl(ntohl(init_ack->initial_tsn) + remote_diff);
			/* XXX: Does this work in all cases? */
			if (ntohl(init_ack->initiate_tag) == socket->script.local_initiate_tag) {
				init_ack->initiate_tag = htonl(socket->live.local_initiate_tag);
			}
			break;
		case SCTP_SACK_CHUNK_TYPE:
			sack = (struct sctp_sack_chunk *)chunk;
			DEBUGP("Old SACK cum TSN %d\n", ntohl(sack->cum_tsn));
			sack->cum_tsn = htonl(ntohl(sack->cum_tsn) + local_diff);
			DEBUGP("New SACK cum TSN %d\n", ntohl(sack->cum_tsn));
			nr_gap_blocks = ntohs(sack->nr_gap_blocks);
			nr_dup_tsns = ntohs(sack->nr_dup_tsns);
			for (i = 0; i < nr_dup_tsns; i++) {
				sack->block[i + nr_gap_blocks].tsn = htonl(ntohl(sack->block[i + nr_gap_blocks].tsn) + local_diff);
			}
			break;
		case SCTP_ABORT_CHUNK_TYPE:
			abort = (struct sctp_abort_chunk *)chunk;
			if (abort->flags & SCTP_ABORT_CHUNK_T_BIT) {
				reflect_v_tag = true;
			}
			break;
		case SCTP_SHUTDOWN_CHUNK_TYPE:
			shutdown = (struct sctp_shutdown_chunk *)chunk;
			shutdown->cum_tsn = htonl(ntohl(shutdown->cum_tsn) + local_diff);
			break;
		case SCTP_ECNE_CHUNK_TYPE:
			ecne = (struct sctp_ecne_chunk *)chunk;
			ecne->lowest_tsn = htonl(ntohl(ecne->lowest_tsn) + local_diff);
			break;
		case SCTP_CWR_CHUNK_TYPE:
			cwr = (struct sctp_cwr_chunk *)chunk;
			cwr->lowest_tsn = htonl(ntohl(cwr->lowest_tsn) + local_diff);
			break;
		case SCTP_SHUTDOWN_COMPLETE_CHUNK_TYPE:
			shutdown_complete = (struct sctp_shutdown_complete_chunk *)chunk;
			if (shutdown_complete->flags & SCTP_SHUTDOWN_COMPLETE_CHUNK_T_BIT) {
				reflect_v_tag = true;
			}
			break;
		case SCTP_I_DATA_CHUNK_TYPE:
			i_data = (struct sctp_i_data_chunk *)chunk;
			i_data->tsn = htonl(ntohl(i_data->tsn) + remote_diff);
			break;
		default:
			break;
		}
	}
	/* Map the verification tag in the common header */
	DEBUGP("live remote initiate tag 0x%08x, script remote initiate tag 0x%08x\n",
	       socket->live.remote_initiate_tag, socket->script.remote_initiate_tag);
	DEBUGP("live local initiate tag 0x%08x, script local initiate tag 0x%08x\n",
	       socket->live.local_initiate_tag, socket->script.local_initiate_tag);
	if (live_packet->flags & FLAGS_SCTP_EXPLICIT_TAG) {
		v_tag = ntohl(live_packet->sctp->v_tag);
		DEBUGP("verification tag specified in script: 0x%08x\n", v_tag);
		if (v_tag != 0) {
			if (reflect_v_tag) {
				u32 diff;

				diff = v_tag - socket->script.remote_initiate_tag;
				v_tag = socket->live.remote_initiate_tag + diff;
			} else {
				u32 diff;

				diff = v_tag - socket->script.local_initiate_tag;
				v_tag = socket->live.local_initiate_tag + diff;
			}
			if (v_tag == 0) {
				DEBUGP("Need to increment, since it would be zero.\n");
				v_tag = 1;
			}
		}
	} else {
		DEBUGP("verification tag not specified in script.\n")
		if (contains_init_chunk) {
			v_tag = 0;
		} else {
			if (reflect_v_tag) {
				v_tag = socket->live.remote_initiate_tag;
			} else {
				v_tag = socket->live.local_initiate_tag;
			}
		}
	}
	DEBUGP("verification tag of inbound packet: 0x%08x\n", v_tag);
	live_packet->sctp->v_tag = htonl(v_tag);

	return STATUS_OK;
}

/* Rewrite the IP and TCP, UDP, or ICMP fields in 'live_packet', mapping
 * inbound packet values (address 4-tuple and sequence numbers in seq,
 * ACK, SACK blocks) from script values to live values, so that we can
 * inject this packet into the kernel and have the kernel accept it
 * for the given socket and process it. Returns STATUS_OK on success;
 * on failure returns STATUS_ERR and sets error message.
 */
static int map_inbound_packet(
	struct socket *socket, struct packet *live_packet, char **error)
{
	DEBUGP("map_inbound_packet\n");

	/* Remap packet to live values. */
	struct tuple live_inbound;
	socket_get_inbound(&socket->live, &live_inbound);
	set_packet_tuple(live_packet, &live_inbound);

	if ((live_packet->icmpv4 != NULL) || (live_packet->icmpv6 != NULL))
		return map_inbound_icmp_packet(socket, live_packet, error);

	if (live_packet->sctp) {
		return map_inbound_sctp_packet(socket, live_packet, error);
	}

	/* If no TCP headers to rewrite, then we're done. */
	if (live_packet->tcp == NULL)
		return STATUS_OK;

	/* Remap the sequence number from script sequence number to live. */
	const bool is_syn = live_packet->tcp->syn;
	const u32 seq_offset = remote_seq_script_to_live_offset(socket, is_syn);
	live_packet->tcp->seq =
	    htonl(ntohl(live_packet->tcp->seq) + seq_offset);

	/* Remap the ACK and SACKs from script sequence number to live. */
	const u32 ack_offset = local_seq_script_to_live_offset(socket, is_syn);
	if (live_packet->tcp->ack)
		live_packet->tcp->ack_seq =
			htonl(ntohl(live_packet->tcp->ack_seq) + ack_offset);
	if (offset_sack_blocks(live_packet, ack_offset, error))
		return STATUS_ERR;

	/* Find the timestamp echo reply is, so we can remap that below. */
	if (find_tcp_timestamp(live_packet, error))
		return STATUS_ERR;

	/* Remap TCP timestamp echo reply from script value to a live
	 * value. We say "a" rather than "the" live value because
	 * there could be multiple live values corresponding to the
	 * same script value if a live test replay flips to a new
	 * jiffie in a spot where the script did not.
	 */
	if (live_packet->tcp->ack && (live_packet->tcp_ts_ecr != NULL)) {
		u32 live_ts_ecr = 0;

		if (get_outbound_ts_val_mapping(socket,
						packet_tcp_ts_ecr(live_packet),
						&live_ts_ecr)) {
			asprintf(error,
				 "unable to find mapping for timestamp ecr %u",
				 packet_tcp_ts_ecr(live_packet));
			return STATUS_ERR;
		}
		packet_set_tcp_ts_ecr(live_packet, live_ts_ecr);
	}

	return STATUS_OK;
}

static int map_outbound_live_sctp_packet(
	struct socket *socket,
	struct packet *live_packet,
	struct packet *actual_packet,
	struct packet *script_packet,
	char **error)
{
	struct sctp_chunks_iterator iter;
	struct sctp_chunk *chunk;
	struct sctp_data_chunk *data;
	struct sctp_init_chunk *init;
	struct sctp_init_ack_chunk *init_ack;
	struct sctp_sack_chunk *sack;
	struct sctp_shutdown_chunk *shutdown;
	struct sctp_ecne_chunk *ecne;
	struct sctp_cwr_chunk *cwr;
	struct sctp_i_data_chunk *i_data;
	u32 local_diff, remote_diff;
	u16 nr_gap_blocks, nr_dup_tsns, i;

	/* FIXME: transform v-tag in the common header*/
	DEBUGP("map_outbound_live_sctp_packet\n");
	for (chunk = sctp_chunks_begin(actual_packet, &iter, error);
	     chunk != NULL;
	     chunk = sctp_chunks_next(&iter, error)) {
		if (*error != NULL) {
			return STATUS_ERR;
		}
		local_diff = socket->script.local_initial_tsn - socket->live.local_initial_tsn;
		remote_diff = socket->script.remote_initial_tsn - socket->live.remote_initial_tsn;
		DEBUGP("Chunk type: 0x%02x\n", chunk->type);
		switch (chunk->type) {
		case SCTP_DATA_CHUNK_TYPE:
			data = (struct sctp_data_chunk *)chunk;
			data->tsn = htonl(ntohl(data->tsn) + local_diff);
			break;
		case SCTP_INIT_CHUNK_TYPE:
			init = (struct sctp_init_chunk *)chunk;
			init->initial_tsn = htonl(ntohl(init->initial_tsn) + local_diff);
			/* XXX: Does this work in all cases? */
			if (ntohl(init->initiate_tag) == socket->live.local_initiate_tag) {
				init->initiate_tag = htonl(socket->script.local_initiate_tag);
			}
			break;
		case SCTP_INIT_ACK_CHUNK_TYPE:
			init_ack = (struct sctp_init_ack_chunk *)chunk;
			init_ack->initial_tsn = htonl(ntohl(init_ack->initial_tsn) + local_diff);
			/* XXX: Does this work in all cases? */
			if (ntohl(init_ack->initiate_tag) == socket->live.local_initiate_tag) {
				init_ack->initiate_tag = htonl(socket->script.local_initiate_tag);
			}
			break;
		case SCTP_SACK_CHUNK_TYPE:
			sack = (struct sctp_sack_chunk *)chunk;
			sack->cum_tsn = htonl(ntohl(sack->cum_tsn) + remote_diff);
			nr_gap_blocks = ntohs(sack->nr_gap_blocks);
			nr_dup_tsns = ntohs(sack->nr_dup_tsns);
			for (i = 0; i < nr_dup_tsns; i++) {
				sack->block[i + nr_gap_blocks].tsn = htonl(ntohl(sack->block[i + nr_gap_blocks].tsn) + remote_diff);
			}
			break;
		case SCTP_SHUTDOWN_CHUNK_TYPE:
			shutdown = (struct sctp_shutdown_chunk *)chunk;
			shutdown->cum_tsn = htonl(ntohl(shutdown->cum_tsn) + remote_diff);
			break;
		case SCTP_ECNE_CHUNK_TYPE:
			ecne = (struct sctp_ecne_chunk *)chunk;
			ecne->lowest_tsn = htonl(ntohl(ecne->lowest_tsn) + remote_diff);
			break;
		case SCTP_CWR_CHUNK_TYPE:
			cwr = (struct sctp_cwr_chunk *)chunk;
			cwr->lowest_tsn = htonl(ntohl(cwr->lowest_tsn) + remote_diff);
			break;
		case SCTP_I_DATA_CHUNK_TYPE:
			i_data = (struct sctp_i_data_chunk *)chunk;
			i_data->tsn = htonl(ntohl(i_data->tsn) + local_diff);
			break;
		default:
			break;
		}
	}
	return STATUS_OK;
}

/* Transforms values in the 'actual_packet' by mapping outbound packet
 * values in the sniffed 'live_packet' (address 4-tuple, sequence
 * number in seq, timestamp value) from live values to script values
 * in the space of 'script_packet'. This will allow us to compare a
 * packet sent by the kernel to the packet expected by the script.
 */
static int map_outbound_live_packet(
	struct socket *socket,
	struct packet *live_packet,
	struct packet *actual_packet,
	struct packet *script_packet,
	char **error)
{
	DEBUGP("map_outbound_live_packet\n");

	struct tuple live_packet_tuple, live_outbound, script_outbound;

	/* Verify packet addresses are outbound and live for this socket. */
	get_packet_tuple(live_packet, &live_packet_tuple);
	socket_get_outbound(&socket->live, &live_outbound);
	assert(is_equal_tuple(&live_packet_tuple, &live_outbound));

	/* Rewrite 4-tuple to be outbound script values. */
	socket_get_outbound(&socket->script, &script_outbound);
	set_packet_tuple(actual_packet, &script_outbound);

	if (live_packet->sctp) {
		return map_outbound_live_sctp_packet(socket, live_packet, actual_packet, script_packet, error);
	}

	/* If no TCP headers to rewrite, then we're done. */
	if (live_packet->tcp == NULL)
		return STATUS_OK;

	/* Rewrite TCP sequence number from live to script space. */
	const bool is_syn = live_packet->tcp->syn;
	const u32 seq_offset = local_seq_live_to_script_offset(socket, is_syn);
	actual_packet->tcp->seq =
	    htonl(ntohl(live_packet->tcp->seq) + seq_offset);

	/* Rewrite ACKs and SACKs from live to script space. */
	const u32 ack_offset = remote_seq_live_to_script_offset(socket, is_syn);
	if (actual_packet->tcp->ack)
		actual_packet->tcp->ack_seq =
		    htonl(ntohl(live_packet->tcp->ack_seq) + ack_offset);
	if (offset_sack_blocks(actual_packet, ack_offset, error))
		return STATUS_ERR;

	/* Extract location of script and actual TCP timestamp values. */
	if (find_tcp_timestamp(script_packet, error))
		return STATUS_ERR;
	if (find_tcp_timestamp(actual_packet, error))
		return STATUS_ERR;
	if ((script_packet->tcp_ts_val != NULL) &&
	    (actual_packet->tcp_ts_val != NULL)) {
		u32 script_ts_val = packet_tcp_ts_val(script_packet);
		u32 actual_ts_val = packet_tcp_ts_val(actual_packet);

		/* Remember script->actual TS val mapping for later. */
		set_outbound_ts_val_mapping(socket,
					    script_ts_val,
					    actual_ts_val);

		/* Find baseline for socket's live->script TS val mapping. */
		if (!socket->found_first_tcp_ts) {
			socket->found_first_tcp_ts = true;
			socket->first_script_ts_val = script_ts_val;
			socket->first_actual_ts_val = actual_ts_val;
		}

		/* Rewrite TCP timestamp value to script space, so we
		 * can compare the script and actual outbound TCP
		 * timestamp val.
		 */
		packet_set_tcp_ts_val(actual_packet,
				      socket->first_script_ts_val +
				      (actual_ts_val -
				       socket->first_actual_ts_val));
	}

	return STATUS_OK;
}

/* Verify IP and TCP checksums on an outbound live packet. */
static int verify_outbound_live_checksums(struct packet *live_packet,
					  char **error)
{
	/* Verify IP header checksum. */
	if ((live_packet->ipv4 != NULL) &&
	    ipv4_checksum(live_packet->ipv4,
			  ipv4_header_len(live_packet->ipv4))) {
		asprintf(error, "bad outbound IP checksum");
		return STATUS_ERR;
	}

	/* TODO(ncardwell): Verify TCP and UDP checksum. This is a little
	 * subtle, due to TCP checksum offloading.
	 */

	return STATUS_OK;
}

/* Check whether the given field of a packet matches the expected
 * value, and emit a human-readable error message if not.
 */
static int check_field(
	const char *name,	/* human-readable name of the header field */
	u32 expected,		/* value script hopes to see */
	u32 actual,		/* actual value seen during test */
	char **error)		/* human-readable error string on failure */
{
	if (actual != expected) {
		asprintf(error, "live packet field %s: "
			 "expected: %u (0x%x) vs actual: %u (0x%x)",
			 name, expected, expected, actual, actual);
		return STATUS_ERR;
	}
	return STATUS_OK;
}

/* Verify that the actual ECN bits are as the script expected. */
static int verify_outbound_live_ecn(enum ip_ecn_t ecn,
				    u8 actual_ecn_bits,
				    u8 script_ecn_bits,
				    char **error)
{
	if (ecn == ECN_NOCHECK)
		return STATUS_OK;

	if (ecn == ECN_ECT01) {
		if ((actual_ecn_bits != IP_ECN_ECT0) &&
		    (actual_ecn_bits != IP_ECN_ECT1)) {
			asprintf(error, "live packet field ip_ecn: "
				 "expected: 0x1 or 0x2 vs actual: 0x%x",
				 actual_ecn_bits);
			return STATUS_ERR;
		}
	} else if (check_field("ip_ecn",
			       script_ecn_bits,
			       actual_ecn_bits, error)) {
		return STATUS_ERR;
	}

	return STATUS_OK;
}

/* How many bytes should we tack onto the script packet to account for
 * the actual TCP options we did see?
 */
static int tcp_options_allowance(const struct packet *actual_packet,
				 const struct packet *script_packet)
{
	if (script_packet->flags & FLAG_OPTIONS_NOCHECK)
		return packet_tcp_options_len(actual_packet);
	else
		return 0;
}

/* Verify that required actual IPv4 header fields are as the script expected. */
static int verify_ipv4(
	const struct packet *actual_packet,
	const struct packet *script_packet,
	int layer, char **error)
{
	const struct ipv4 *actual_ipv4 = actual_packet->headers[layer].h.ipv4;
	const struct ipv4 *script_ipv4 = script_packet->headers[layer].h.ipv4;

	if (check_field("ipv4_version",
			script_ipv4->version,
			actual_ipv4->version, error) ||
	    check_field("ipv4_protocol",
			script_ipv4->protocol,
			actual_ipv4->protocol, error) ||
	    check_field("ipv4_header_length",
			script_ipv4->ihl,
			actual_ipv4->ihl, error))
		return STATUS_ERR;
	switch (script_ipv4->protocol) {
	case IPPROTO_SCTP:
		/* FIXME */;
		break;
	case IPPROTO_TCP:
		if (check_field("ipv4_total_length",
				(ntohs(script_ipv4->tot_len) +
				 tcp_options_allowance(actual_packet,
						       script_packet)),
				ntohs(actual_ipv4->tot_len), error))
			return STATUS_ERR;
		break;
	default:
		if (check_field("ipv4_total_length",
				ntohs(script_ipv4->tot_len),
				ntohs(actual_ipv4->tot_len), error))
			return STATUS_ERR;
		break;
	}

	if (verify_outbound_live_ecn(script_packet->ecn,
				     ipv4_ecn_bits(actual_ipv4),
				     ipv4_ecn_bits(script_ipv4),
				     error))
		return STATUS_ERR;

	return STATUS_OK;
}

/* Verify that required actual IPv6 header fields are as the script expected. */
static int verify_ipv6(
	const struct packet *actual_packet,
	const struct packet *script_packet,
	int layer, char **error)
{
	const struct ipv6 *actual_ipv6 = actual_packet->headers[layer].h.ipv6;
	const struct ipv6 *script_ipv6 = script_packet->headers[layer].h.ipv6;

	if (check_field("ipv6_version",
			script_ipv6->version,
			actual_ipv6->version, error) ||
	    check_field("ipv6_next_header",
			script_ipv6->next_header,
			actual_ipv6->next_header, error))
		return STATUS_ERR;
	switch (script_ipv6->next_header) {
	case IPPROTO_SCTP:
		/* FIXME */
		break;
	case IPPROTO_TCP:
		if (check_field("ipv6_payload_len",
				(ntohs(script_ipv6->payload_len) +
				 tcp_options_allowance(actual_packet,
						       script_packet)),
				ntohs(actual_ipv6->payload_len), error))
			return STATUS_ERR;
		break;
	default:
		if (check_field("ipv6_payload_len",
				ntohs(script_ipv6->payload_len),
				ntohs(actual_ipv6->payload_len), error))
			return STATUS_ERR;
		break;
	}

	if (verify_outbound_live_ecn(script_packet->ecn,
				     ipv6_ecn_bits(actual_ipv6),
				     ipv6_ecn_bits(script_ipv6),
				     error))
		return STATUS_ERR;

	return STATUS_OK;
}

static int verify_sctp_parameters(u8 *begin, u16 length,
                                  struct sctp_chunk_list_item *script_chunk_item,
                                  char **error)
{
	struct sctp_parameters_iterator iter;
	struct sctp_parameter *actual_parameter;
	struct sctp_parameter *script_parameter;
	struct sctp_parameter_list_item *script_parameter_item;
	u32 flags;

	for (actual_parameter = sctp_parameters_begin(begin, length, &iter, error),
	     script_parameter_item = script_chunk_item->parameter_list->first;
	     actual_parameter != NULL && script_parameter_item != NULL;
	     actual_parameter = sctp_parameters_next(&iter, error),
	     script_parameter_item = script_parameter_item->next) {
		if (*error != NULL) {
			DEBUGP("Error during iteration\n");
			return STATUS_ERR;
		}
		script_parameter = script_parameter_item->parameter;
		flags = script_parameter_item->flags;
		assert(script_parameter != NULL);
		DEBUGP("script parameter: type 0x%04x, length %05d\n",
		       ntohs(script_parameter->type),
		       ntohs(script_parameter->length));
		DEBUGP("actual parameter: type 0x%04x, length %05d\n",
		       ntohs(actual_parameter->type),
		       ntohs(actual_parameter->length));
		DEBUGP("flags: %08x\n", flags);
		if ((flags & FLAG_PARAMETER_TYPE_NOCHECK ? STATUS_OK :
		        check_field("sctp_parameter_type",
		                    ntohs(script_parameter->type),
		                    ntohs(actual_parameter->type),
		                    error)) ||
		    (flags & FLAG_PARAMETER_LENGTH_NOCHECK ? STATUS_OK :
		        check_field("sctp_parameter_length",
		                    ntohs(script_parameter->length),
		                    ntohs(actual_parameter->length),
		                    error))) {
			return STATUS_ERR;
		}
		if ((flags & FLAG_PARAMETER_VALUE_NOCHECK) == 0) {
			assert((flags & FLAG_PARAMETER_LENGTH_NOCHECK) == 0);
			if (memcmp(script_parameter->value,
			           actual_parameter->value,
			           ntohs(actual_parameter->length) - sizeof(struct sctp_parameter))) {
				asprintf(error, "live packet parameter value not as expected");
				return STATUS_ERR;
			}
		}
	}
	if (actual_parameter != NULL) {
		DEBUGP("actual chunk contains more parameters than script chunk\n");
	}
	if (script_parameter_item != NULL) {
		DEBUGP("script chunk contains more parameters than actual chunk\n");
	}
	if ((actual_parameter != NULL) || (script_parameter_item != NULL)) {
		asprintf(error,
		         "live chunk and expected chunk have not the same number of parameters");
		return STATUS_ERR;
	}
	return STATUS_OK;
}

static int verify_sctp_causes(struct sctp_chunk *chunk, u16 offset,
                              struct sctp_chunk_list_item *script_chunk_item,
                              char **error)
{
	struct sctp_causes_iterator iter;
	struct sctp_cause *actual_cause;
	struct sctp_cause *script_cause;
	struct sctp_cause_list_item *script_cause_item;
	u32 flags;

	for (actual_cause = sctp_causes_begin(chunk, offset, &iter, error),
	     script_cause_item = script_chunk_item->cause_list->first;
	     actual_cause != NULL && script_cause_item != NULL;
	     actual_cause = sctp_causes_next(&iter, error),
	     script_cause_item = script_cause_item->next) {
		if (*error != NULL) {
			DEBUGP("Error during iteration\n");
			return STATUS_ERR;
		}
		script_cause = script_cause_item->cause;
		flags = script_cause_item->flags;
		assert(script_cause != NULL);
		DEBUGP("script cause: code 0x%04x, length %05d\n",
		       ntohs(script_cause->code),
		       ntohs(script_cause->length));
		DEBUGP("actual cause: code 0x%04x, length %05d\n",
		       ntohs(actual_cause->code),
		       ntohs(actual_cause->length));
		DEBUGP("flags: %08x\n", flags);
		if ((flags & FLAG_CAUSE_CODE_NOCHECK ? STATUS_OK :
		        check_field("sctp_cause_code",
		                    ntohs(script_cause->code),
		                    ntohs(actual_cause->code),
		                    error)) ||
		    (flags & FLAG_CAUSE_LENGTH_NOCHECK ? STATUS_OK :
		        check_field("sctp_cause_length",
		                    ntohs(script_cause->length),
		                    ntohs(actual_cause->length),
		                    error))) {
			return STATUS_ERR;
		}
		if ((flags & FLAG_CAUSE_INFORMATION_NOCHECK) == 0) {
			assert((flags & FLAG_CAUSE_LENGTH_NOCHECK) == 0);
			if (memcmp(script_cause->information,
			           actual_cause->information,
			           ntohs(actual_cause->length) - sizeof(struct sctp_cause))) {
				asprintf(error, "live packet cause information not as expected");
				return STATUS_ERR;
			}
		}
	}
	if (actual_cause != NULL) {
		DEBUGP("actual chunk contains more causes than script chunk\n");
	}
	if (script_cause_item != NULL) {
		DEBUGP("script chunk contains more causes than actual chunk\n");
	}
	if ((actual_cause != NULL) || (script_cause_item != NULL)) {
		asprintf(error,
		         "live chunk and expected chunk have not the same number of causes");
		return STATUS_ERR;
	}
	return STATUS_OK;
}

static int verify_data_chunk(struct sctp_data_chunk *actual_chunk,
                             struct sctp_data_chunk *script_chunk,
                             u32 flags, char **error)
{
	if (check_field("sctp_data_chunk_tsn",
		        ntohl(script_chunk->tsn),
		        ntohl(actual_chunk->tsn),
		        error) ||
	    (flags & FLAG_DATA_CHUNK_SID_NOCHECK ? STATUS_OK :
	        check_field("sctp_data_chunk_sid",
		            ntohs(script_chunk->sid),
		            ntohs(actual_chunk->sid),
		            error)) ||
	    (flags & FLAG_DATA_CHUNK_SSN_NOCHECK? STATUS_OK :
		check_field("sctp_data_chunk_ssn",
		            ntohs(script_chunk->ssn),
		            ntohs(actual_chunk->ssn),
		            error)) ||
	    (flags & FLAG_DATA_CHUNK_PPID_NOCHECK? STATUS_OK :
		check_field("sctp_data_chunk_ppid",
		            ntohl(script_chunk->ppid),
		            ntohl(actual_chunk->ppid),
		            error))) {
		return STATUS_ERR;
	}
	return STATUS_OK;
}

static int verify_init_chunk(struct sctp_init_chunk *actual_chunk,
                             struct sctp_chunk_list_item *script_chunk_item,
                             char **error)
{
	struct sctp_init_chunk *script_chunk;
	u32 flags;
	u16 parameters_length;

	script_chunk = (struct sctp_init_chunk *)script_chunk_item->chunk;
	flags = script_chunk_item->flags;
	assert(ntohs(actual_chunk->length) >= sizeof(struct sctp_init_chunk));
	parameters_length = ntohs(actual_chunk->length) - sizeof(struct sctp_init_chunk);
	if ((flags & FLAG_INIT_CHUNK_TAG_NOCHECK ? STATUS_OK :
	        check_field("sctp_init_chunk_tag",
		            ntohl(script_chunk->initiate_tag),
		            ntohl(actual_chunk->initiate_tag),
		            error)) ||
	    (flags & FLAG_INIT_CHUNK_A_RWND_NOCHECK ? STATUS_OK :
	        check_field("sctp_init_chunk_a_rwnd",
		            ntohl(script_chunk->a_rwnd),
		            ntohl(actual_chunk->a_rwnd),
		            error)) ||
	    (flags & FLAG_INIT_CHUNK_OS_NOCHECK? STATUS_OK :
		check_field("sctp_init_chunk_os",
		            ntohs(script_chunk->os),
		            ntohs(actual_chunk->os),
		            error)) ||
	    (flags & FLAG_INIT_CHUNK_IS_NOCHECK? STATUS_OK :
		check_field("sctp_init_chunk_is",
		            ntohs(script_chunk->is),
		            ntohs(actual_chunk->is),
		            error)) ||
	    (flags & FLAG_INIT_CHUNK_TSN_NOCHECK? STATUS_OK :
		check_field("sctp_init_chunk_tsn",
		            ntohl(script_chunk->initial_tsn),
		            ntohl(actual_chunk->initial_tsn),
		            error)) ||
	    (flags & FLAG_INIT_CHUNK_OPT_PARAM_NOCHECK? STATUS_OK :
	        verify_sctp_parameters(actual_chunk->parameter,
	                               parameters_length,
	                               script_chunk_item,
	                               error))) {
		return STATUS_ERR;
	}
	return STATUS_OK;
}

static int verify_init_ack_chunk(struct sctp_init_ack_chunk *actual_chunk,
                                 struct sctp_chunk_list_item *script_chunk_item,
                                 char **error)
{
	struct sctp_init_ack_chunk *script_chunk;
	u32 flags;
	u16 parameters_length;

	script_chunk = (struct sctp_init_ack_chunk *)script_chunk_item->chunk;
	flags = script_chunk_item->flags;
	assert(ntohs(actual_chunk->length) >= sizeof(struct sctp_init_ack_chunk));
	parameters_length = ntohs(actual_chunk->length) - sizeof(struct sctp_init_ack_chunk);
	if ((flags & FLAG_INIT_ACK_CHUNK_TAG_NOCHECK ? STATUS_OK :
	        check_field("sctp_init_ack_chunk_tag",
		            ntohl(script_chunk->initiate_tag),
		            ntohl(actual_chunk->initiate_tag),
		            error)) ||
	    (flags & FLAG_INIT_ACK_CHUNK_A_RWND_NOCHECK ? STATUS_OK :
	        check_field("sctp_init_ack_chunk_a_rwnd",
		            ntohl(script_chunk->a_rwnd),
		            ntohl(actual_chunk->a_rwnd),
		            error)) ||
	    (flags & FLAG_INIT_ACK_CHUNK_OS_NOCHECK? STATUS_OK :
		check_field("sctp_init_ack_chunk_os",
		            ntohs(script_chunk->os),
		            ntohs(actual_chunk->os),
		            error)) ||
	    (flags & FLAG_INIT_ACK_CHUNK_IS_NOCHECK? STATUS_OK :
		check_field("sctp_init_ack_chunk_is",
		            ntohs(script_chunk->is),
		            ntohs(actual_chunk->is),
		            error)) ||
	    (flags & FLAG_INIT_ACK_CHUNK_TSN_NOCHECK? STATUS_OK :
		check_field("sctp_init_ack_chunk_tsn",
		            ntohl(script_chunk->initial_tsn),
		            ntohl(actual_chunk->initial_tsn),
		            error)) ||
	    (flags & FLAG_INIT_ACK_CHUNK_OPT_PARAM_NOCHECK? STATUS_OK :
		verify_sctp_parameters(actual_chunk->parameter,
		                       parameters_length,
		                       script_chunk_item,
		                       error))) {
		return STATUS_ERR;
	}
	return STATUS_OK;
}

static int verify_sack_chunk(struct sctp_sack_chunk *actual_chunk,
                             struct sctp_sack_chunk *script_chunk,
                             u32 flags, char **error)
{
	u16 actual_nr_gap_blocks, actual_nr_dup_tsns;
	u16 script_nr_gap_blocks, script_nr_dup_tsns;
	u16 i, actual_base, script_base;

	actual_nr_gap_blocks = ntohs(actual_chunk->nr_gap_blocks);
	actual_nr_dup_tsns = ntohs(actual_chunk->nr_dup_tsns);
	script_nr_gap_blocks = ntohs(script_chunk->nr_gap_blocks);
	script_nr_dup_tsns = ntohs(script_chunk->nr_dup_tsns);

	if ((flags & FLAG_SACK_CHUNK_CUM_TSN_NOCHECK ? STATUS_OK :
	        check_field("sctp_sack_chunk_cum_tsn",
		            ntohl(script_chunk->cum_tsn),
		            ntohl(actual_chunk->cum_tsn),
		            error)) ||
	    (flags & FLAG_SACK_CHUNK_A_RWND_NOCHECK ? STATUS_OK :
	        check_field("sctp_sack_chunk_a_rwnd",
		            ntohl(script_chunk->a_rwnd),
		            ntohl(actual_chunk->a_rwnd),
		            error)) ||
	    (flags & FLAG_SACK_CHUNK_GAP_BLOCKS_NOCHECK? STATUS_OK :
		check_field("sctp_sack_chunk_nr_gap_blocks",
		            script_nr_gap_blocks,
		            actual_nr_gap_blocks,
		            error)) ||
	    (flags & FLAG_SACK_CHUNK_DUP_TSNS_NOCHECK? STATUS_OK :
		check_field("sctp_sack_chunk_nr_dup_tsns",
		            script_nr_dup_tsns,
		            actual_nr_dup_tsns,
		            error))) {
		return STATUS_ERR;
	}

	if ((flags & FLAG_SACK_CHUNK_GAP_BLOCKS_NOCHECK) == 0) {
		for (i = 0; i < script_nr_gap_blocks; i++) {
			if (check_field("sctp_sack_chunk_gap_block_start",
		                        ntohs(script_chunk->block[i].gap.start),
		                        ntohs(actual_chunk->block[i].gap.start),
		                        error) ||
		            check_field("sctp_sack_chunk_gap_block_end",
		                        ntohs(script_chunk->block[i].gap.end),
		                        ntohs(actual_chunk->block[i].gap.end),
		                        error)) {
				return STATUS_ERR;
			}
		}
	}
	if ((flags & FLAG_SACK_CHUNK_DUP_TSNS_NOCHECK) == 0) {
		actual_base = actual_nr_gap_blocks;
		if ((flags & FLAG_SACK_CHUNK_GAP_BLOCKS_NOCHECK) == 0) {
			script_base = actual_nr_gap_blocks;
		} else {
			script_base = 0;
		}
		for (i = 0; i < script_nr_dup_tsns; i++) {
			if (check_field("sctp_sack_chunk_dup_tsn",
		                        ntohl(script_chunk->block[script_base + i].tsn),
		                        ntohl(actual_chunk->block[actual_base + i].tsn),
		                        error)) {
				return STATUS_ERR;
			}
		}
	}
	return STATUS_OK;
}

static int verify_heartbeat_chunk(struct sctp_heartbeat_chunk *actual_chunk,
                                  struct sctp_heartbeat_chunk *script_chunk,
                                  u32 flags, char **error)
{
	u16 length;

	if (flags & FLAG_CHUNK_VALUE_NOCHECK) {
		return STATUS_OK;
	} else {
		assert((flags & FLAG_CHUNK_LENGTH_NOCHECK) == 0);
		length = ntohs(actual_chunk->length);
		assert(length >= sizeof(struct sctp_heartbeat_chunk));
		if (memcmp(actual_chunk->value,
		           script_chunk->value,
		           length - sizeof(struct sctp_heartbeat_chunk)) == 0) {
		        return STATUS_OK;
		} else {
			asprintf(error, "live packet heartbeat info not as expected");
			return STATUS_ERR;
		}
	}
}

static int verify_heartbeat_ack_chunk(struct sctp_heartbeat_ack_chunk *actual_chunk,
                                      struct sctp_heartbeat_ack_chunk *script_chunk,
                                      u32 flags, char **error)
{
	u16 length;

	if (flags & FLAG_CHUNK_VALUE_NOCHECK) {
		return STATUS_OK;
	} else {
		assert((flags & FLAG_CHUNK_LENGTH_NOCHECK) == 0);
		length = ntohs(actual_chunk->length);
		assert(length >= sizeof(struct sctp_heartbeat_ack_chunk));
		if (memcmp(actual_chunk->value,
		           script_chunk->value,
		           length - sizeof(struct sctp_heartbeat_ack_chunk)) == 0) {
		        return STATUS_OK;
		} else {
			asprintf(error, "live packet heartbeat info not as expected");
			return STATUS_ERR;
		}
	}
}

static int verify_abort_chunk(struct sctp_abort_chunk *actual_chunk,
                              struct sctp_chunk_list_item *script_chunk_item,
                              char **error)
{
	u32 flags;

	assert(ntohs(actual_chunk->length) >= sizeof(struct sctp_abort_chunk));
	flags = script_chunk_item->flags;
	return (flags & FLAG_ABORT_CHUNK_OPT_CAUSES_NOCHECK ? STATUS_OK :
	    verify_sctp_causes((struct sctp_chunk *)actual_chunk,
	                       sizeof(struct sctp_error_chunk),
		               script_chunk_item, error));
}

static int verify_shutdown_chunk(struct sctp_shutdown_chunk *actual_chunk,
                                 struct sctp_shutdown_chunk *script_chunk,
                                 u32 flags, char **error)
{
	return (flags & FLAG_SHUTDOWN_CHUNK_CUM_TSN_NOCHECK) ? STATUS_OK :
	        check_field("sctp_shutdown_chunk_cum_tsn",
		            ntohl(script_chunk->cum_tsn),
		            ntohl(actual_chunk->cum_tsn),
		            error);
}

static int verify_shutdown_ack_chunk(struct sctp_shutdown_ack_chunk *actual_chunk,
                                     struct sctp_shutdown_ack_chunk *script_chunk,
                                     u32 flags, char **error)
{
	/* Nothing to check */
	return STATUS_OK;
}

static int verify_error_chunk(struct sctp_error_chunk *actual_chunk,
                              struct sctp_chunk_list_item *script_chunk_item,
                              char **error)
{
	u32 flags;

	assert(ntohs(actual_chunk->length) >= sizeof(struct sctp_error_chunk));
	flags = script_chunk_item->flags;
	return (flags & FLAG_ERROR_CHUNK_OPT_CAUSES_NOCHECK ? STATUS_OK :
	    verify_sctp_causes((struct sctp_chunk *)actual_chunk,
	                       sizeof(struct sctp_error_chunk),
		               script_chunk_item, error));
}

static int verify_cookie_echo_chunk(struct sctp_cookie_echo_chunk *actual_chunk,
                                    struct sctp_cookie_echo_chunk *script_chunk,
                                    u32 flags, char **error)
{
	u16 length;

	if (flags & FLAG_CHUNK_VALUE_NOCHECK) {
		return STATUS_OK;
	} else {
		assert((flags & FLAG_CHUNK_LENGTH_NOCHECK) == 0);
		length = ntohs(actual_chunk->length);
		assert(length >= sizeof(struct sctp_cookie_echo_chunk));
		if (memcmp(actual_chunk->cookie,
		           script_chunk->cookie,
		           length - sizeof(struct sctp_cookie_echo_chunk)) == 0) {
		        return STATUS_OK;
		} else {
			return STATUS_ERR;
		}
	}
}

static int verify_cookie_ack_chunk(struct sctp_cookie_ack_chunk *actual_chunk,
                                   struct sctp_cookie_ack_chunk *script_chunk,
                                   u32 flags, char **error)
{
	/* Nothing to check */
	return STATUS_OK;
}

static int verify_ecne_chunk(struct sctp_ecne_chunk *actual_chunk,
                             struct sctp_ecne_chunk *script_chunk,
                             u32 flags, char **error)
{
	return (flags & FLAG_ECNE_CHUNK_LOWEST_TSN_NOCHECK ? STATUS_OK :
	        check_field("sctp_ecne_chunk_lowest_tsn",
		            ntohl(script_chunk->lowest_tsn),
		            ntohl(actual_chunk->lowest_tsn),
		            error));
}

static int verify_cwr_chunk(struct sctp_cwr_chunk *actual_chunk,
                            struct sctp_cwr_chunk *script_chunk,
                            u32 flags, char **error)
{
	return (flags & FLAG_CWR_CHUNK_LOWEST_TSN_NOCHECK ? STATUS_OK :
	        check_field("sctp_cwr_chunk_lowest_tsn",
		            ntohl(script_chunk->lowest_tsn),
		            ntohl(actual_chunk->lowest_tsn),
		            error));
}

static int verify_shutdown_complete_chunk(struct sctp_shutdown_complete_chunk *actual_chunk,
                                          struct sctp_shutdown_complete_chunk *script_chunk,
                                          u32 flags, char **error)
{
	/* Nothing to check */
	return STATUS_OK;
}

static int verify_i_data_chunk(struct sctp_i_data_chunk *actual_chunk,
                               struct sctp_i_data_chunk *script_chunk,
                               u32 flags, char **error)
{
	if (check_field("sctp_i_data_chunk_tsn",
		        ntohl(script_chunk->tsn),
		        ntohl(actual_chunk->tsn),
		        error) ||
	    (flags & FLAG_I_DATA_CHUNK_SID_NOCHECK ? STATUS_OK :
	        check_field("sctp_i_data_chunk_sid",
		            ntohs(script_chunk->sid),
		            ntohs(actual_chunk->sid),
		            error)) ||
	    (flags & FLAG_I_DATA_CHUNK_RES_NOCHECK ? STATUS_OK :
	        check_field("sctp_i_data_chunk_res",
		            ntohs(script_chunk->res),
		            ntohs(actual_chunk->res),
		            error)) ||
	    (flags & FLAG_I_DATA_CHUNK_MID_NOCHECK? STATUS_OK :
		check_field("sctp_i_data_chunk_mid",
		            ntohl(script_chunk->mid),
		            ntohl(actual_chunk->mid),
		            error)) ||
	    (flags & FLAG_I_DATA_CHUNK_PPID_NOCHECK? STATUS_OK :
		check_field("sctp_i_data_chunk_ppid",
		            ntohl(script_chunk->field.ppid),
		            ntohl(actual_chunk->field.ppid),
		            error)) ||
	    (flags & FLAG_I_DATA_CHUNK_FSN_NOCHECK? STATUS_OK :
		check_field("sctp_i_data_chunk_fsn",
		            ntohl(script_chunk->field.fsn),
		            ntohl(actual_chunk->field.fsn),
		            error))) {
		return STATUS_ERR;
	}
	return STATUS_OK;
}

static int verify_pad_chunk(struct sctp_pad_chunk *actual_chunk,
                            struct sctp_pad_chunk *script_chunk,
                            u32 flags, char **error)
{
	/* Nothing to check */
	return STATUS_OK;
}

/* Verify that required actual SCTP packet fields are as the script expected. */
static int verify_sctp(
	const struct packet *actual_packet,
	const struct packet *script_packet,
	int layer, char **error)
{
	struct sctp_chunks_iterator iter;
	struct sctp_chunk *actual_chunk;
	struct sctp_chunk *script_chunk;
	struct sctp_chunk_list_item *script_chunk_item;
	u32 flags;
	int result;

	DEBUGP("Verifying SCTP packet\n")
	DEBUGP("script packet: src port %05u, dst port %05u, v-tag 0x%08x\n",
	       ntohs(script_packet->sctp->src_port),
	       ntohs(script_packet->sctp->dst_port),
	       ntohl(script_packet->sctp->v_tag));
	DEBUGP("actual packet: src port %05u, dst port %05u, v-tag 0x%08x\n",
	       ntohs(actual_packet->sctp->src_port),
	       ntohs(actual_packet->sctp->dst_port),
	       ntohl(actual_packet->sctp->v_tag));
	for (actual_chunk = sctp_chunks_begin((struct packet *)actual_packet, &iter, error),
	     script_chunk_item = script_packet->chunk_list->first;
	     actual_chunk != NULL && script_chunk_item != NULL;
	     actual_chunk = sctp_chunks_next(&iter, error),
	     script_chunk_item = script_chunk_item->next) {
		if (*error != NULL) {
			DEBUGP("Error during iteration\n");
			return STATUS_ERR;
		}
		script_chunk = script_chunk_item->chunk;
		flags = script_chunk_item->flags;
		assert(script_chunk != NULL);
		DEBUGP("script chunk: type %02d, flags 0x%02x, length %04d\n",
		       script_chunk->type,
		       script_chunk->flags,
		       ntohs(script_chunk->length));
		DEBUGP("actual chunk: type %02d, flags 0x%02x, length %04d\n",
		       actual_chunk->type,
		       actual_chunk->flags,
		       ntohs(actual_chunk->length));
		if (check_field("sctp_chunk_type",
		                script_chunk->type,
		                actual_chunk->type,
		                error) ||
		    (flags & FLAG_CHUNK_FLAGS_NOCHECK ? STATUS_OK :
		        check_field("sctp_chunk_flags",
		                    script_chunk->flags,
		                    actual_chunk->flags,
		                    error)) ||
		    (flags & FLAG_CHUNK_LENGTH_NOCHECK ? STATUS_OK :
		        check_field("sctp_chunk_length",
		                    ntohs(script_chunk->length),
		                    ntohs(actual_chunk->length),
		                    error))) {
			return STATUS_ERR;
		}
		switch (actual_chunk->type) {
		case SCTP_DATA_CHUNK_TYPE:
			result = verify_data_chunk((struct sctp_data_chunk *)actual_chunk,
			                           (struct sctp_data_chunk *)script_chunk,
			                           flags, error);
			break;
		case SCTP_INIT_CHUNK_TYPE:
			result = verify_init_chunk((struct sctp_init_chunk *)actual_chunk,
			                           script_chunk_item, error);
			break;
		case SCTP_INIT_ACK_CHUNK_TYPE:
			result = verify_init_ack_chunk((struct sctp_init_ack_chunk *)actual_chunk,
			                               script_chunk_item, error);
			break;
		case SCTP_SACK_CHUNK_TYPE:
			result = verify_sack_chunk((struct sctp_sack_chunk *)actual_chunk,
			                           (struct sctp_sack_chunk *)script_chunk,
			                           flags, error);
			break;
		case SCTP_HEARTBEAT_CHUNK_TYPE:
			result = verify_heartbeat_chunk((struct sctp_heartbeat_chunk *)actual_chunk,
			                                (struct sctp_heartbeat_chunk *)script_chunk,
			                                flags, error);
			break;
		case SCTP_HEARTBEAT_ACK_CHUNK_TYPE:
			result = verify_heartbeat_ack_chunk((struct sctp_heartbeat_ack_chunk *)actual_chunk,
			                                    (struct sctp_heartbeat_ack_chunk *)script_chunk,
			                                    flags, error);
			break;
		case SCTP_ABORT_CHUNK_TYPE:
			result = verify_abort_chunk((struct sctp_abort_chunk *)actual_chunk,
			                            script_chunk_item, error);
			break;
		case SCTP_SHUTDOWN_CHUNK_TYPE:
			result = verify_shutdown_chunk((struct sctp_shutdown_chunk *)actual_chunk,
			                               (struct sctp_shutdown_chunk *)script_chunk,
			                               flags, error);
			break;
		case SCTP_SHUTDOWN_ACK_CHUNK_TYPE:
			result = verify_shutdown_ack_chunk((struct sctp_shutdown_ack_chunk *)actual_chunk,
			                                   (struct sctp_shutdown_ack_chunk *)script_chunk,
			                                   flags, error);
			break;
		case SCTP_ERROR_CHUNK_TYPE:
			result = verify_error_chunk((struct sctp_error_chunk *)actual_chunk,
			                            script_chunk_item, error);
			break;
		case SCTP_COOKIE_ECHO_CHUNK_TYPE:
			result = verify_cookie_echo_chunk((struct sctp_cookie_echo_chunk *)actual_chunk,
			                                  (struct sctp_cookie_echo_chunk *)script_chunk,
			                                  flags, error);
			break;
		case SCTP_COOKIE_ACK_CHUNK_TYPE:
			result = verify_cookie_ack_chunk((struct sctp_cookie_ack_chunk *)actual_chunk,
			                                 (struct sctp_cookie_ack_chunk *)script_chunk,
			                                 flags, error);
			break;
		case SCTP_ECNE_CHUNK_TYPE:
			result = verify_ecne_chunk((struct sctp_ecne_chunk *)actual_chunk,
			                           (struct sctp_ecne_chunk *)script_chunk,
			                           flags, error);
			break;
		case SCTP_CWR_CHUNK_TYPE:
			result = verify_cwr_chunk((struct sctp_cwr_chunk *)actual_chunk,
			                          (struct sctp_cwr_chunk *)script_chunk,
			                          flags, error);
			break;
		case SCTP_SHUTDOWN_COMPLETE_CHUNK_TYPE:
			result = verify_shutdown_complete_chunk((struct sctp_shutdown_complete_chunk *)actual_chunk,
			                                        (struct sctp_shutdown_complete_chunk *)script_chunk,
			                                        flags, error);
			break;
		case SCTP_I_DATA_CHUNK_TYPE:
			result = verify_i_data_chunk((struct sctp_i_data_chunk *)actual_chunk,
			                             (struct sctp_i_data_chunk *)script_chunk,
			                             flags, error);
			break;
		case SCTP_PAD_CHUNK_TYPE:
			result = verify_pad_chunk((struct sctp_pad_chunk *)actual_chunk,
			                          (struct sctp_pad_chunk *)script_chunk,
			                          flags, error);
			break;
		default:
			result = STATUS_ERR;
			assert(!"unsupported SCTP chunk type");
			break;
		}
		if (result == STATUS_ERR) {
			return STATUS_ERR;
		}
	}
	if (actual_chunk != NULL) {
		DEBUGP("actual packet contains more chunks than script packet\n");
	}
	if (script_chunk_item != NULL) {
		DEBUGP("script packet contains more chunks than actual packet\n");
	}
	if ((actual_chunk != NULL) || (script_chunk_item != NULL)) {
		asprintf(error,
		         "live packet and expected packet have not the same number of chunks");
		return STATUS_ERR;
	}
	return STATUS_OK;
}

/* Verify that required actual TCP header fields are as the script expected. */
static int verify_tcp(
	const struct packet *actual_packet,
	const struct packet *script_packet,
	int layer, char **error)
{
	const struct tcp *actual_tcp = actual_packet->headers[layer].h.tcp;
	const struct tcp *script_tcp = script_packet->headers[layer].h.tcp;

	if (check_field("tcp_data_offset",
			(script_tcp->doff +
			 tcp_options_allowance(actual_packet,
					       script_packet)/sizeof(u32)),
			actual_tcp->doff, error) ||
	    check_field("tcp_fin",
			script_tcp->fin,
			actual_tcp->fin, error) ||
	    check_field("tcp_syn",
			script_tcp->syn,
			actual_tcp->syn, error) ||
	    check_field("tcp_rst",
			script_tcp->rst,
			actual_tcp->rst, error) ||
	    check_field("tcp_psh",
			script_tcp->psh,
			actual_tcp->psh, error) ||
	    check_field("tcp_ack",
			script_tcp->ack,
			actual_tcp->ack, error) ||
	    check_field("tcp_urg",
			script_tcp->urg,
			actual_tcp->urg, error) ||
	    check_field("tcp_ece",
			script_tcp->ece,
			actual_tcp->ece, error) ||
	    check_field("tcp_cwr",
			script_tcp->cwr,
			actual_tcp->cwr, error) ||
	    check_field("tcp_reserved_bits",
			script_tcp->res1,
			actual_tcp->res1, error) ||
	    check_field("tcp_seq",
			ntohl(script_tcp->seq),
			ntohl(actual_tcp->seq), error) ||
	    check_field("tcp_ack_seq",
			ntohl(script_tcp->ack_seq),
			ntohl(actual_tcp->ack_seq), error) ||
	    (script_packet->flags & FLAG_WIN_NOCHECK ? STATUS_OK :
		check_field("tcp_window",
			    ntohs(script_tcp->window),
			    ntohs(actual_tcp->window), error))  ||
	    check_field("tcp_urg_ptr",
			ntohs(script_tcp->urg_ptr),
			ntohs(actual_tcp->urg_ptr), error))
		return STATUS_ERR;

	return STATUS_OK;
}

/* Verify that required actual UDP header fields are as the script expected. */
static int verify_udp(
	const struct packet *actual_packet,
	const struct packet *script_packet,
	int layer, char **error)
{
	const struct udp *actual_udp = actual_packet->headers[layer].h.udp;
	const struct udp *script_udp = script_packet->headers[layer].h.udp;

	if (check_field("udp_len",
			ntohs(script_udp->len),
			ntohs(actual_udp->len), error))
		return STATUS_ERR;
	return STATUS_OK;
}

/* Verify that required actual UDPLite header fields are as the script
   expected. */
static int verify_udplite(
	const struct packet *actual_packet,
	const struct packet *script_packet,
	int layer, char **error)
{
	const struct udplite *actual_udplite =
	    actual_packet->headers[layer].h.udplite;
	const struct udplite *script_udplite =
	    script_packet->headers[layer].h.udplite;
	if (check_field("udplite_cov",
			ntohs(script_udplite->cov),
			ntohs(actual_udplite->cov), error))
		return STATUS_ERR;
	return STATUS_OK;
}

/* Verify that required actual GRE header fields are as the script expected. */
static int verify_gre(
	const struct packet *actual_packet,
	const struct packet *script_packet,
	int layer, char **error)
{
	const struct gre *actual_gre = actual_packet->headers[layer].h.gre;
	const struct gre *script_gre = script_packet->headers[layer].h.gre;

	/* TODO(ncardwell) check all fields of GRE header */
	if (check_field("gre_len",
			gre_len(script_gre),
			gre_len(actual_gre), error))
		return STATUS_ERR;
	return STATUS_OK;
}

/* Verify that required actual MPLS header fields are as the script expected. */
static int verify_mpls(
	const struct packet *actual_packet,
	const struct packet *script_packet,
	int layer, char **error)
{
	const struct header *actual_header = &actual_packet->headers[layer];
	const struct header *script_header = &script_packet->headers[layer];
	const struct mpls *actual_mpls = actual_packet->headers[layer].h.mpls;
	const struct mpls *script_mpls = script_packet->headers[layer].h.mpls;
	int num_entries = script_header->header_bytes / sizeof(struct mpls);
	int i = 0;

	if (script_header->header_bytes != actual_header->header_bytes) {
		asprintf(error, "mismatch in MPLS label stack depth");
		return STATUS_ERR;
	}

	for (i = 0; i < num_entries; ++i) {
		const struct mpls *actual_entry = actual_mpls + i;
		const struct mpls *script_entry = script_mpls + i;
		if (memcmp(actual_entry, script_entry, sizeof(*script_entry))) {
			asprintf(error, "mismatch in MPLS label %d", i);
			return STATUS_ERR;
		}
	}

	return STATUS_OK;
}

typedef int (*verifier_func)(
	const struct packet *actual_packet,
	const struct packet *script_packet,
	int layer, char **error);

/* Verify that required actual header fields are as the script expected. */
static int verify_header(
	const struct packet *actual_packet,
	const struct packet *script_packet,
	int layer, char **error)
{
	verifier_func verifiers[HEADER_NUM_TYPES] = {
		[HEADER_IPV4]		= verify_ipv4,
		[HEADER_IPV6]		= verify_ipv6,
		[HEADER_GRE]		= verify_gre,
		[HEADER_MPLS]		= verify_mpls,
		[HEADER_SCTP]		= verify_sctp,
		[HEADER_TCP]		= verify_tcp,
		[HEADER_UDP]		= verify_udp,
		[HEADER_UDPLITE]	= verify_udplite,
	};
	verifier_func verifier = NULL;
	const struct header *actual_header = &actual_packet->headers[layer];
	const struct header *script_header = &script_packet->headers[layer];
	enum header_t type = script_header->type;

	if (script_header->type != actual_header->type) {
		asprintf(error, "live packet header layer %d: "
			 "expected: %s header vs actual: %s header",
			 layer,
			 header_type_info(script_header->type)->name,
			 header_type_info(actual_header->type)->name);
		return STATUS_ERR;
	}

	assert(type > HEADER_NONE);
	assert(type < HEADER_NUM_TYPES);
	verifier = verifiers[type];
	assert(verifier != NULL);
	return verifier(actual_packet, script_packet, layer, error);
}

/* Verify that required actual header fields are as the script expected. */
static int verify_outbound_live_headers(
	const struct packet *actual_packet,
	const struct packet *script_packet, char **error)
{
	const int actual_headers = packet_header_count(actual_packet);
	const int script_headers = packet_header_count(script_packet);
	int i;

	DEBUGP("verify_outbound_live_headers\n");

	assert((actual_packet->ipv4 != NULL) || (actual_packet->ipv6 != NULL));
	assert((actual_packet->sctp != NULL) ||
	       (actual_packet->tcp != NULL) ||
	       (actual_packet->udp != NULL) ||
	       (actual_packet->udplite != NULL));

	if (actual_headers != script_headers) {
		asprintf(error, "live packet header layers: "
			 "expected: %d headers vs actual: %d headers",
			 script_headers, actual_headers);
		return STATUS_ERR;
	}

	/* Compare actual vs script headers, layer by layer. */
	for (i = 0; i < ARRAY_SIZE(script_packet->headers); ++i) {
		if (script_packet->headers[i].type == HEADER_NONE)
			break;

		if (verify_header(actual_packet, script_packet, i, error))
			return STATUS_ERR;
	}

	return STATUS_OK;
}

/* Return true iff the TCP options for the packets are bytewise identical. */
static bool same_tcp_options(struct packet *packet_a,
			     struct packet *packet_b)
{
	return ((packet_tcp_options_len(packet_a) ==
		 packet_tcp_options_len(packet_b)) &&
		(memcmp(packet_tcp_options(packet_a),
			packet_tcp_options(packet_b),
			packet_tcp_options_len(packet_a)) == 0));
}

/* Verify that the TCP option values matched expected values. */
static int verify_outbound_live_tcp_options(
	struct config *config,
	struct packet *actual_packet,
	struct packet *script_packet, char **error)
{
	/* See if we should validate TCP options at all. */
	if (script_packet->flags & FLAG_OPTIONS_NOCHECK)
		return STATUS_OK;

	/* Simplest case: see if full options are bytewise identical. */
	if (same_tcp_options(actual_packet, script_packet))
		return STATUS_OK;

	/* Otherwise, see if we just have a slight difference in TS val. */
	if (script_packet->tcp_ts_val != NULL &&
	    actual_packet->tcp_ts_val != NULL) {
		u32 script_ts_val = packet_tcp_ts_val(script_packet);
		u32 actual_ts_val = packet_tcp_ts_val(actual_packet);

		/* See if the deviation from the script TS val is
		 * within our configured tolerance.
		 */
		if (config->tcp_ts_tick_usecs &&
		    ((abs((s32)(actual_ts_val - script_ts_val)) *
		      config->tcp_ts_tick_usecs) >
		     config->tolerance_usecs)) {
			asprintf(error, "bad outbound TCP timestamp value");
			return STATUS_ERR;
		}

		/* Now see if the rest of the TCP options outside the
		 * TS val match: temporarily re-write the actual TS
		 * val to the script TS val and then see if the full
		 * options are now bytewise identical.
		 */
		packet_set_tcp_ts_val(actual_packet, script_ts_val);
		bool is_same = same_tcp_options(actual_packet, script_packet);
		packet_set_tcp_ts_val(actual_packet, actual_ts_val);
		if (is_same)
			return STATUS_OK;
	}

	asprintf(error, "bad outbound TCP options");
	return STATUS_ERR;	/* The TCP options did not match */
}


/* Verify TCP/UDP payload matches expected value. */
static int verify_outbound_live_payload(
	struct packet *actual_packet,
	struct packet *script_packet, char **error)
{
	if (actual_packet->sctp != NULL)
		return STATUS_OK;
	/* Diff the TCP/UDP data payloads. We've already implicitly
	 * checked their length by checking the IP and TCP/UDP headers.
	 */
	assert(packet_payload_len(actual_packet) ==
	       packet_payload_len(script_packet));
	if (memcmp(packet_payload(script_packet),
		   packet_payload(actual_packet),
		   packet_payload_len(script_packet)) != 0) {
		asprintf(error, "incorrect outbound data payload");
		return STATUS_ERR;
	}
	return STATUS_OK;
}

/* Verify that the outbound packet correctly matches the expected
 * outbound packet from the script.
 * Return STATUS_OK upon success.  If non_fatal_packet is unset in the
 * config, return STATUS_ERR upon all failures.  With non_fatal_packet,
 * return STATUS_WARN upon non-fatal failures.
 */
static int verify_outbound_live_packet(
	struct state *state, struct socket *socket,
	struct packet *script_packet, struct packet *live_packet,
	char **error)
{
	DEBUGP("verify_outbound_live_packet\n");

	int result = STATUS_ERR;	/* return value */
	bool non_fatal = false;		/* ok to continue on error? */
	enum event_time_t time_type = state->event->time_type;
	s64 script_usecs = state->event->time_usecs;
	s64 script_usecs_end = state->event->time_usecs_end;

	/* The "actual" packet will be the live packet with values
	 * mapped into script space.
	 */
	struct packet *actual_packet = packet_copy(live_packet);
	s64 actual_usecs = live_time_to_script_time_usecs(
		state, live_packet->time_usecs);

	/* Before mapping, see if the live outgoing checksums are correct. */
	if (verify_outbound_live_checksums(live_packet, error))
		goto out;

	/* Map live packet values into script space for easy comparison. */
	if (map_outbound_live_packet(
		    socket, live_packet, actual_packet, script_packet, error))
		goto out;

	/* Verify actual IP, TCP/UDP header values matched expected ones. */
	if (verify_outbound_live_headers(actual_packet, script_packet, error)) {
		non_fatal = true;
		goto out;
	}

	if (script_packet->tcp) {
		/* Verify TCP options matched expected values. */
		if (verify_outbound_live_tcp_options(
			    state->config, actual_packet, script_packet,
			    error)) {
			non_fatal = true;
			goto out;
		}
	}

	/* Verify TCP/UDP payload matches expected value. */
	if (verify_outbound_live_payload(actual_packet, script_packet, error)) {
		non_fatal = true;
		goto out;
	}

	/* Verify that kernel sent packet at the time the script expected. */
	DEBUGP("packet time_usecs: %lld\n", live_packet->time_usecs);
	if (verify_time(state, time_type, script_usecs,
				script_usecs_end, live_packet->time_usecs,
				"outbound packet", error)) {
		non_fatal = true;
		goto out;
	}

	result = STATUS_OK;

out:
	add_packet_dump(error, "script", script_packet, script_usecs,
			DUMP_SHORT);
	if (actual_packet != NULL) {
		add_packet_dump(error, "actual", actual_packet, actual_usecs,
				DUMP_SHORT);
		packet_free(actual_packet);
	}
	if (result == STATUS_ERR &&
	    non_fatal &&
	    state->config->non_fatal_packet) {
		result = STATUS_WARN;
	}
	return result;
}

/* Sniff the next outbound live packet and return it. */
static int sniff_outbound_live_packet(
	struct state *state, struct socket *expected_socket,
	struct packet **packet, char **error)
{
	DEBUGP("sniff_outbound_live_packet\n");
	struct socket *socket = NULL;
	enum direction_t direction = DIRECTION_INVALID;
	assert(*packet == NULL);
	while (1) {
		if (netdev_receive(state->netdev, packet, error))
			return STATUS_ERR;
		/* See if the packet matches an existing, known socket. */
		socket = find_socket_for_live_packet(state, *packet,
						     &direction);
		if ((socket != NULL) && (direction == DIRECTION_OUTBOUND))
			break;
		/* See if the packet matches a recent connect() call. */
		socket = find_connect_for_live_packet(state, *packet,
						      &direction);
		if ((socket != NULL) && (direction == DIRECTION_OUTBOUND))
			break;
		packet_free(*packet);
		*packet = NULL;
	}

	assert(*packet != NULL);
	assert(socket != NULL);
	assert(direction == DIRECTION_OUTBOUND);

	if (socket != expected_socket) {
		asprintf(error, "packet is not for expected socket");
		return STATUS_ERR;
	}
	return STATUS_OK;
}

/* Return true iff the given packet could be sent/received by the socket. */
static bool is_script_packet_match_for_socket(
	struct state *state, struct packet *packet, struct socket *socket)
{
	const bool is_packet_icmp = (packet->icmpv4 || packet->icmpv6);

	if (socket->protocol == IPPROTO_SCTP)
		return packet->sctp || is_packet_icmp;
	else if (socket->protocol == IPPROTO_TCP)
		return packet->tcp || is_packet_icmp;
	else if (socket->protocol == IPPROTO_UDP)
		return packet->udp || is_packet_icmp;
	else if (socket->protocol == IPPROTO_UDPLITE)
		return packet->udplite || is_packet_icmp;
	else
		assert(!"unsupported layer 4 protocol in socket");
	return false;
}

/* Find or create a socket object matching the given packet. */
static int find_or_create_socket_for_script_packet(
	struct state *state, struct packet *packet,
	enum direction_t direction, struct socket **socket,
	char **error)
{
	*socket = NULL;

	DEBUGP("find_or_create_socket_for_script_packet\n");

	if ((packet->tcp != NULL) || (packet->sctp != NULL)) {
		/* Is this an inbound packet matching a listening
		 * socket? If so, this call will create a new child
		 * socket object.
		 */
		*socket = handle_listen_for_script_packet(state,
							  packet, direction);
		if (*socket != NULL)
			return STATUS_OK;

		/* Is this an outbound packet matching a connecting socket? */
		*socket = handle_connect_for_script_packet(state,
							   packet, direction);
		if (*socket != NULL)
			return STATUS_OK;
	}
	/* See if there is an existing connection to handle this packet. */
	if (state->socket_under_test != NULL &&
	    is_script_packet_match_for_socket(state, packet,
					      state->socket_under_test)) {
		*socket = state->socket_under_test;
		return STATUS_OK;
	}

	asprintf(error, "no matching socket for script packet");
	return STATUS_ERR;
}

/* Perform the action implied by an outbound packet in a script
 * Return STATUS_OK upon success.  Without --use_expect, return STATUS_ERR
 * upon all failures.  With --use_expect, return STATUS_WARN upon non-fatal
 * failures.
 */
static int do_outbound_script_packet(
	struct state *state, struct packet *packet,
	struct socket *socket,	char **error)
{
	struct sctp_chunk_list_item *item;
	struct sctp_chunks_iterator chunk_iter;
	struct sctp_parameters_iterator param_iter;
	struct sctp_chunk *chunk;
	struct sctp_init_ack_chunk *init_ack;
	struct sctp_cookie_echo_chunk *cookie_echo;
	struct sctp_heartbeat_chunk *heartbeat;
	struct sctp_heartbeat_ack_chunk *heartbeat_ack;
	struct sctp_parameter *parameter;
	struct sctp_state_cookie_parameter *state_cookie;
	int result = STATUS_ERR;		/* return value */
	struct packet *live_packet = NULL;
	u16 cookie_length, chunk_length, parameter_length, parameters_length;
	u16 value_length, padding_length;

	DEBUGP("do_outbound_script_packet\n");
	if ((packet->icmpv4 != NULL) || (packet->icmpv6 != NULL)) {
		asprintf(error, "outbound ICMP packets are not supported");
		goto out;
	}

	if (socket->state == SOCKET_PASSIVE_PACKET_RECEIVED) {
		if (packet->tcp && packet->tcp->syn && packet->tcp->ack) {
			/* Script says we should see an outbound server SYNACK. */
			socket->script.local_isn = ntohl(packet->tcp->seq);
			DEBUGP("SYNACK script.local_isn: %u\n",
			       socket->script.local_isn);
		}
		if (packet->sctp) {
			assert(packet->chunk_list != NULL);
			item = packet->chunk_list->first;
			if ((item != NULL) &&
			    (item->chunk->type == SCTP_INIT_ACK_CHUNK_TYPE)) {
				init_ack = (struct sctp_init_ack_chunk *)item->chunk;
				socket->script.local_initiate_tag = ntohl(init_ack->initiate_tag);
				socket->script.local_initial_tsn = ntohl(init_ack->initial_tsn);
				DEBUGP("INIT_ACK: script.local_initiate_tag: %u\n",
				       socket->script.local_initiate_tag);
				DEBUGP("INIT_ACK: script.local_initial_tsn: %u\n",
				       socket->script.local_initial_tsn);
			}
		}
	}

	/* Sniff outbound live packet and verify it's for the right socket. */
	if (sniff_outbound_live_packet(state, socket, &live_packet, error))
		goto out;

	if (packet->tcp) {
		if ((socket->state == SOCKET_PASSIVE_PACKET_RECEIVED) &&
		    packet->tcp->syn && packet->tcp->ack) {
			socket->state = SOCKET_PASSIVE_SYNACK_SENT;
			socket->live.local_isn = ntohl(live_packet->tcp->seq);
			DEBUGP("SYNACK live.local_isn: %u\n",
			       socket->live.local_isn);
		}
	}
	if (live_packet->sctp) {
		for (chunk = sctp_chunks_begin(live_packet, &chunk_iter, error);
		     chunk != NULL;
		     chunk = sctp_chunks_next(&chunk_iter, error)) {
			if (*error != NULL)
				goto out;
			if ((socket->state == SOCKET_PASSIVE_PACKET_RECEIVED) &&
			    (chunk->type == SCTP_INIT_ACK_CHUNK_TYPE)) {
				chunk_length = ntohs(chunk->length);
				if (chunk_length < sizeof(struct sctp_init_ack_chunk)) {
					asprintf(error, "INIT chunk too short (length=%u)", chunk_length);
					goto out;
				}
				parameters_length = chunk_length - sizeof(struct sctp_init_chunk);
				init_ack = (struct sctp_init_ack_chunk *)chunk;

				for (parameter = sctp_parameters_begin(init_ack->parameter,
				                                       parameters_length,
				                                       &param_iter, error);
				     parameter != NULL;
				     parameter = sctp_parameters_next(&param_iter, error)) {
					if (*error != NULL)
						goto out;
					if (ntohs(parameter->type) == SCTP_STATE_COOKIE_PARAMETER_TYPE) {
						state_cookie = (struct sctp_state_cookie_parameter *)parameter;
						parameter_length = ntohs(state_cookie->length);
						if (parameter_length < sizeof(struct sctp_state_cookie_parameter)) {
							asprintf(error, "State Cookie parameter too short (length=%u)", parameter_length);
							goto out;
						}
						cookie_length = parameter_length - 4;
						padding_length = cookie_length % 4;
						if (padding_length > 0) {
							padding_length = 4 - padding_length;
						}
						chunk_length = sizeof(struct sctp_cookie_echo_chunk) + cookie_length;
						cookie_echo = (struct sctp_cookie_echo_chunk *)malloc(chunk_length + padding_length);
						cookie_echo->type = SCTP_COOKIE_ECHO_CHUNK_TYPE;
						cookie_echo->flags = 0;
						cookie_echo->length = htons(chunk_length);
						memcpy(cookie_echo->cookie, state_cookie->cookie, cookie_length);
						memset(cookie_echo->cookie + cookie_length, 0, padding_length);
						if (socket->prepared_cookie_echo != NULL) {
							 /* paranoia to help catch bugs */
							memset(socket->prepared_cookie_echo,
							       0,
							       socket->prepared_cookie_echo_length);
							free(socket->prepared_cookie_echo);
							socket->prepared_cookie_echo = NULL;
							socket->prepared_cookie_echo_length = 0;
						}
						socket->prepared_cookie_echo = cookie_echo;
						socket->prepared_cookie_echo_length = chunk_length + padding_length;
						DEBUGP("COOKIE_ECHO of length %u prepeared\n",
						       chunk_length);
						break;
					}
				}
				socket->live.local_initiate_tag = ntohl(init_ack->initiate_tag);
				socket->live.local_initial_tsn = ntohl(init_ack->initial_tsn);
				socket->state = SOCKET_PASSIVE_INIT_ACK_SENT;
				DEBUGP("INIT_ACK: live.local_initiate_tag: %u\n",
				       socket->live.local_initiate_tag);
				DEBUGP("INIT_ACK: live.local_initial_tsn: %u\n",
				       socket->live.local_initial_tsn);
			}
			if (chunk->type == SCTP_HEARTBEAT_CHUNK_TYPE) {
				heartbeat = (struct sctp_heartbeat_chunk *)chunk;
				chunk_length = ntohs(heartbeat->length);
				if (chunk_length < sizeof(struct sctp_heartbeat_chunk)) {
					asprintf(error, "HEARTBEAT chunk too short (length=%u)", chunk_length);
					goto out;
				}
				value_length = chunk_length - sizeof(struct sctp_heartbeat_chunk);
				padding_length = chunk_length % 4;
				if (padding_length > 0) {
					padding_length = 4 - padding_length;
				}
				heartbeat_ack = (struct sctp_heartbeat_ack_chunk *)malloc(chunk_length + padding_length);
				heartbeat_ack->type = SCTP_HEARTBEAT_ACK_CHUNK_TYPE;
				heartbeat_ack->flags = 0;
				heartbeat_ack->length = htons(chunk_length);
				memcpy(heartbeat_ack->value, heartbeat->value, value_length);
				memset(heartbeat_ack->value + value_length, 0, padding_length);
				if (socket->prepared_heartbeat_ack != NULL) {
					 /* paranoia to help catch bugs */
					memset(socket->prepared_heartbeat_ack,
					       0,
					       socket->prepared_heartbeat_ack_length);
					free(socket->prepared_heartbeat_ack);
					socket->prepared_heartbeat_ack = NULL;
					socket->prepared_heartbeat_ack_length = 0;
				}
				socket->prepared_heartbeat_ack = heartbeat_ack;
				socket->prepared_heartbeat_ack_length = chunk_length + padding_length;
				DEBUGP("HEARTBEAT-ACK of length %u prepeared\n",
				       chunk_length);
			}
		}
	}

	verbose_packet_dump(state, "outbound sniffed", live_packet,
			    live_time_to_script_time_usecs(
				    state, live_packet->time_usecs));

	/* Save the TCP header so we can reset the connection at the end. */
	if (live_packet->tcp)
		socket->last_outbound_tcp_header = *(live_packet->tcp);

	/* Verify the bits the kernel sent were what the script expected. */
	result = verify_outbound_live_packet(
			state, socket, packet, live_packet, error);

out:
	if (live_packet != NULL)
		packet_free(live_packet);
	return result;
}

/* Checksum the packet and inject it into the kernel under test. */
static int send_live_ip_packet(struct netdev *netdev,
			       struct packet *packet)
{
	assert(packet->ip_bytes > 0);
	/* We do IPv4 and IPv6 */
	assert(packet->ipv4 || packet->ipv6);
	/* We only do TCP, UDP, UDPLite and ICMP */
	assert(packet->sctp || packet->tcp || packet->udp || packet->udplite ||
	       packet->icmpv4 || packet->icmpv6);

	/* Fill in layer 3 and layer 4 checksums */
	checksum_packet(packet);

	return netdev_send(netdev, packet);
}

/* Perform the action implied by an inbound packet in a script */
static int do_inbound_script_packet(
	struct state *state, struct packet *packet,
	struct socket *socket,	char **error)
{
	struct sctp_init_ack_chunk *init_ack;
	struct sctp_chunk_list_item *item;
	int result = STATUS_ERR;	/* return value */
	u16 offset = 0, temp_offset;
	u16 i;

	DEBUGP("do_inbound_script_packet\n");
	if (packet->tcp) {
		if ((socket->state == SOCKET_PASSIVE_SYNACK_SENT) &&
		    packet->tcp->ack) {
			/* Received the ACK that completes the 3-way handshake. */
			socket->state = SOCKET_PASSIVE_SYNACK_ACKED;
		} else if ((socket->state == SOCKET_ACTIVE_SYN_SENT) &&
		           packet->tcp->syn && packet->tcp->ack) {
			/* Received the server's SYNACK, which ACKs our SYN. */
			socket->state = SOCKET_ACTIVE_SYN_ACKED;
			socket->script.remote_isn = ntohl(packet->tcp->seq);
			socket->live.remote_isn = ntohl(packet->tcp->seq);
		}
	}
	if (packet->sctp) {
		for (item = packet->chunk_list->first;
		     item != NULL;
		     item = item->next) {
			switch (item->chunk->type) {
			case SCTP_INIT_ACK_CHUNK_TYPE:
				if (socket->state == SOCKET_ACTIVE_INIT_SENT) {
					init_ack = (struct sctp_init_ack_chunk *)item->chunk;
					DEBUGP("Moving socket in SOCKET_ACTIVE_INIT_ACK_RECEIVED\n");
					socket->state = SOCKET_ACTIVE_INIT_ACK_RECEIVED;
					socket->script.remote_initiate_tag = ntohl(init_ack->initiate_tag);
					socket->script.remote_initial_tsn = ntohl(init_ack->initial_tsn);
					socket->live.remote_initiate_tag = ntohl(init_ack->initiate_tag);
					socket->live.remote_initial_tsn = ntohl(init_ack->initial_tsn);
					DEBUGP("remote_initiate_tag 0x%08x, remote_initial_tsn 0x%08x\n", ntohl(init_ack->initiate_tag), ntohl(init_ack->initial_tsn));
				}
				break;
			case SCTP_COOKIE_ECHO_CHUNK_TYPE:
				if ((socket->state == SOCKET_PASSIVE_INIT_ACK_SENT) &&
				    (item->flags & FLAG_CHUNK_VALUE_NOCHECK)) {
					temp_offset = socket->prepared_cookie_echo_length - item->length;
					assert(packet->ip_bytes + temp_offset <= packet->buffer_bytes);
					memmove((u8 *)item->chunk + item->length + temp_offset,
						(u8 *)item->chunk + item->length,
						packet_end(packet) - ((u8 *)item->chunk + item->length));
					memcpy(item->chunk,
					       socket->prepared_cookie_echo,
					       socket->prepared_cookie_echo_length);
					item->length = socket->prepared_cookie_echo_length;
					packet->buffer_bytes += temp_offset;
					packet->ip_bytes += temp_offset;
					if (packet->ipv4) {
						packet->ipv4->tot_len = htons(ntohs(packet->ipv4->tot_len) + temp_offset);
					}
					if (packet->ipv6) {
						packet->ipv6->payload_len = htons(ntohs(packet->ipv6->payload_len) + temp_offset);
					}
					for (i = 0; i < PACKET_MAX_HEADERS; i++) {
						if ((packet->ipv4 != NULL && packet->headers[i].h.ipv4 == packet->ipv4) ||
						    (packet->ipv6 != NULL && packet->headers[i].h.ipv6 == packet->ipv6)) {
							break;
						}
					}
					assert(packet->headers[i + 1].type == HEADER_SCTP);
					packet->headers[i].total_bytes += temp_offset;
					packet->headers[i + 1].total_bytes += temp_offset;
					socket->state = SOCKET_PASSIVE_COOKIE_ECHO_RECEIVED;
					offset += temp_offset;
				}
				break;
			case SCTP_HEARTBEAT_ACK_CHUNK_TYPE:
				temp_offset = socket->prepared_heartbeat_ack_length - item->length;
				assert(packet->ip_bytes + temp_offset <= packet->buffer_bytes);
				memmove((u8 *)item->chunk + item->length + temp_offset,
					(u8 *)item->chunk + item->length,
					packet_end(packet) - ((u8 *)item->chunk + item->length));
				memcpy(item->chunk,
				       socket->prepared_heartbeat_ack,
				       socket->prepared_heartbeat_ack_length);
				item->length = socket->prepared_heartbeat_ack_length;
				packet->buffer_bytes += temp_offset;
				packet->ip_bytes += temp_offset;
				if (packet->ipv4) {
					packet->ipv4->tot_len = htons(ntohs(packet->ipv4->tot_len) + temp_offset);
				}
				if (packet->ipv6) {
					packet->ipv6->payload_len = htons(ntohs(packet->ipv6->payload_len) + temp_offset);
				}
				for (i = 0; i < PACKET_MAX_HEADERS; i++) {
					if ((packet->ipv4 != NULL && packet->headers[i].h.ipv4 == packet->ipv4) ||
					    (packet->ipv6 != NULL && packet->headers[i].h.ipv6 == packet->ipv6)) {
						break;
					}
				}
				assert(packet->headers[i + 1].type == HEADER_SCTP);
				packet->headers[i].total_bytes += temp_offset;
				packet->headers[i + 1].total_bytes += temp_offset;
				offset += temp_offset;
				break;
			default:
				item->chunk = (struct sctp_chunk *)((char *)item->chunk + offset);
				break;
			}
		}
	}

	/* Start with a bit-for-bit copy of the packet from the script. */
	struct packet *live_packet = packet_copy(packet);
	/* Map packet fields from script values to live values. */
	if (map_inbound_packet(socket, live_packet, error))
		goto out;

	verbose_packet_dump(state, "inbound injected", live_packet,
			    live_time_to_script_time_usecs(
				    state, now_usecs()));

	if (live_packet->tcp) {
		/* Save the TCP header so we can reset the connection later. */
		socket->last_injected_tcp_header = *(live_packet->tcp);
		socket->last_injected_tcp_payload_len =
			packet_payload_len(live_packet);
	}

	/* Inject live packet into kernel. */
	result = send_live_ip_packet(state->netdev, live_packet);

out:
	packet_free(live_packet);
	return result;
}

int run_packet_event(
	struct state *state, struct event *event, struct packet *packet,
	char **error)
{
	DEBUGP("%d: packet\n", event->line_number);

	char *err = NULL;
	struct socket *socket = NULL;
	int result = STATUS_ERR;

	enum direction_t direction = packet_direction(packet);
	assert(direction != DIRECTION_INVALID);

	if (find_or_create_socket_for_script_packet(
		    state, packet, direction, &socket, &err))
		goto out;

	assert(socket != NULL);

	if (direction == DIRECTION_OUTBOUND) {
		/* We don't wait for outbound event packets because we
		 * want to start sniffing ASAP in order to see if
		 * packets go out earlier than the script specifies.
		 */
		result = do_outbound_script_packet(state, packet, socket, &err);
		if (result == STATUS_WARN)
			goto out;
		else if (result == STATUS_ERR)
			goto out;
	} else if (direction == DIRECTION_INBOUND) {
		wait_for_event(state);
		if (do_inbound_script_packet(state, packet, socket, &err))
			goto out;
	} else {
		assert(!"bad direction");  /* internal bug */
	}

	return STATUS_OK;	 /* everything went fine */

out:
	/* Format a more complete error message and return that. */
	asprintf(error, "%s:%d: %s handling packet: %s\n",
		 state->config->script_path, event->line_number,
		 result == STATUS_ERR ? "error" : "warning", err);
	free(err);
	return result;
}

/* Inject a TCP RST packet to clear the connection state out of the
 * kernel, so the connection does not continue to retransmit packets
 * that may be sniffed during later test executions and cause false
 * negatives.
 */
int reset_connection(struct state *state, struct socket *socket)
{
	char *error = NULL;
	u32 seq = 0, ack_seq = 0;
	u16 window = 0;
	struct packet *packet = NULL;
	struct tuple live_inbound;
	int result = STATUS_OK;

	/* Pick TCP header fields to be something the kernel will accept. */
	if (socket->last_injected_tcp_header.ack) {
		/* If we've already injected something, then use a sequence
		 * number right after the last one we injected, and ACK
		 * the last thing we ACKed, and offer the same receive
		 * window we last offered.
		 */
		seq	= (ntohl(socket->last_injected_tcp_header.seq) +
			   (socket->last_injected_tcp_header.syn ? 1 : 0) +
			   (socket->last_injected_tcp_header.fin ? 1 : 0) +
			   socket->last_injected_tcp_payload_len);
		ack_seq	= ntohl(socket->last_injected_tcp_header.ack_seq);
		window	= ntohs(socket->last_injected_tcp_header.window);
	} else if (socket->last_outbound_tcp_header.ack) {
		/* If the kernel ACKed something, then just make sure
		 * we use the sequence number it ACKed, which will be
		 * something it expects.
		 */
		seq = ntohl(socket->last_outbound_tcp_header.ack_seq);
		ack_seq = ntohl(socket->last_outbound_tcp_header.seq);
	} else {
		/* If the kernel didn't ACK anything, then it probably
		 * sent only an initial SYN. So we get to send any
		 * sequence number we want, but should send an ACK
		 * suggesting we've seen the kernel's SYN.
		 */
		seq = 0;
		ack_seq = ntohl(socket->last_outbound_tcp_header.seq) + 1;
	}

	packet = new_tcp_packet(socket->address_family,
				DIRECTION_INBOUND, ECN_NONE,
				"R.", seq, 0, ack_seq, window, NULL, &error);
	if (packet == NULL)
		die("%s", error);

	/* Rewrite addresses and port to match inbound live traffic. */
	socket_get_inbound(&socket->live, &live_inbound);
	set_packet_tuple(packet, &live_inbound);

	/* Inject live packet into kernel. */
	result = send_live_ip_packet(state->netdev, packet);

	packet_free(packet);

	return result;
}

/* Inject an SCTP packet containing an ABORT chunk to clear the
 * association state out of the kernel, so the association does not
 * continue to retransmit packets that may be sniffed during later test
 * executions and cause false negatives.
 */
int abort_association(struct state *state, struct socket *socket)
{
	char *error = NULL;
	struct packet *packet;
	struct sctp_chunk_list *chunk_list;
	struct sctp_cause_list *cause_list;
	struct tuple live_inbound;
	int result = STATUS_OK;
	s64 flgs;

	if ((socket->live.local_initiate_tag == 0) &&
	    (socket->live.remote_initiate_tag == 0)) {
		return STATUS_OK;
	}
	if (socket->live.local_initiate_tag != 0) {
		flgs = 0;
	} else {
		flgs = SCTP_ABORT_CHUNK_T_BIT;
	}
	cause_list = sctp_cause_list_new();
	sctp_cause_list_append(cause_list,
	                       sctp_user_initiated_abort_cause_new("packetdrill cleaning up"));
	chunk_list = sctp_chunk_list_new();
	sctp_chunk_list_append(chunk_list, sctp_abort_chunk_new(flgs, cause_list));
	packet = new_sctp_packet(socket->address_family,
				 DIRECTION_INBOUND, ECN_NONE, -1, false,
				 chunk_list, &error);
	if (packet == NULL)
		die("%s", error);
	/* Rewrite addresses and port to match inbound live traffic. */
	socket_get_inbound(&socket->live, &live_inbound);
	set_packet_tuple(packet, &live_inbound);
	/* Rewrite the verification tag in the SCTP common header */
	if (socket->live.local_initiate_tag != 0) {
		packet->sctp->v_tag = htonl(socket->live.local_initiate_tag);
	} else {
		packet->sctp->v_tag = htonl(socket->live.remote_initiate_tag);
	}

	/* Inject live packet into kernel. */
	result = send_live_ip_packet(state->netdev, packet);

	packet_free(packet);

	return result;
}

struct packets *packets_new(void)
{
	struct packets *packets = calloc(1, sizeof(struct packets));

	packets->next_ephemeral_port = ephemeral_port();  /* cache a port */

	return packets;
}

void packets_free(struct packets *packets)
{
	memset(packets, 0, sizeof(*packets));  /* to help catch bugs */
	free(packets);
}
