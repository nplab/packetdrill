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
 * Implementation for module to allow iteration over TCP options in
 * wire format.
 */

#include "tcp_options_iterator.h"

#include <stdlib.h>
#include <string.h>
#include "packet.h"
#include "tcp.h"
#include "tcp_options.h"

/* Calculate the length of the TCP option at 'option', in a block of TCP
 * options that ends at 'end'.
 * Return length of option in bytes in *length.
 * Returns STATUS_OK on success; on failure returns STATUS_ERR and sets
 * error message.
 */
static int get_tcp_option_length(const u8 *option, const u8 *end,
                                 u8 *length, char **error)
{
	int result = STATUS_ERR;

	if (*option == TCPOPT_EOL || *option == TCPOPT_NOP) {
		*length = 1;
		result = STATUS_OK;
		goto out;
	}
	if (option + 1 >= end) {
		asprintf(error, "TCP option length byte extends too far");
		goto out;
	}
	*length = *(option + 1);
	if (*length < 2) {
		asprintf(error, "TCP option with length byte is too short");
		goto out;
	}
	if (option + (*length) > end) {
		asprintf(error, "TCP option data extends too far");
		goto out;
	}
	result = STATUS_OK;
out:
	return result;
}

static struct tcp_option *get_current_option(
	struct tcp_options_iterator *iter)
{
	assert(iter->current_option <= iter->options_end);
	if (iter->current_option >= iter->options_end)
		iter->current_option = NULL;
	return (struct tcp_option *)iter->current_option;
}

struct tcp_option *tcp_options_begin(
	struct packet *packet,
	struct tcp_options_iterator *iter)
{
	memset(iter, 0, sizeof(*iter));
	iter->current_option	= packet_tcp_options(packet);
	iter->options_end	= packet_payload(packet);
	return get_current_option(iter);
}

struct tcp_option *tcp_options_next(
	struct tcp_options_iterator *iter, char **error)
{
	u8 length;

	/* Ensure we haven't hit the end. */
	assert(iter->current_option < iter->options_end);
	assert(iter->current_option != NULL);
	/* Parse and validate length byte. */
	if (get_tcp_option_length(iter->current_option,
				  iter->options_end,
				  &length, error)) {
		goto out;
	}
	/* Advance to the next TCP option. */
	assert(length > 0);
	iter->current_option += length;
	assert(iter->current_option <= iter->options_end);
	return get_current_option(iter);
out:
	return NULL;
}
