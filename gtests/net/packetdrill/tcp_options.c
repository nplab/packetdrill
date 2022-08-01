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
 * Implementation for reading and writing TCP options in their wire format.
 */

#include "tcp_options.h"

#include <stdlib.h>
#include <string.h>
#include "packet.h"

struct tcp_options *tcp_options_new(void)
{
	return calloc(1, sizeof(struct tcp_options));
}

struct tcp_option *tcp_option_new(u8 kind, u8 length)
{
	struct tcp_option *option = calloc(1, sizeof(struct tcp_option));
	option->kind = kind;
	option->length = length;
	return option;
}

struct tcp_option *tcp_exp_option_new(u8 kind, u8 length, u16 magic)
{
	struct tcp_option *option = calloc(1, sizeof(struct tcp_option));

	assert(kind == TCPOPT_EXP);
	option->kind = kind;
	option->length = length;
	option->exp.magic = htons(magic);
	return option;
}

int tcp_options_append(struct tcp_options *options,
			       struct tcp_option *option)
{
	if (options->length + option->length > sizeof(options->data))
		return STATUS_ERR;
	memcpy(options->data + options->length, option, option->length);
	options->length += option->length;
	assert(options->length <= sizeof(options->data));
	free(option);
	return STATUS_OK;
}

int num_sack_blocks(u8 opt_len, int *num_blocks, char **error)
{
	if (opt_len <= 2) {
		asprintf(error, "TCP SACK option too short");
		return STATUS_ERR;
	}
	const int num_bytes = opt_len - 2;
	if (num_bytes % sizeof(struct sack_block) != 0) {
		asprintf(error,
			 "TCP SACK option not a multiple of SACK block size");
		return STATUS_ERR;
	}
	*num_blocks = num_bytes / sizeof(struct sack_block);
	return STATUS_OK;
}

u32 acc_ecn_get_ee0b(struct tcp_option *option)
{
	u32 offset;

	assert(option->kind == TCPOPT_ACC_ECN_0 ||
	       option->kind == TCPOPT_ACC_ECN_1);
	switch (option->kind) {
	case TCPOPT_ACC_ECN_0:
		assert(option->length >= ACC_ECN_ONE_COUNTER_LEN);
		offset = ACC_ECN_FIRST_COUNTER_OFFSET;
		break;
	case TCPOPT_ACC_ECN_1:
		assert(option->length >= ACC_ECN_THREE_COUNTER_LEN);
		offset = ACC_ECN_THIRD_COUNTER_OFFSET;
		break;
	}
	return get_unaligned_be24(&option->acc_ecn.data[offset]);
}

u32 acc_ecn_get_eceb(struct tcp_option *option)
{
	u32 offset;

	assert(option->kind == TCPOPT_ACC_ECN_0 ||
	       option->kind == TCPOPT_ACC_ECN_1);
	assert(option->length >= ACC_ECN_TWO_COUNTER_LEN);
	offset = ACC_ECN_SECOND_COUNTER_OFFSET;
	return get_unaligned_be24(&option->acc_ecn.data[offset]);
}

u32 acc_ecn_get_ee1b(struct tcp_option *option)
{
	u32 offset;

	assert(option->kind == TCPOPT_ACC_ECN_0 ||
	       option->kind == TCPOPT_ACC_ECN_1);
	switch (option->kind) {
	case TCPOPT_ACC_ECN_0:
		assert(option->length >= ACC_ECN_THREE_COUNTER_LEN);
		offset = ACC_ECN_THIRD_COUNTER_OFFSET;
		break;
	case TCPOPT_ACC_ECN_1:
		assert(option->length >= ACC_ECN_ONE_COUNTER_LEN);
		offset = ACC_ECN_FIRST_COUNTER_OFFSET;
		break;
	}
	return get_unaligned_be24(&option->acc_ecn.data[offset]);
}

u32 exp_acc_ecn_get_ee0b(struct tcp_option *option)
{
	u32 offset;
	u16 magic;

	assert(option->kind == TCPOPT_EXP);
	magic = get_unaligned_be16(&option->exp.magic);
	assert(magic == TCPOPT_ACC_ECN_0_MAGIC || magic == TCPOPT_ACC_ECN_1_MAGIC);
	switch (magic) {
	case TCPOPT_ACC_ECN_0_MAGIC:
		assert(option->length >= EXP_ACC_ECN_ONE_COUNTER_LEN);
		offset = ACC_ECN_FIRST_COUNTER_OFFSET;
		break;
	case TCPOPT_ACC_ECN_1_MAGIC:
		assert(option->length >= EXP_ACC_ECN_THREE_COUNTER_LEN);
		offset = ACC_ECN_THIRD_COUNTER_OFFSET;
		break;
	}
	return get_unaligned_be24(&option->exp.acc_ecn.data[offset]);
}

u32 exp_acc_ecn_get_eceb(struct tcp_option *option)
{
	u32 offset;
#ifndef NDEBUG
	u16 magic;
#endif

	assert(option->kind == TCPOPT_EXP);
#ifndef NDEBUG
	magic = get_unaligned_be16(&option->exp.magic);
#endif
	assert(magic == TCPOPT_ACC_ECN_0_MAGIC || magic == TCPOPT_ACC_ECN_1_MAGIC);
	assert(option->length >= EXP_ACC_ECN_TWO_COUNTER_LEN);
	offset = ACC_ECN_SECOND_COUNTER_OFFSET;
	return get_unaligned_be24(&option->exp.acc_ecn.data[offset]);
}

u32 exp_acc_ecn_get_ee1b(struct tcp_option *option)
{
	u32 offset;
	u16 magic;

	assert(option->kind == TCPOPT_EXP);
	magic = get_unaligned_be16(&option->exp.magic);
	assert(magic == TCPOPT_ACC_ECN_0_MAGIC || magic == TCPOPT_ACC_ECN_1_MAGIC);
	switch (magic) {
	case TCPOPT_ACC_ECN_0_MAGIC:
		assert(option->length >= EXP_ACC_ECN_THREE_COUNTER_LEN);
		offset = ACC_ECN_THIRD_COUNTER_OFFSET;
		break;
	case TCPOPT_ACC_ECN_1_MAGIC:
		assert(option->length >= EXP_ACC_ECN_ONE_COUNTER_LEN);
		offset = ACC_ECN_FIRST_COUNTER_OFFSET;
		break;
	}
	return get_unaligned_be24(&option->exp.acc_ecn.data[offset]);
}
