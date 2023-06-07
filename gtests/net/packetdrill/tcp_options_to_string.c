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
 * Implementation for generating human-readable representations of TCP options.
 */

#include "tcp_options_to_string.h"

#include "tcp_options_iterator.h"

/* If the MD5 digest option is in the valid range of sizes, print the MD5
 * option and digest and return STATUS_OK. Otherwise, return STATUS_ERR.
 */
static int tcp_md5_option_to_string(FILE *s, struct tcp_option *option)
{
	int digest_bytes, i;

	assert(option->kind == TCPOPT_MD5SIG);
	if (option->length < TCPOLEN_MD5_BASE ||
	    option->length > TCPOLEN_MD5SIG)
		return STATUS_ERR;

	digest_bytes = option->length - TCPOLEN_MD5_BASE;
	assert(digest_bytes >= 0);
	assert(digest_bytes <= TCP_MD5_DIGEST_LEN);
	fputs("md5", s);
	if (digest_bytes > 0)
		fputs(" ", s);
	for (i = 0; i < digest_bytes; ++i)
		fprintf(s, "%02x", option->md5.digest[i]);
	return STATUS_OK;
}

static int tcp_fast_open_option_to_string(FILE *s, struct tcp_option *option)
{
	assert(option->kind == TCPOPT_FASTOPEN);
	if (option->length < TCPOLEN_FASTOPEN_BASE) {
		return STATUS_ERR;
	}

	fputs("FO", s);
	int cookie_bytes = option->length - TCPOLEN_FASTOPEN_BASE;
	assert(cookie_bytes >= 0);
	assert(cookie_bytes <= MAX_TCP_FAST_OPEN_COOKIE_BYTES);
	if (cookie_bytes > 0) {
		fputs(" ", s);
	}
	int i;
	for (i = 0; i < cookie_bytes; ++i)
		fprintf(s, "%02x", option->fast_open.cookie[i]);
	return STATUS_OK;
}

/* See if the given experimental option is a TFO option, and if so
 * then print the TFO option and return STATUS_OK. Otherwise, return
 * STATUS_ERR.
 */
static void tcp_exp_fast_open_option_to_string(FILE *s, struct tcp_option *option)
{
	int cookie_bytes, i;

	assert(option->kind == TCPOPT_EXP);
	assert(option->length >= TCPOLEN_EXP_FASTOPEN_BASE);
	assert(option->exp.exid == htons(TCPOPT_FASTOPEN_EXID));

	fputs("EXP-FO", s);
	cookie_bytes = option->length - TCPOLEN_EXP_FASTOPEN_BASE;
	assert(cookie_bytes <= MAX_TCP_EXP_FAST_OPEN_COOKIE_BYTES);
	if (cookie_bytes > 0) {
		fputs(" ", s);
	}
	for (i = 0; i < cookie_bytes; ++i)
		fprintf(s, "%02x", option->exp.fast_open.cookie[i]);
}

static int tcp_acc_ecn_option_to_string(FILE *s, struct tcp_option *option)
{
	unsigned int order;

	assert(option->kind == TCPOPT_ACC_ECN_0 ||
	       option->kind == TCPOPT_ACC_ECN_1);
	if ((option->length != ACC_ECN_ZERO_COUNTER_LEN) &&
	    (option->length != ACC_ECN_ONE_COUNTER_LEN) &&
	    (option->length != ACC_ECN_TWO_COUNTER_LEN) &&
	    (option->length != ACC_ECN_THREE_COUNTER_LEN)) {
		return STATUS_ERR;
	}
	switch (option->kind) {
	case TCPOPT_ACC_ECN_0:
		order = 0;
		break;
	case TCPOPT_ACC_ECN_1:
		order = 1;
		break;
	}
	switch (option->length) {
	case ACC_ECN_ZERO_COUNTER_LEN:
		fprintf(s, "AccECN%u", order);
		break;
	case ACC_ECN_ONE_COUNTER_LEN:
		fprintf(s, "AccECN%u ee%ub %u",
		        order, order,
		        order == 0 ? acc_ecn_get_ee0b(option) : acc_ecn_get_ee1b(option));
		break;
	case ACC_ECN_TWO_COUNTER_LEN:
		fprintf(s, "AccECN%u ee%ub %u eceb %u",
		        order, order,
		        order == 0 ? acc_ecn_get_ee0b(option) : acc_ecn_get_ee1b(option),
		        acc_ecn_get_eceb(option));
		break;
	case ACC_ECN_THREE_COUNTER_LEN:
		fprintf(s, "AccECN%u ee%ub %u eceb %u ee%ub %u",
		        order, order,
		        order == 0 ? acc_ecn_get_ee0b(option) : acc_ecn_get_ee1b(option),
		        acc_ecn_get_eceb(option),
		        1 - order,
		        order == 0 ? acc_ecn_get_ee1b(option) : acc_ecn_get_ee0b(option));
		break;
	}
	return STATUS_OK;
}

static int tcp_exp_acc_ecn_option_to_string(FILE *s, u16 exid, struct tcp_option *option)
{
	unsigned int order;

	assert(option->kind == TCPOPT_EXP);
	assert(exid == TCPOPT_ACC_ECN_0_EXID || exid == TCPOPT_ACC_ECN_1_EXID);
	if ((option->length != EXP_ACC_ECN_ZERO_COUNTER_LEN) &&
	    (option->length != EXP_ACC_ECN_ONE_COUNTER_LEN) &&
	    (option->length != EXP_ACC_ECN_TWO_COUNTER_LEN) &&
	    (option->length != EXP_ACC_ECN_THREE_COUNTER_LEN)) {
		return STATUS_ERR;
	}
	switch (exid) {
	case TCPOPT_ACC_ECN_0_EXID:
		order = 0;
		break;
	case TCPOPT_ACC_ECN_1_EXID:
		order = 1;
		break;
	}
	switch (option->length) {
	case EXP_ACC_ECN_ZERO_COUNTER_LEN:
		fprintf(s, "exp-AccECN%u", order);
		break;
	case EXP_ACC_ECN_ONE_COUNTER_LEN:
		fprintf(s, "exp-AccECN%u EE%uB %u",
		        order, order,
		        order == 0 ? exp_acc_ecn_get_ee0b(option) : exp_acc_ecn_get_ee1b(option));
		break;
	case EXP_ACC_ECN_TWO_COUNTER_LEN:
		fprintf(s, "exp-AccECN%u EE%uB %u ECEB %u",
		        order, order,
		        order == 0 ? exp_acc_ecn_get_ee0b(option) : exp_acc_ecn_get_ee1b(option),
		        exp_acc_ecn_get_eceb(option));
		break;
	case EXP_ACC_ECN_THREE_COUNTER_LEN:
		fprintf(s, "exp-AccECN%u EE%uB %u ECEB %u EE%uB %u",
		        order, order,
		        order == 0 ? exp_acc_ecn_get_ee0b(option) : exp_acc_ecn_get_ee1b(option),
		        exp_acc_ecn_get_eceb(option),
		        1 - order,
		        order == 0 ? exp_acc_ecn_get_ee1b(option) : exp_acc_ecn_get_ee0b(option));
		break;
	}
	return STATUS_OK;
}

static int tcp_exp_tarr_option_to_string(FILE *s, u16 exid, struct tcp_option *option)
{
	assert(option->kind == TCPOPT_EXP);
	assert(exid == TCPOPT_TARR_EXID);
	if ((option->length != TCPOLEN_EXP_TARR_WITHOUT_RATE_LEN) &&
	    (option->length != TCPOLEN_EXP_TARR_WITH_RATE_LEN)) {
		return STATUS_ERR;
	}
	switch (option->length) {
	case TCPOLEN_EXP_TARR_WITHOUT_RATE_LEN:
		fputs("exp-tarr", s);
		break;
	case TCPOLEN_EXP_TARR_WITH_RATE_LEN:
		fprintf(s, "exp-tarr %u", option->exp.tarr.data >> 1);
	}
	return STATUS_OK;
}

int tcp_options_to_string(struct packet *packet,
				  char **ascii_string, char **error)
{
	struct tcp_options_iterator iter;
	struct tcp_option *option;
	size_t size = 0;
	FILE *s = open_memstream(ascii_string, &size);  /* output string */
	int i, num_blocks, result;
	unsigned int index = 0;	/* number of options seen so far */
	u16 exid;
	bool written;

	for (option = tcp_options_begin(packet, &iter);
	     option != NULL; option = tcp_options_next(&iter, error)) {
		written = false;
		if (index > 0)
			fputc(',', s);

		switch (option->kind) {
		case TCPOPT_EOL:
			fputs("eol", s);
			written = true;
			break;

		case TCPOPT_NOP:
			fputs("nop", s);
			written = true;
			break;

		case TCPOPT_MAXSEG:
			if (option->length == TCPOLEN_MAXSEG) {
				fprintf(s, "mss %u",
				        get_unaligned_be16(&option->mss.bytes));
				written = true;
			}
			break;

		case TCPOPT_WINDOW:
			if (option->length == TCPOLEN_WINDOW) {
				fprintf(s, "wscale %u",
				        option->window_scale.shift_count);
				written = true;
			}
			break;

		case TCPOPT_SACK_PERMITTED:
			if (option->length == TCPOLEN_SACK_PERMITTED) {
				fputs("sackOK", s);
				written = true;
			}
			break;

		case TCPOPT_SACK:
			if (num_sack_blocks(option->length,
			                    &num_blocks, error)) {
				free(*error);
				*error = NULL;
				break;
			}
			fputs("sack ", s);
			for (i = 0; i < num_blocks; ++i) {
				if (i > 0)
					fputc(' ', s);
				fprintf(s, "%u:%u",
					get_unaligned_be32(&option->sack.block[i].left),
					get_unaligned_be32(&option->sack.block[i].right));
			}
			written = true;
			break;

		case TCPOPT_TIMESTAMP:
			if (option->length == TCPOLEN_TIMESTAMP) {
				fprintf(s, "TS val %u ecr %u",
				        get_unaligned_be32(&option->time_stamp.val),
				        get_unaligned_be32(&option->time_stamp.ecr));
				written = true;
			}
			break;

		case TCPOPT_MD5SIG:
			written = tcp_md5_option_to_string(s, option) == STATUS_OK;
			break;

		case TCPOPT_FASTOPEN:
			written = tcp_fast_open_option_to_string(s, option) == STATUS_OK;
			break;

		case TCPOPT_ACC_ECN_0:
		case TCPOPT_ACC_ECN_1:
			written = tcp_acc_ecn_option_to_string(s, option) == STATUS_OK;
			break;

		case TCPOPT_EXP:
			if (option->length >= MIN_EXP_OPTION_LEN) {
				exid = get_unaligned_be16(&option->exp.exid);
				switch (exid) {
				case TCPOPT_FASTOPEN_EXID:
					tcp_exp_fast_open_option_to_string(s, option);
					written = true;
					break;
				case TCPOPT_ACC_ECN_0_EXID:
				case TCPOPT_ACC_ECN_1_EXID:
					written = tcp_exp_acc_ecn_option_to_string(s, exid, option) == STATUS_OK;
					break;
				case TCPOPT_TARR_EXID:
					written = tcp_exp_tarr_option_to_string(s, exid, option) == STATUS_OK;
					break;
				}
				if (!written) {
					fprintf(s, "exp-%04x", exid);
					if (option->length > TCP_EXP_OPTION_HEADER_BYTES) {
						fputs(" ", s);
					}
					for (i = 0; i < option->length - TCP_EXP_OPTION_HEADER_BYTES; i++) {
						fprintf(s, "%02x", option->exp.generic.data[i]);
					}
					written = true;
				}
			}
			break;
		}

		if (!written) {
			fprintf(s, "gen-%u", option->kind);
			if (option->length > TCP_OPTION_HEADER_BYTES) {
				fputs(" ", s);
			}
			for (i = 0; i < option->length - TCP_OPTION_HEADER_BYTES; i++) {
				fprintf(s, "%02x", option->generic.data[i]);
			}
		}
		++index;
	}
	if (*error != NULL) {
		/* bogus TCP options prevented iteration */
		result = STATUS_ERR;
	} else {
		result = STATUS_OK;
	}
	fclose(s);
	return result;

}
