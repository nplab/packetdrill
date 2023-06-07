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
 * Interfaces for reading and writing TCP options in their wire format.
 */

#ifndef __TCP_OPTIONS_H__
#define __TCP_OPTIONS_H__

#include "types.h"

#include "packet.h"

#define MAX_TCP_OPTION_BYTES (MAX_TCP_HEADER_BYTES - (int)sizeof(struct tcp))
#define TCP_OPTION_HEADER_BYTES 2
#define TCP_EXP_OPTION_HEADER_BYTES 4
#define MAX_TCP_OPTION_DATA_BYTES (MAX_TCP_OPTION_BYTES - TCP_OPTION_HEADER_BYTES)
#define MAX_TCP_EXP_OPTION_DATA_BYTES (MAX_TCP_OPTION_BYTES - TCP_EXP_OPTION_HEADER_BYTES)

/* TCP Fast Open uses the following ExID number to be after the
 * option value for sharing TCP experimental options.
 *
 * For a description of experimental options, see:
 *   https://tools.ietf.org/html/rfc6994
 *
 * For a description of TFO, see:
 *   https://tools.ietf.org/html/rfc7413
 */
#define TCPOPT_FASTOPEN_EXID	0xF989

/* TFO option must have: 1-byte kind, 1-byte length, and 2-byte ExID: */
#define TCPOLEN_EXP_FASTOPEN_BASE 4	/* smallest legal TFO option size */

/* The TFO option base prefix leaves this amount of space: */
#define MAX_TCP_EXP_FAST_OPEN_COOKIE_BYTES				\
	(MAX_TCP_OPTION_BYTES - TCPOLEN_EXP_FASTOPEN_BASE)

/* TFO option must have: 1-byte kind, 1-byte length */
#define TCPOLEN_FASTOPEN_BASE 2	/* smallest legal TFO option size */

/* The TFO option base prefix leaves this amount of space: */
#define MAX_TCP_FAST_OPEN_COOKIE_BYTES				\
	(MAX_TCP_OPTION_BYTES - TCPOLEN_FASTOPEN_BASE)

/* AccECN is based on https://www.ietf.org/archive/id/draft-ietf-tcpm-accurate-ecn-20.html */
#define ACC_ECN_MAX_DATA_LEN		9
#define ACC_ECN_ZERO_COUNTER_LEN	2
#define ACC_ECN_ONE_COUNTER_LEN		5
#define ACC_ECN_TWO_COUNTER_LEN		8
#define ACC_ECN_THREE_COUNTER_LEN	11
#define ACC_ECN_FIRST_COUNTER_OFFSET	0
#define ACC_ECN_SECOND_COUNTER_OFFSET	3
#define ACC_ECN_THIRD_COUNTER_OFFSET	6
#define EXP_ACC_ECN_ZERO_COUNTER_LEN	4
#define EXP_ACC_ECN_ONE_COUNTER_LEN	7
#define EXP_ACC_ECN_TWO_COUNTER_LEN	10
#define EXP_ACC_ECN_THREE_COUNTER_LEN	13

#define MIN_EXP_OPTION_LEN		4

#define TCPOPT_ACC_ECN_0_EXID		0xACC0
#define TCPOPT_ACC_ECN_1_EXID		0xACC1

/* TARR is based on https://datatracker.ietf.org/doc/html/draft-gomez-tcpm-ack-rate-request-05 */
#define TCPOPT_TARR_EXID			0x00AC
#define TCPOLEN_EXP_TARR_WITHOUT_RATE_LEN	4
#define TCPOLEN_EXP_TARR_WITH_RATE_LEN		5

/* Represents a list of TCP options in their wire format. */
struct tcp_options {
	u8 data[MAX_TCP_OPTION_BYTES];	/* The options data, in wire format */
	u8 length;		/* The length, in bytes, of the data */
};

/* Specification of a TCP SACK block (RFC 2018) */
struct sack_block {
	u32 left;   /* left edge: 1st sequence number in block */
	u32 right;  /* right edge: 1st sequence number just past block */
};

/* Represents a single TCP option in its wire format. Note that for
 * EOL and NOP options the length and data field are not included in
 * the on-the-wire data. For other options, the length field describes
 * the number of bytes of the struct that go on the wire. */
struct tcp_option {
	u8 kind;
	u8 length;  /* bytes on the wire; includes kind and length byte */
	union {
		struct {
			u16 bytes;	/* in network order */
		} mss;
		struct {
			u32 val;	/* in network order */
			u32 ecr;	/* in network order */
		} time_stamp;
		struct {
			u8 shift_count;
		} window_scale;
		struct {
			/* actual number of blocks will be 1..4 */
			struct sack_block block[4];
		} sack;
		struct {
			u8 digest[TCP_MD5_DIGEST_LEN];
		} md5; /* TCP MD5 Signature Option: RFC 2385 */
		struct {
			/* The fast open chookie should be 4-16 bytes
			 * of cookie, multiple of 2 bytes, but we
			 * allow for larger sizes, so we can test what
			 * stacks do with illegal options.
			 */
			u8 cookie[MAX_TCP_FAST_OPEN_COOKIE_BYTES];
		} fast_open;
		struct {
			/* There are up to three 24-bit unsigned integers.
			 * These are handled as a vector of u8. The number
			 * of the integers is derived from the option length.
			 * The option kind specifies the order of integers.
			 */
			u8 data[ACC_ECN_MAX_DATA_LEN];
		} acc_ecn;
		struct {
			u16 exid;
			union {
				struct {
					/* The fast open chookie should be
					 * 4-16 bytes of cookie, multiple of
					 * 2 bytes, but we allow for larger
					 * sizes, so we can test what stacks
					 * do with illegal options.
					 */
					u8 cookie[MAX_TCP_EXP_FAST_OPEN_COOKIE_BYTES];
				} fast_open;
				struct {
					/* See description above. */
					u8 data[ACC_ECN_MAX_DATA_LEN];
				} acc_ecn;
				struct {
					u8 data;
				} tarr;
				struct {
					u8 data[MAX_TCP_EXP_OPTION_DATA_BYTES];
				} generic;
			};
		} exp;
		struct {
			u8 data[MAX_TCP_OPTION_DATA_BYTES];
		} generic;
	};
} __packed;

/* Allocate a new options list. */
extern struct tcp_options *tcp_options_new(void);

/* Allocate a new option and initialize its kind and length fields. */
extern struct tcp_option *tcp_option_new(u8 kind, u8 length);

/* Allocate a new experimental option and initialize its kind, length,
 * and ExID fields.
 */
extern struct tcp_option *tcp_exp_option_new(u8 kind, u8 length, u16 exid);

/* Appends the given option to the given list of options. Returns
 * STATUS_OK on success; on failure returns STATUS_ERR and sets
 * error message.
 */
extern int tcp_options_append(struct tcp_options *options,
			      struct tcp_option *option);

/* Calculate the number of SACK blocks in a SACK option of the given
 * length and store it in *num_blocks. Returns STATUS_OK on success;
 * on failure returns STATUS_ERR and sets error message.
 */
extern int num_sack_blocks(u8 opt_len, int *num_blocks, char **error);

extern u32 acc_ecn_get_ee0b(struct tcp_option *option);

extern u32 acc_ecn_get_eceb(struct tcp_option *option);

extern u32 acc_ecn_get_ee1b(struct tcp_option *option);

extern u32 exp_acc_ecn_get_ee0b(struct tcp_option *option);

extern u32 exp_acc_ecn_get_eceb(struct tcp_option *option);

extern u32 exp_acc_ecn_get_ee1b(struct tcp_option *option);

#endif /* __TCP_OPTIONS_H__ */
