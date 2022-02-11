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
 * Our own IPv4 header declarations, so we have something that's
 * portable and somewhat more readable than a typical system header
 * file.
 */

#ifndef __IP_HEADERS_H__
#define __IP_HEADERS_H__

#include "types.h"

struct ipv4 {
#if defined(__BYTE_ORDER__) && (__BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__)
	__u8	ihl:4,
		version:4;
#elif defined(__BYTE_ORDER__) && (__BYTE_ORDER__ == __ORDER_BIG_ENDIAN__)
	__u8	version:4,
		ihl:4;
#else
# error "Please fix endianness defines"
#endif
	__u8	tos;
	__be16	tot_len;
	__be16	id;
	__be16	frag_off;
	__u8	ttl;
	__u8	protocol;
	__sum16	check;
	struct in_addr	src_ip;
	struct in_addr	dst_ip;
};

/* ----------------------- IP socket option values -------------------- */

/* Oddly enough, Linux distributions are typically missing even some
 * of the older and more common IP socket options, such as IP_MTU.
 */
#ifdef linux
#define IP_TOS		1
#define IP_TTL		2
#define IP_HDRINCL	3
#define IP_OPTIONS	4
#define IP_ROUTER_ALERT	5
#define IP_RECVOPTS	6
#define IP_RETOPTS	7
#define IP_PKTINFO	8
#define IP_PKTOPTIONS	9
#define IP_MTU_DISCOVER	10
#define IP_RECVERR	11
#define IP_RECVTTL	12
#define IP_RECVTOS	13
#define IP_MTU		14
#define IP_FREEBIND	15
#define IP_IPSEC_POLICY	16
#define IP_XFRM_POLICY	17
#define IP_PASSSEC	18
#define IP_TRANSPARENT	19
#endif  /* linux */

/* ECN: RFC 3168: http://tools.ietf.org/html/rfc3168 */
#define IP_ECN_MASK 3
#define IP_ECN_NONE 0
#define IP_ECN_ECT1 1
#define IP_ECN_ECT0 2
#define IP_ECN_CE   3

#define DSCP_CS0         0x00
#define DSCP_CS1         0x08
#define DSCP_CS2         0x10
#define DSCP_CS3         0x18
#define DSCP_CS4         0x20
#define DSCP_CS5         0x28
#define DSCP_CS6         0x30
#define DSCP_CS7         0x38
#define DSCP_AF11        0x0a
#define DSCP_AF12        0x0c
#define DSCP_AF13        0x0e
#define DSCP_AF21        0x12
#define DSCP_AF22        0x14
#define DSCP_AF23        0x16
#define DSCP_AF31        0x1a
#define DSCP_AF32        0x1c
#define DSCP_AF33        0x1e
#define DSCP_AF41        0x22
#define DSCP_AF42        0x24
#define DSCP_AF43        0x26
#define DSCP_EF          0x2e
#define DSCP_VOICE_ADMIT 0x2c
#define DSCP_LE          0x01

static inline u8 ipv4_ecn_bits(const struct ipv4 *ipv4)
{
	return ipv4->tos & IP_ECN_MASK;
}

static inline u8 ipv4_tos_byte(const struct ipv4 *ipv4)
{
	return ipv4->tos;
}

static inline u8 ipv4_ttl_byte(const struct ipv4 *ipv4)
{
	return ipv4->ttl;
}

static inline int ipv4_header_len(const struct ipv4 *ipv4)
{
	return ipv4->ihl * sizeof(u32);
}

/* IP fragmentation bit flags */
#define IP_RF		0x8000	/* reserved fragment flag */
#define IP_DF		0x4000	/* don't fragment flag */
#define IP_MF		0x2000	/* more fragments flag */
#define IP_OFFMASK	0x1FFF	/* mask for fragmenting bits */

#endif /* __IP_HEADERS_H__ */
