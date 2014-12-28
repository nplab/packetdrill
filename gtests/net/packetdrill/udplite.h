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
 * Our own UDPLite header declarations, so we have something that's
 * portable and somewhat more readable than a typical system header
 * file.
 *
 * We cannot include the kernel's linux/udplite.h because this tool tries
 * to compile and work for basically any Linux/BSD kernel version. So
 * we declare our own version of various UDPLite-related definitions here.
 */

#ifndef __UDPLITE_HEADERS_H__
#define __UDPLITE_HEADERS_H__

#include "types.h"

/* UDPLite header. See RFC 3828. */
struct udplite {
	__be16	src_port;
	__be16	dst_port;
	__be16	cov;		/* UDPLite checksum coverage */
	__sum16 check;		/* UDPLite checksum */
};

#endif /* __UDPLITE_HEADERS_H__ */
