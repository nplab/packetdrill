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
 * Declarations for platform-specific information.
 */

#ifndef __PLATFORMS_H__
#define __PLATFORMS_H__


/* ------------------------- Linux --------------------- */

#ifdef linux

/* It seems that Linux does not provide netinet/udplite.h */
#define SOL_UDPLITE            IPPROTO_UDPLITE
#define UDPLITE_SEND_CSCOV     10
#define UDPLITE_RECV_CSCOV     11
#include <features.h>
#include <netinet/sctp.h>
#define HAVE_OPEN_MEMSTREAM     1
#define HAVE_FMEMOPEN           1
#define TUN_DIR                 "/dev/net"
#define HAVE_TCP_INFO           1

#endif  /* linux */


/* ------------------------- FreeBSD --------------------- */

#if defined(__FreeBSD__)

#include <netinet/sctp.h>
#include <sys/param.h>
#include <paths.h>
#if __FreeBSD_version >= 1001000
#include <netinet/udplite.h>
#endif
#define USE_LIBPCAP             1
#define TUN_DIR                 _PATH_DEV
#define HAVE_TCP_INFO           1
#if (__FreeBSD_version < 1000000 && __FreeBSD_version > 902000) || __FreeBSD_version > 1000028
#define HAVE_FMEMOPEN           1
#else
#include "fmemopen.h"
#endif
#if (__FreeBSD_version > 902000)
#define HAVE_OPEN_MEMSTREAM     1
#else
#include "open_memstream.h"
#endif

#endif  /* __FreeBSD__ */

/* ------------------------- OpenBSD --------------------- */

#if defined(__OpenBSD__)

#define USE_LIBPCAP             1
#define TUN_DIR                 "/dev"

#define HAVE_TCP_INFO           0

#include "open_memstream.h"
#include "fmemopen.h"

#define __always_inline __attribute__((__always_inline__))

#endif  /* __OpenBSD__ */

/* ------------------------- NetBSD --------------------- */

#if defined(__NetBSD__)

#define USE_LIBPCAP             1
#define TUN_DIR                 "/dev"

#define HAVE_TCP_INFO           0

#define HAVE_FMEMOPEN           1
#include "open_memstream.h"

#define __always_inline __attribute__((__always_inline__))

#endif  /* __NetBSD__ */

/* ------------------------- Darwin --------------------- */

#if defined(__APPLE__)

#include <AvailabilityMacros.h>

#if defined(HAVE_SCTP)
#include <sys/types.h>
#include <netinet/sctp.h>
#endif
#define USE_LIBPCAP             1
#define HAVE_TCP_INFO           1
/* open_memstream() and fmemopen() are available in MacOS 10.13 and higher. */
#if MAC_OS_X_VERSION_MIN_REQUIRED >= 101300
#define HAVE_FMEMOPEN           1
#define HAVE_OPEN_MEMSTREAM     1
#else
#include "open_memstream.h"
#include "fmemopen.h"
#endif

#endif  /* __APPLE__ */

/* ------------------------- Solaris --------------------- */

#if defined(__SunOS_5_11)

#define IPPROTO_IPIP            IPPROTO_ENCAP
#define IPPROTO_GRE             47
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/sctp.h>
#define USE_LIBPCAP             1
#define TUN_DIR                 "/dev"
#define HAVE_TCP_INFO           1
/* open_memstream() and fmemopen() are available in Solaris 11.4 and higher. */
#define HAVE_FMEMOPEN           1
#define HAVE_OPEN_MEMSTREAM     1

#endif  /* __SunOS_5_11 */


#endif /* __PLATFORMS_H__ */
