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
 * Interface for various network utilities related to configuring IP
 * addresses for network devices.
 */

#ifndef __NET_UTILS_H__
#define __NET_UTILS_H__

#include "types.h"

#include "ip_address.h"

/* Delete the given IP address, with the given subnet/prefix length,
 * from the given device.
 */
extern void net_del_dev_address(const char *dev_name,
				const struct ip_address *ip,
				int prefix_len);

/* See if the given IP address, with the given subnet/prefix length,
 * is already on the given device. If so, return without doing
 * anything.  If not, delete it from any device it's currently on, and
 * add it to the given network device.
 * On some platforms P2P devices are used, so also provide the gateway
 * address.
 */
extern void net_setup_dev_address(const char *dev_name,
				  const struct ip_address *local_ip,
				  int prefix_len,
				  const struct ip_address *local_linklocal_ip,
				  const struct ip_address *gateway_ip);

#endif /* __NET_UTILS_H__ */
