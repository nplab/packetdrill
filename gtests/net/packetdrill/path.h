#ifndef __PATH_H__
#define __PATH_H__

#include "ip_address.h"
#include "ip_prefix.h"

struct path {
	struct ip_address local_ip;	    /* local interface IP */
	struct ip_address local_linklocal_ip;	/* IPv6 local link-local address */
	struct ip_address remote_ip;	/* remote interface IP */
	struct ip_prefix remote_prefix;	/* remote prefix under test */
	struct ip_address gateway_ip;	/* gateway interface IP */
	struct ip_address gateway_linklocal_ip;	/* IPv6 gateway link-local address */

	char local_ip_string[ADDR_STR_LEN];	        /* human-readable IP */
	char local_linklocal_ip_string[ADDR_STR_LEN];	/* human-readable IP */
	char remote_ip_string[ADDR_STR_LEN];	    /* human-readable IP */
	char remote_prefix_string[ADDR_STR_LEN];	/* <addr>/<prefixlen> */

	char gateway_ip_string[ADDR_STR_LEN];	/* local gateway IP */
	char gateway_linklocal_ip_string[ADDR_STR_LEN];	/* local gateway IP */
	char netmask_ip_string[ADDR_STR_LEN];	/* local netmask */

	int prefix_len;		/* IPv4/IPv6 interface prefix len */
};

enum paths_address_types {
	PATH_ADDRESS_LOCAL_TYPE,
	PATH_ADDRESS_REMOTE_TYPE
};

#endif /* __PATH_H__ */
