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
 * Helper functions for configuration information for a test run.
 */

#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <string.h>

#include "config.h"
#include "logging.h"
#include "ip_prefix.h"

/* For the sake of clarity, we require long option names, e.g. --foo,
 * for all options except -v.
 */
enum option_codes {
	OPT_IP_VERSION = 256,
	OPT_BIND_PORT,
	OPT_CODE_COMMAND,
	OPT_CODE_FORMAT,
	OPT_CODE_SOCKOPT,
	OPT_CONNECT_PORT,
	OPT_REMOTE_IP,
	OPT_LOCAL_IP,
	OPT_LOCAL_LINKLOCAL_IP,
	OPT_GATEWAY_IP,
	OPT_GATEWAY_LINKLOCAL_IP,
	OPT_NETMASK_IP,
	OPT_SPEED,
	OPT_MTU,
	OPT_INIT_SCRIPTS,
	OPT_TOLERANCE_USECS,
	OPT_WIRE_CLIENT,
	OPT_WIRE_SERVER,
	OPT_WIRE_SERVER_IP,
	OPT_WIRE_SERVER_PORT,
	OPT_WIRE_CLIENT_DEV,
	OPT_WIRE_SERVER_DEV,
	OPT_TCP_TS_TICK_USECS,
	OPT_NON_FATAL,
	OPT_DRY_RUN,
	OPT_DEBUG,
	OPT_UDP_ENCAPS,
	OPT_PATHS,
#if defined(__FreeBSD__) || defined(__OpenBSD__) || defined(__NetBSD__)
	OPT_TUN_DEV,
	OPT_PERSISTENT_TUN_DEV,
#endif
	OPT_NO_CLEANUP,
	OPT_DEFINE = 'D',	/* a '-D' single-letter option */
	OPT_VERBOSE = 'v',	/* a '-v' single-letter option */
};

/* Specification of command line options for getopt_long(). */
struct option options[] = {
	{ "ip_version",           .has_arg = true,  NULL, OPT_IP_VERSION },
	{ "bind_port",            .has_arg = true,  NULL, OPT_BIND_PORT },
	{ "code_command",         .has_arg = true,  NULL, OPT_CODE_COMMAND },
	{ "code_format",          .has_arg = true,  NULL, OPT_CODE_FORMAT },
	{ "code_sockopt",         .has_arg = true,  NULL, OPT_CODE_SOCKOPT },
	{ "connect_port",         .has_arg = true,  NULL, OPT_CONNECT_PORT },
	{ "remote_ip",            .has_arg = true,  NULL, OPT_REMOTE_IP },
	{ "local_ip",             .has_arg = true,  NULL, OPT_LOCAL_IP },
	{ "local_linklocal_ip",   .has_arg = true,  NULL, OPT_LOCAL_LINKLOCAL_IP },
	{ "gateway_ip",           .has_arg = true,  NULL, OPT_GATEWAY_IP },
	{ "gateway_linklocal_ip", .has_arg = true,  NULL, OPT_GATEWAY_LINKLOCAL_IP },
	{ "netmask_ip",           .has_arg = true,  NULL, OPT_NETMASK_IP },
	{ "speed",                .has_arg = true,  NULL, OPT_SPEED },
	{ "mtu",                  .has_arg = true,  NULL, OPT_MTU },
	{ "init_scripts",         .has_arg = true,  NULL, OPT_INIT_SCRIPTS },
	{ "tolerance_usecs",      .has_arg = true,  NULL, OPT_TOLERANCE_USECS },
	{ "wire_client",          .has_arg = false, NULL, OPT_WIRE_CLIENT },
	{ "wire_server",          .has_arg = false, NULL, OPT_WIRE_SERVER },
	{ "wire_server_ip",       .has_arg = true,  NULL, OPT_WIRE_SERVER_IP },
	{ "wire_server_port",     .has_arg = true,  NULL, OPT_WIRE_SERVER_PORT },
	{ "wire_client_dev",      .has_arg = true,  NULL, OPT_WIRE_CLIENT_DEV },
	{ "wire_server_dev",      .has_arg = true,  NULL, OPT_WIRE_SERVER_DEV },
	{ "tcp_ts_tick_usecs",    .has_arg = true,  NULL, OPT_TCP_TS_TICK_USECS },
	{ "non_fatal",            .has_arg = true,  NULL, OPT_NON_FATAL },
	{ "dry_run",              .has_arg = false, NULL, OPT_DRY_RUN },
	{ "define",               .has_arg = true,  NULL, OPT_DEFINE },
	{ "verbose",              .has_arg = false, NULL, OPT_VERBOSE },
	{ "debug",                .has_arg = false, NULL, OPT_DEBUG },
	{ "udp_encapsulation",    .has_arg = true,  NULL, OPT_UDP_ENCAPS },
	{ "paths",                .has_arg = true,  NULL, OPT_PATHS },
#if defined(__FreeBSD__) || defined(__OpenBSD__) || defined(__NetBSD__)
	{ "tun_dev",              .has_arg = true,  NULL, OPT_TUN_DEV },
	{ "persistent_tun_dev",   .has_arg = false, NULL, OPT_PERSISTENT_TUN_DEV },
#endif
	{ "no_cleanup",           .has_arg = false, NULL, OPT_NO_CLEANUP },
	{ NULL },
};

void show_usage(void)
{
	fprintf(stderr, "Usage: packetdrill\n"
		"\t[--ip_version=[ipv4,ipv4_mapped_ipv6,ipv6]]\n"
		"\t[--bind_port=bind_port]\n"
		"\t[--code_command=code_command]\n"
		"\t[--code_format=code_format]\n"
		"\t[--code_sockopt=TCP_INFO]\n"
		"\t[--connect_port=connect_port]\n"
		"\t[--remote_ip=<comma separated remote ips>]\n"
		"\t[--local_ip=<comma separated local ips>]\n"
		"\t[--local_linklocal_ip=<comma separated local linklocal ips>]\n"
		"\t[--gateway_ip=<comma separated gateway ips>]\n"
		"\t[--gateway_linklocal_ip=<comma separated gateway linklocal ips>]\n"
		"\t[--netmask_ip=<comma separated netmask ips>]\n"
		"\t[--init_scripts=<comma separated filenames>]\n"
		"\t[--speed=<speed in Mbps>]\n"
		"\t[--mtu=<MTU in bytes>]\n"
		"\t[--tolerance_usecs=tolerance_usecs]\n"
		"\t[--tcp_ts_tick_usecs=<microseconds per TCP TS val tick>]\n"
		"\t[--non_fatal=<comma separated types: packet,syscall>]\n"
		"\t[--wire_client]\n"
		"\t[--wire_server]\n"
		"\t[--wire_server_ip=<server_ipv4_address>]\n"
		"\t[--wire_server_port=<server_port>]\n"
		"\t[--wire_client_dev=<eth_dev_name>]\n"
		"\t[--wire_server_dev=<eth_dev_name>]\n"
		"\t[--dry_run]\n"
		"\t[--define symbol1=val1 --define symbol2=val2 ...]\n"
		"\t[--verbose|-v]\n"
		"\t[--debug] * requires compilation with DEBUG *\n"
		"\t[--udp_encapsulation=[sctp,tcp]]\n"
		"\t[--paths=<number of paths to be used>]\n"
#if defined(__FreeBSD__) || defined(__OpenBSD__) || defined(__NetBSD__)
		"\t[--tun_dev=<tun_dev_name>]\n"
		"\t[--persistent_tun_dev]\n"
#endif
		"\t[--no_cleanup]\n"
		"\tscript_path ...\n");
}

/* Allocate space for paths_cnt paths in config */
extern void paths_new(struct config *config, uint paths_cnt) {
	if (paths_cnt == 0)
		die("can't have zero paths\n");

	if (paths_cnt == config->live_paths_cnt)
		return;

	assert(config->live_paths == NULL);

	config->live_paths_cnt = paths_cnt;
	config->live_paths = calloc(paths_cnt, sizeof(struct path));
}

struct ip_address *paths_get_address(struct config *config, int addr_skip,
	int address_family, enum paths_address_types address_type)
{
	for (uint i = 0; i < config->live_paths_cnt; i++) {
		struct ip_address *ip_address;
		switch (address_type) {
		case PATH_ADDRESS_LOCAL_TYPE:
			ip_address = &config->live_paths[i].local_ip;
			break;
		case PATH_ADDRESS_REMOTE_TYPE:
			ip_address = &config->live_paths[i].remote_ip;
			break;
		}

		if (ip_address->address_family == address_family) {
			if (addr_skip == 0)
				return ip_address;
			addr_skip--;
		}
	}
	die("requested to many paths");
}

/* Fill in any as-yet-unspecified IP address attributes using IPv4 defaults.
 *
 * For IPv4, we use the 192.168.0.0/16 RFC 1918 private IP space for
 * our tun interface. To avoid accidents and confusion we want remote
 * addresses to be permanently unallocated addresses outside of the
 * private/unroutable RFC 1918 ranges (kernel code can behave
 * differently for private addresses). So for remote addresses we use
 * the 192.0.2.0/24 TEST-NET-1 range (see RFC 5737).
 *
 * Summary for IPv4:
 * - local address:  192.168.0.0/16 private IP space (RFC 1918)
 * - remote address: 192.0.2.0/24 TEST-NET-1 range (RFC 5737)
 */

static void set_ipv4_defaults(struct config *config)
{
	if (config->live_paths_cnt == 0)
		paths_new(config, 1);
	else if (config->live_paths_cnt >= 64)
		die("To many paths %d", config->live_paths_cnt);

	for (uint i = 0; i < config->live_paths_cnt; i++) {
		struct path *path = &config->live_paths[i];

		if (strlen(path->remote_ip_string) == 0)
			snprintf(path->remote_ip_string, ADDR_STR_LEN, "192.0.2.%d/%s",
			i + 1, config->live_paths_cnt == 1 ? "24" : "32");
		if (strlen(path->local_ip_string) == 0)
			snprintf(path->local_ip_string, ADDR_STR_LEN, "192.168.%d.1", i);
		if (strlen(path->gateway_ip_string) == 0)
			snprintf(path->gateway_ip_string, ADDR_STR_LEN, "192.168.%d.2", i);
		if (strlen(path->netmask_ip_string) == 0)
			strcpy(path->netmask_ip_string, config->live_paths_cnt == 1 ?
			"255.255.0.0" : "255.255.255.0");
	}
}

/* Fill in any as-yet-unspecified IP address attributes using IPv6 defaults.
 *
 * For IPv6 we use a ULA (unique local address) for our local (tun)
 * interface, and the RFC 3849 documentation space for our remote
 * address.
 *
 * Summary for IPv6:
 * - local address: fd3d:fa7b:d17d::/48 in unique local address space (RFC 4193)
 * - remote address: 2001:DB8::/32 documentation prefix (RFC 3849)
 */
static void set_ipv6_defaults(struct config *config)
{
	if (config->live_paths_cnt == 0)
		paths_new(config, 1);
	else if (config->live_paths_cnt >= 0xffff)
		die("To many paths %d", config->live_paths_cnt);

	for (uint i = 0; i < config->live_paths_cnt; i++) {
		struct path *path = &config->live_paths[i];

		if (strlen(path->remote_ip_string) == 0)
			snprintf(path->remote_ip_string, ADDR_STR_LEN, "2001:DB8::%d/%s",
			i, config->live_paths_cnt == 1 ? "32" : "128");
		if (strlen(path->local_ip_string) == 0)
			snprintf(path->local_ip_string, ADDR_STR_LEN, "fd3d:fa7b:d17d::%d:1", i);
		if (strlen(path->local_linklocal_ip_string) == 0)
			strcpy(path->local_linklocal_ip_string, "fe80::1");
		if (strlen(path->gateway_ip_string) == 0)
			snprintf(path->gateway_ip_string, ADDR_STR_LEN, "fd3d:fa7b:d17d::%d:2", i);
		if (strlen(path->gateway_linklocal_ip_string) == 0)
			strcpy(path->gateway_linklocal_ip_string, "fe80::2");
	}
}

/* Set default configuration before we begin parsing. */
void set_default_config(struct config *config)
{
	cleanup_config(config);
#if defined(__FreeBSD__)
	config->code_command_line	= "/usr/local/bin/python";
#else
	config->code_command_line	= "/usr/bin/python";
#endif
	config->code_format		= "python";
	config->code_sockopt		= "";		/* auto-detect */
	config->ip_version		= IP_VERSION_4;
	config->live_bind_port		= 8080;
	config->live_connect_port	= 8080;
	config->tolerance_usecs		= 4000;
	config->speed			= TUN_DRIVER_SPEED_CUR;
	config->mtu			= TUN_DRIVER_DEFAULT_MTU;

	/* For now, by default we disable checks of outbound TS val
	 * values, since there are timestamp val bugs in the tests and
	 * kernel. TODO(ncardwell): Switch default tcp_ts_tick_usecs
	 * to 1000 when TCP timestamp val bugs have been eradicated
	 * from kernel and tests.
	 */
	config->tcp_ts_tick_usecs	= 0;	/* disable checks of TS val */

	// We initialize these later either by options or in set_XXX_defaults
	config->live_paths = NULL;
	config->live_paths_cnt = 0;

	config->init_scripts = NULL;

	config->wire_server_port	= 8081;
#ifdef linux
	config->wire_client_device	= "eth0";
	config->wire_server_device	= "eth0";
#endif

	/* Enter a flag for the OS we are running on */
#ifdef __APPLE__
	definition_set(&config->defines, strdup("Apple"), NULL);
#endif
#ifdef linux
	definition_set(&config->defines, strdup("Linux"), NULL);
#endif
#ifdef __FreeBSD__
	definition_set(&config->defines, strdup("FreeBSD"), NULL);
#endif
#ifdef __NetBSD__
	definition_set(&config->defines, strdup("NetBSD"), NULL);
#endif
#ifdef __OpenBSD__
	definition_set(&config->defines, strdup("OpenBSD"), NULL);
#endif
#ifdef __SunOS_5_11
	definition_set(&config->defines, strdup("Solaris"), NULL);
#endif
}

static void set_remote_ip_and_prefix(struct path *path)
{
	path->remote_ip = path->remote_prefix.ip;
	ip_to_string(&path->remote_ip, path->remote_ip_string);

	ip_prefix_normalize(&path->remote_prefix);
	ip_prefix_to_string(&path->remote_prefix, path->remote_prefix_string);
}

/* Here's a table summarizing the types of various entities in the
 * different flavors of IP that we support:
 *
 * flavor	socket_domain	bind/connect/accept IP		local/remote IP
 * --------	-------------	-------------------------	---------------
 * 4		AF_INET		AF_INET				AF_INET
 * 4-mapped-6	AF_INET6	AF_INET6 mapped from IPv4	AF_INET
 * 6		AF_INET6	AF_INET6			AF_INET6
 */

/* Calculate final configuration values needed for IPv4 */
static void finalize_ipv4_config(struct config *config)
{
	set_ipv4_defaults(config);

	for (uint i = 0; i < config->live_paths_cnt; i++) {
		struct path *path = &config->live_paths[i];

		path->local_ip	= ipv4_parse(path->local_ip_string);

		path->remote_prefix = ipv4_prefix_parse(path->remote_ip_string);
		set_remote_ip_and_prefix(path);

		path->prefix_len = netmask_to_prefix(path->netmask_ip_string);
		path->gateway_ip = ipv4_parse(path->gateway_ip_string);
	}

	config->socket_domain	= AF_INET;
	config->wire_protocol	= AF_INET;
}

/* Calculate final configuration values needed for ipv4-mapped-ipv6 */
static void finalize_ipv4_mapped_ipv6_config(struct config *config)
{
	set_ipv4_defaults(config);

	for (uint i = 0; i < config->live_paths_cnt; i++) {
		struct path *path = &config->live_paths[i];

		path->local_ip	= ipv4_parse(path->local_ip_string);

		path->remote_prefix = ipv4_prefix_parse(path->remote_ip_string);
		set_remote_ip_and_prefix(path);

		path->prefix_len = netmask_to_prefix(path->netmask_ip_string);
		path->gateway_ip = ipv4_parse(path->gateway_ip_string);
	}

	config->socket_domain	= AF_INET6;
	config->wire_protocol	= AF_INET;
}

/* Calculate final configuration values needed for IPv6 */
static void finalize_ipv6_config(struct config *config)
{
	set_ipv6_defaults(config);

	for (uint i = 0; i < config->live_paths_cnt; i++) {
		struct path *path = &config->live_paths[i];

		path->local_ip	= ipv6_parse(path->local_ip_string);
		path->local_linklocal_ip = ipv6_parse(path->local_linklocal_ip_string);

		path->remote_prefix = ipv6_prefix_parse(path->remote_ip_string);
		set_remote_ip_and_prefix(path);

		path->prefix_len = config->live_paths_cnt == 1 ? 48 : 64;
		path->gateway_ip = ipv6_parse(path->gateway_ip_string);
		path->gateway_linklocal_ip = ipv6_parse(path->gateway_linklocal_ip_string);
	}

	config->socket_domain	= AF_INET6;
	config->wire_protocol	= AF_INET6;
}

void finalize_config(struct config *config)
{
	assert(config->ip_version >= IP_VERSION_4);
	assert(config->ip_version <= IP_VERSION_6);
	switch (config->ip_version) {
	case IP_VERSION_4:
		finalize_ipv4_config(config);
		break;
	case IP_VERSION_4_MAPPED_6:
		finalize_ipv4_mapped_ipv6_config(config);
		break;
	case IP_VERSION_6:
		finalize_ipv6_config(config);
		break;
		/* omitting default so compiler will catch missing cases */
	}
	if (config->is_wire_client) {
		if (config->wire_client_device == NULL) {
			die("wire_client_dev not specified\n");
		}
		if (config->wire_server_ip_string == NULL) {
			die("wire_server_ip not specified\n");
		}
	}
#if defined(__FreeBSD__) || defined(__OpenBSD__) || defined(__NetBSD__)
	if ((config->tun_device == NULL) &&
	    (config->persistent_tun_device == true)) {
		die("tun_dev not specified\n");
	}
	if ((config->is_wire_client) || (config->is_wire_server)){
		if (config->tun_device != NULL) {
			die("tun_dev specified specified\n");
		}
		if (config->persistent_tun_device == true) {
			die("persistent_tun_dev requested\n");
		}
	}
#endif
}

void cleanup_config(struct config *config)
{
	struct definition *cur_def, *next_def;
	int i;

	if (config->argv != NULL) {
		for (i = 0; config->argv[i] != NULL; i++) {
			free(config->argv[i]);
		}
	}
	free(config->argv);
	free(config->script_path);
	free(config->live_paths);
#if defined(__FreeBSD__) || defined(__OpenBSD__) || defined(__NetBSD__)
	free(config->tun_device);
#endif
	cur_def = config->defines;
	while (cur_def != NULL) {
		next_def = cur_def->next;
		free(cur_def->symbol);
		free(cur_def->value);
		free(cur_def);
		cur_def = next_def;
	}
	memset(config, 0, sizeof(struct config));
}

/* Expect that arg is comma-delimited, allowing for spaces. */
void parse_non_fatal_arg(char *arg, struct config *config)
{
	char *argdup, *saveptr, *token;

	if (arg == NULL || strlen(arg) == 0)
		return;

	argdup = strdup(arg);
	token = strtok_r(argdup, ", ", &saveptr);
	while (token != NULL) {
		if (strcmp(token, "packet") == 0)
			config->non_fatal_packet = true;
		else if (strcmp(token, "syscall") == 0)
			config->non_fatal_syscall = true;
		token = strtok_r(NULL, ", ", &saveptr);
	}

	free(argdup);
}

/* Expect that ips are comma-delimited, allowing for spaces. */
int parse_ips_arg(char *arg, int target, struct config *config)
{
	char *argdup, *saveptr, *token;

	if (arg == NULL || strlen(arg) == 0)
		return STATUS_ERR;

	int ip_cnt = 1;
	for (int i = 0; arg[i]; i++) {
		if (arg[i] == ',')
			ip_cnt++;
	}

	if(config->live_paths_cnt == 0)
		paths_new(config, ip_cnt);
	else if (config->live_paths_cnt != ip_cnt)
		return STATUS_ERR;

	argdup = strdup(arg);
	token = strtok_r(argdup, ", ", &saveptr);
	for (int i = 0; token != NULL; i++) {
		switch (target) {
		case OPT_REMOTE_IP:
			strncpy(config->live_paths[i].remote_ip_string, token, ADDR_STR_LEN - 1);
			break;
		case OPT_LOCAL_IP:
			strncpy(config->live_paths[i].local_ip_string, token, ADDR_STR_LEN - 1);
			break;
		case OPT_LOCAL_LINKLOCAL_IP:
			strncpy(config->live_paths[i].local_linklocal_ip_string, token, ADDR_STR_LEN - 1);
			break;
		case OPT_GATEWAY_IP:
			strncpy(config->live_paths[i].gateway_ip_string, token, ADDR_STR_LEN - 1);
			break;
		case OPT_GATEWAY_LINKLOCAL_IP:
			strncpy(config->live_paths[i].gateway_linklocal_ip_string, token, ADDR_STR_LEN - 1);
			break;
		case OPT_NETMASK_IP:
			strncpy(config->live_paths[i].netmask_ip_string, token, ADDR_STR_LEN - 1);
			break;
		default:
			return STATUS_ERR;
		}
		token = strtok_r(NULL, ", ", &saveptr);
	}
	free(argdup);

	return STATUS_OK;
}


/* Process a command line option */
static void process_option(int opt, char *optarg, struct config *config,
			   char *where)
{
	int port, paths = 0;
	char *end = NULL, *equals = NULL, *symbol = NULL, *value = NULL;
	unsigned long speed = 0;

	DEBUGP("process_option %d = %s\n", opt, optarg);

	switch (opt) {
	case OPT_IP_VERSION:
		assert(optarg != NULL);
		if (strcmp(optarg, "ipv4") == 0)
			config->ip_version = IP_VERSION_4;
		else if ((strcmp(optarg, "ipv4-mapped-ipv6") == 0) ||
		         (strcmp(optarg, "ipv4_mapped_ipv6") == 0))
			config->ip_version = IP_VERSION_4_MAPPED_6;
		else if (strcmp(optarg, "ipv6") == 0)
			config->ip_version = IP_VERSION_6;
		else
			die("%s: bad --ip_version: %s\n", where, optarg);
		break;
	case OPT_BIND_PORT:
		assert(optarg != NULL);
		port = atoi(optarg);
		if ((port <= 0) || (port > 0xffff))
			die("%s: bad --bind_port: %s\n", where, optarg);
		config->live_bind_port = port;
		break;
	case OPT_CODE_COMMAND:
		assert(optarg != NULL);
		config->code_command_line = optarg;
		break;
	case OPT_CODE_FORMAT:
		assert(optarg != NULL);
		config->code_format = optarg;
		break;
	case OPT_CODE_SOCKOPT:
		assert(optarg != NULL);
		config->code_sockopt = optarg;
		break;
	case OPT_CONNECT_PORT:
		assert(optarg != NULL);
		port = atoi(optarg);
		if ((port <= 0) || (port > 0xffff))
			die("%s: bad --connect_port: %s\n", where, optarg);
		config->live_connect_port = port;
		break;
	case OPT_REMOTE_IP:
		assert(optarg != NULL);
		if (parse_ips_arg(optarg, OPT_REMOTE_IP, config) == STATUS_ERR)
			die("%s: bad --remote_ip: %s\n", where, optarg);
		break;
	case OPT_LOCAL_IP:
		assert(optarg != NULL);
		if (parse_ips_arg(optarg, OPT_LOCAL_IP, config) == STATUS_ERR)
			die("%s: bad --local_ip: %s\n", where, optarg);
		break;
	case OPT_LOCAL_LINKLOCAL_IP:
		assert(optarg != NULL);
		if (parse_ips_arg(optarg, OPT_LOCAL_LINKLOCAL_IP, config) == STATUS_ERR)
			die("%s: bad --local_linklocal_ip: %s\n", where, optarg);
		break;
	case OPT_GATEWAY_IP:
		assert(optarg != NULL);
		if (parse_ips_arg(optarg, OPT_GATEWAY_IP, config) == STATUS_ERR)
			die("%s: bad --gateway_ip: %s\n", where, optarg);
		break;
	case OPT_GATEWAY_LINKLOCAL_IP:
		assert(optarg != NULL);
		if (parse_ips_arg(optarg, OPT_GATEWAY_LINKLOCAL_IP, config) == STATUS_ERR)
			die("%s: bad --gateway_linklocal_ip: %s\n", where, optarg);
		break;
	case OPT_NETMASK_IP:
		assert(optarg != NULL);
		if (parse_ips_arg(optarg, OPT_NETMASK_IP, config) == STATUS_ERR)
			die("%s: bad --netmask_ip: %s\n", where, optarg);
		break;
	case OPT_MTU:
		assert(optarg != NULL);
		config->mtu = atoi(optarg);
		if (config->mtu < 0)
			die("%s: bad --mtu: %s\n", where, optarg);
		break;
	case OPT_INIT_SCRIPTS:
		assert(optarg != NULL);
		config->init_scripts = optarg;
		break;
	case OPT_NON_FATAL:
		assert(optarg != NULL);
		parse_non_fatal_arg(optarg, config);
		break;
	case OPT_SPEED:
		assert(optarg != NULL);
		speed = strtoul(optarg, &end, 10);
		if (end == optarg || *end || !is_valid_u32(speed))
			die("%s: bad --speed: %s\n", where, optarg);
		config->speed = speed;
		break;
	case OPT_TOLERANCE_USECS:
		assert(optarg != NULL);
		config->tolerance_usecs = atoi(optarg);
		if (config->tolerance_usecs <= 0)
			die("%s: bad --tolerance_usecs: %s\n", where, optarg);
		break;
	case OPT_TCP_TS_TICK_USECS:
		assert(optarg != NULL);
		config->tcp_ts_tick_usecs = atoi(optarg);
		if (config->tcp_ts_tick_usecs < 0 ||
		    config->tcp_ts_tick_usecs > 1000000)
			die("%s: bad --tcp_ts_tick_usecs: %s\n", where, optarg);
		break;
	case OPT_WIRE_CLIENT:
		config->is_wire_client = true;
		break;
	case OPT_WIRE_SERVER:
		config->is_wire_server = true;
		break;
	case OPT_WIRE_SERVER_IP:
		assert(optarg != NULL);
		config->wire_server_ip_string = strdup(optarg);
		config->wire_server_ip	=
			ipv4_parse(config->wire_server_ip_string);
		break;
	case OPT_WIRE_SERVER_PORT:
		assert(optarg != NULL);
		port = atoi(optarg);
		if ((port <= 0) || (port > 0xffff))
			die("%s: bad --wire_server_port: %s\n", where, optarg);
		config->wire_server_port = port;
		break;
	case OPT_WIRE_CLIENT_DEV:
		assert(optarg != NULL);
		config->wire_client_device = strdup(optarg);
		break;
	case OPT_WIRE_SERVER_DEV:
		assert(optarg != NULL);
		config->wire_server_device = strdup(optarg);
		break;
	case OPT_DRY_RUN:
		config->dry_run = true;
		break;
	case OPT_DEFINE:
		assert(optarg != NULL);
		equals = strstr(optarg, "=");
		if (equals == optarg || equals == NULL)
			die("%s: bad definition: %s\n", where, optarg);
		symbol = strndup(optarg, equals - optarg);
		value = strdup(equals + 1);
		definition_set(&config->defines, symbol, value);
		break;
	case OPT_VERBOSE:
		config->verbose = true;
		break;
	case OPT_DEBUG:
#if !defined(DEBUG)
		die("error: --debug requires building with DEBUG on.\n");
#endif
		debug_logging = true;
		break;
	case OPT_UDP_ENCAPS:
		assert(optarg != NULL);
		if (strcmp(optarg, "sctp") == 0)
			config->udp_encaps = IPPROTO_SCTP;
		else if (strcmp(optarg, "tcp") == 0)
			config->udp_encaps = IPPROTO_TCP;
		else
			die("%s: bad --udp_encapsulation: %s\n", where, optarg);
		break;
	case OPT_PATHS:
		assert(optarg != NULL);
		paths = atoi(optarg);
		if(paths <= 0)
			die("%s: bad --paths: %s must be positive\n", where, optarg);
		if(config->live_paths_cnt == 0)
			paths_new(config, paths);
		else if (config->live_paths_cnt != paths)
			die("%s: bad --paths: %s does not match the number of IPs\n", where, optarg);
		break;
#if defined(__FreeBSD__) || defined(__OpenBSD__) || defined(__NetBSD__)
	case OPT_TUN_DEV:
		assert(optarg != NULL);
		config->tun_device = strdup(optarg);
		break;
	case OPT_PERSISTENT_TUN_DEV:
		config->persistent_tun_device = true;
		break;
#endif
	case OPT_NO_CLEANUP:
		config->no_cleanup = true;
		break;
	default:
		show_usage();
		exit(EXIT_FAILURE);
	}
}


/* Parse command line options. Returns a pointer to the first argument
 * beyond the options.
 */
char **parse_command_line_options(int argc, char *argv[],
				  struct config *config)
{
	int c = 0;
	int i = 0;

	DEBUGP("parse_command_line_options argc=%d\n", argc);
	for (i = 0; i < argc; ++i)
		DEBUGP("argv[%d] = '%s'\n", i, argv[i]);

	/* Make a copy of our arguments for later, in case we need to
	 * pass our options to a server. We use argc+1 here because,
	 * following main() calling conventions, we make the array
	 * element at argv[argc] a NULL pointer.
	 */
	config->argv = calloc(argc + 1, sizeof(char *));
	for (i = 0; argv[i]; ++i)
		config->argv[i] = strdup(argv[i]);

	/* Parse the arguments. */
	optind = 0;
	while ((c = getopt_long(argc, argv, "vD:", options, NULL)) > 0)
		process_option(c, optarg, config, "Command Line");
	return argv + optind;
}

static void parse_script_options(struct config *config,
				 struct option_list *option_list)
{
	struct option_list *opt = option_list;
	while (opt != NULL) {
		int i;
		int c = 0;
		for (i = 0; options[i].name != NULL; i++) {
			if (strcmp(options[i].name, opt->name) == 0) {
				c = options[i].val;
				break;
			}
		}

		if (!c)
			die("%s: option '%s' unknown\n",
			    config->script_path, opt->name);
		if (opt->value && !options[i].has_arg)
			die("%s: option '%s' forbids an argument\n",
			    config->script_path, opt->name);
		if (!opt->value && options[i].has_arg)
			die("%s: option '%s' requires an argument\n",
			    config->script_path, opt->name);

		process_option(options[i].val,
			       opt->value, config,
			       config->script_path);

		opt = opt->next;
	}
}

/* The parser calls this callback after it finishes parsing all
 * --foo=bar options inside the script. At this point we know all
 * command line and in-script options, and can finalize our
 * configuration. Notably, this allows us to know when we parse a TCP
 * packet line in the script whether we should create an IPv4 or IPv6
 * packet.
 */
void parse_and_finalize_config(struct invocation *invocation)
{
	DEBUGP("parse_and_finalize_config\n");

	/* Parse options in script */
	parse_script_options(invocation->config,
			     invocation->script->option_list);

	/* Command line options overwrite options in script */
	parse_command_line_options(invocation->argc, invocation->argv,
					   invocation->config);

	/* Now take care of the last details */
	finalize_config(invocation->config);
}
