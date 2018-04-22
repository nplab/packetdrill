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
 * Implementation for a "virtual network device" module to
 * inject packets into the kernel and read packets leaving the kernel.
 */

#include "netdev.h"

#include <arpa/inet.h>
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <net/if.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <sys/wait.h>
#include <unistd.h>

#if defined(__FreeBSD__) || defined(__OpenBSD__) || defined(__NetBSD__)
#include <net/if_tun.h>
#endif /* defined(__FreeBSD__) || defined(__OpenBSD__) || defined(__NetBSD__) */
#if defined(__APPLE__)
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <net/if.h>
#include <net/if_utun.h>
#include <sys/kern_control.h>
#include <sys/kern_event.h>
#endif
#include "ip.h"
#include "ipv6.h"
#include "logging.h"
#include "net_utils.h"
#include "packet.h"
#include "packet_parser.h"
#include "packet_socket.h"
#include "tcp.h"
#include "tun.h"

/* Internal private state for the netdev for purely local tests. */
struct local_netdev {
	struct netdev netdev;		/* "inherit" from netdev */

	char *name;		/* malloc-ed copy of interface name (owned) */
	int tun_fd;		/* tun for sending/receiving packets */
	int ipv4_control_fd;	/* fd for IPv4 configuration of tun interface */
	int ipv6_control_fd;	/* fd for IPv6 configuration of tun interface */
	int index;		/* interface index from if_nametoindex */
	struct packet_socket *psock;	/* for sniffing packets (owned) */
	bool persistent;
};

struct netdev_ops local_netdev_ops;

/* "Downcast" an abstract netdev to our local flavor. */
static inline struct local_netdev *to_local_netdev(struct netdev *netdev)
{
	return (struct local_netdev *)netdev;
}

/* Clean up any old tun device state that might be lying around from
 * previous tests. NetBSD the kernel does not automatically tear down
 * unreferenced tun devices and routes referencing those routes.
 */
static void cleanup_old_device(struct config *config,
				struct local_netdev *netdev)
{
#if defined(__NetBSD__)
	char *cleanup_command = NULL;
#ifdef DEBUG
	int result;
#endif

	if ((config->tun_device == NULL) || config->persistent_tun_device) {
		return;
	}
	asprintf(&cleanup_command,
		 "/sbin/ifconfig %s down delete > /dev/null 2>&1",
		 config->tun_device);
	DEBUGP("running: '%s'\n", cleanup_command);
#ifdef DEBUG
	result = system(cleanup_command);
#else
	system(cleanup_command);
#endif
	DEBUGP("result: %d\n", result);
	free(cleanup_command);
#endif  /* defined(__NetBSD__) */
}

/* Check that the remote IP is actually remote. It must be to ensure
 * that test packets will pass into our tun device.
 */
static void check_remote_address(struct config *config,
				 struct local_netdev *netdev)
{
	if (is_ip_local(&config->live_remote_ip)) {
		die("error: live_remote_ip %s is not remote\n",
		    config->live_remote_ip_string);
	}
}

/* Create a tun device for the lifetime of this test. */
#if defined(__APPLE__)
static void create_device(struct config *config, struct local_netdev *netdev)
{
	struct sockaddr_ctl addr;
	struct ctl_info info;
	char name[IFNAMSIZ];
	char *command;
	socklen_t len;
	int tun_fd;

	tun_fd = socket(PF_SYSTEM, SOCK_DGRAM, SYSPROTO_CONTROL);
	if (tun_fd < 0) {
		die_perror("open utun device");
	}
	memset(&info, 0, sizeof(struct ctl_info));
	strncpy(info.ctl_name, UTUN_CONTROL_NAME, MAX_KCTL_NAME);
	if (ioctl(tun_fd, CTLIOCGINFO, &info) < 0) {
		die_perror("open utun device");
	}
	addr.sc_len = sizeof(struct sockaddr_ctl);
	addr.sc_family = AF_SYSTEM;
	addr.ss_sysaddr = AF_SYS_CONTROL;
	addr.sc_id = info.ctl_id;
	addr.sc_unit = 0;
	if (connect(tun_fd, (struct sockaddr *)&addr, sizeof(struct sockaddr_ctl)) < 0) {
		die_perror("open utun device");
	}
	netdev->tun_fd = tun_fd;
	len = IFNAMSIZ;
	if (getsockopt(tun_fd, SYSPROTO_CONTROL, UTUN_OPT_IFNAME, name, &len) < 0) {
		die_perror("open utun device");
	}
	netdev->name = strdup(name);
	DEBUGP("utun name: '%s'\n", netdev->name);
	netdev->index = if_nametoindex(netdev->name);
	if (netdev->index == 0)
		die_perror("if_nametoindex");
	DEBUGP("utun index: '%d'\n", netdev->index);
	if (config->mtu != TUN_DRIVER_DEFAULT_MTU) {
		asprintf(&command, "ifconfig %s mtu %d", netdev->name, config->mtu);
		if (system(command) < 0)
			die("Error executing %s\n", command);
		free(command);
	}
}
#else
static void create_device(struct config *config, struct local_netdev *netdev)
{
	/* Open the tun device, which "clones" it for our purposes. */
	int tun_fd;
	char *tun_path;
#if defined(__FreeBSD__) || defined(__OpenBSD__) || defined(__NetBSD__)
	struct stat buf;
#endif

#if defined(__FreeBSD__) || defined(__OpenBSD__) || defined(__NetBSD__)
	netdev->persistent = config->persistent_tun_device;
	if (config->tun_device != NULL) {
		asprintf(&tun_path, "%s/%s", TUN_DIR, config->tun_device);
	} else {
		asprintf(&tun_path, "%s/%s", TUN_DIR, "tun");
	}
#endif
#if defined(linux)
	asprintf(&tun_path, "%s/%s", TUN_DIR, "tun");
#endif
	tun_fd = open(tun_path, O_RDWR);
#if defined(__FreeBSD__)
	if ((tun_fd < 0) && (errno == ENOENT)) {
		if (system("kldload -q if_tun") < 0) {
			die_perror("kldload -q if_tun");
		}
		tun_fd = open(tun_path, O_RDWR);
	}
#endif
	free(tun_path);
	if (tun_fd < 0) {
		die_perror("open tun device");
	}
	netdev->tun_fd = tun_fd;

#ifdef linux
	/* Create the device. Since we do not specify a device name, the
	 * kernel will try to allocate the "next" device of the specified
	 * type. This device will disappear when we are done.
	 */
	struct ifreq ifr;
	memset(&ifr, 0, sizeof(ifr));
	ifr.ifr_flags = IFF_TUN | IFF_NO_PI;
	int status = ioctl(netdev->tun_fd, TUNSETIFF, (void *)&ifr);
	if (status < 0)
		die_perror("TUNSETIFF");

	netdev->name = strdup(ifr.ifr_name);
#endif

#if defined(__FreeBSD__) || defined(__OpenBSD__) || defined(__NetBSD__)
	const int mode = IFF_BROADCAST | IFF_MULTICAST;
	if (ioctl(netdev->tun_fd, TUNSIFMODE, &mode, sizeof(mode)) < 0)
		die_perror("TUNSIFMODE");
	if (fstat(netdev->tun_fd, &buf) < 0) {
		die_perror("fstat tun device");
	}
	netdev->name = strdup(devname(buf.st_rdev, S_IFCHR));
#endif /* defined(__FreeBSD__) || defined(__OpenBSD__) || defined(__NetBSD__) */

#if defined(__FreeBSD__) ||  defined(__NetBSD__)
	/* On FreeBSD and NetBSD we need to explicitly ask to be able
	 * to prepend the address family when injecting tun packets.
	 * OpenBSD presumes we are doing this, even without the ioctl.
	 */
	const int header = 1;
	if (ioctl(netdev->tun_fd, TUNSIFHEAD, &header, sizeof(header)) < 0)
		die_perror("TUNSIFHEAD");
#endif /* defined(__FreeBSD__) ||  defined(__NetBSD__) */

	DEBUGP("tun name: '%s'\n", netdev->name);

	netdev->index = if_nametoindex(netdev->name);
	if (netdev->index == 0)
		die_perror("if_nametoindex");

	DEBUGP("tun index: '%d'\n", netdev->index);

#ifdef __FreeBSD__
	struct tuninfo tuninfo;

	if (ioctl(netdev->tun_fd, TUNGIFINFO, &tuninfo, sizeof(tuninfo)) < 0)
		die_perror("TUNGIFINFO");
	DEBUGP("Interface baudrate: %d bps, mtu: %d\n",
	        tuninfo.baudrate, tuninfo.mtu);
	DEBUGP("Requested baudrate: %ju bps, mtu: %d\n",
	       IF_Mbps(config->speed), config->mtu);
	if ((tuninfo.baudrate != IF_Mbps(config->speed)) ||
	    (tuninfo.mtu != config->mtu)) {
		tuninfo.baudrate = IF_Mbps(config->speed);
		tuninfo.mtu = config->mtu;
		if (ioctl(netdev->tun_fd, TUNSIFINFO, &tuninfo, sizeof(tuninfo)) < 0)
			die_perror("TUNSIFINFO");
	}
#else
	if (config->speed != TUN_DRIVER_SPEED_CUR) {
		char *command;
		asprintf(&command, "ethtool -s %s speed %u autoneg off",
			 netdev->name, config->speed);
		if (system(command) < 0)
			die("Error executing %s\n", command);
		free(command);

		/* Need to bring interface down and up so the interface speed
		 * will be copied to the link_speed field. This field is
		 * used by TCP's cwnd bound. */
		asprintf(&command, "ifconfig %s down; sleep 1; ifconfig %s up; "
			      "sleep 1", netdev->name, netdev->name);
		if (system(command) < 0)
			die("Error executing %s\n", command);
		free(command);
	}

	if (config->mtu != TUN_DRIVER_DEFAULT_MTU) {
		char *command;
		asprintf(&command, "ifconfig %s mtu %d",
			 netdev->name, config->mtu);
		if (system(command) < 0)
			die("Error executing %s\n", command);
		free(command);
	}
#endif

	/* Open a socket we can use to configure the tun interface.
	 * We only open up an AF_INET6 socket on-demand as needed,
	 * so that we can run IPv4 tests on a machine without IPv6.
	 */
	netdev->ipv4_control_fd = -1;
	netdev->ipv6_control_fd = -1;
	netdev->ipv4_control_fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_IP);
	if (netdev->ipv4_control_fd < 0)
		die_perror("opening AF_INET, SOCK_DGRAM, IPPROTO_IP socket");
}
#endif

/* Set the offload flags to be like a typical ethernet device */
static void set_device_offload_flags(struct local_netdev *netdev)
{
#ifdef linux
	u32 offload = TUN_F_CSUM | TUN_F_TSO4 | TUN_F_TSO6 | TUN_F_TSO_ECN;

	if (ioctl(netdev->tun_fd, TUNSETOFFLOAD, offload) != 0)
		die_perror("TUNSETOFFLOAD");
	/* Linux 3.18 doesn't support TUN_F_UFO. So try and ignore... */
	offload = TUN_F_UFO;
	ioctl(netdev->tun_fd, TUNSETOFFLOAD, offload);
#endif
}

#if !defined(__APPLE__)
/* Bring up the device */
static void bring_up_device(struct local_netdev *netdev)
{
	struct ifreq ifr;

	assert(strlen(netdev->name) < IFNAMSIZ);
	memset(&ifr, 0, sizeof(ifr));
	if (strlen(netdev->name) < IFNAMSIZ)
		strcpy(ifr.ifr_name, netdev->name);
	else
		die("interface name %s too long.\n", netdev->name);
	if (ioctl(netdev->ipv4_control_fd, SIOCGIFFLAGS, &ifr) < 0)
		die_perror("SIOCGIFFLAGS");
	ifr.ifr_flags |= IFF_UP | IFF_RUNNING;
	if (ioctl(netdev->ipv4_control_fd, SIOCSIFFLAGS, &ifr) < 0)
		die_perror("SIOCSIFFLAGS");
}
#endif

/* Route traffic destined for our remote IP through this device */
static void route_traffic_to_device(struct config *config,
				    struct local_netdev *netdev)
{
	char *route_command = NULL;
#if defined(linux)
	asprintf(&route_command,
		 "ip route del %s > /dev/null 2>&1 ; "
		 "ip route add %s dev %s via %s > /dev/null 2>&1",
		 config->live_remote_prefix_string,
		 config->live_remote_prefix_string,
		 netdev->name,
		 config->live_gateway_ip_string);
#else
	if (config->wire_protocol == AF_INET) {
		asprintf(&route_command,
			 "route delete %s > /dev/null 2>&1 ; "
			 "route add %s %s > /dev/null",
			 config->live_remote_prefix_string,
			 config->live_remote_prefix_string,
			 config->live_gateway_ip_string);
	} else if (config->wire_protocol == AF_INET6) {
		asprintf(&route_command,
			 "route delete -inet6 %s > /dev/null 2>&1 ; "
			 "route add -inet6 %s %s > /dev/null",
			 config->live_remote_prefix_string,
			 config->live_remote_prefix_string,
			 config->live_gateway_ip_string);
	} else {
		assert(!"bad wire protocol");
	}
#endif /* defined(linux) */
	int result = system(route_command);
	if ((result == -1) || (WEXITSTATUS(result) != 0)) {
		die("error executing route command '%s'\n",
		    route_command);
	}
	free(route_command);
}

struct netdev *local_netdev_new(struct config *config)
{
	struct local_netdev *netdev = calloc(1, sizeof(struct local_netdev));

	netdev->netdev.ops = &local_netdev_ops;

	cleanup_old_device(config, netdev);

	check_remote_address(config, netdev);
	create_device(config, netdev);
	set_device_offload_flags(netdev);
#if !defined(__APPLE__)
	bring_up_device(netdev);
#endif

	net_setup_dev_address(netdev->name,
			      &config->live_local_ip,
			      config->live_prefix_len,
			      &config->live_gateway_ip);

	route_traffic_to_device(config, netdev);
	netdev->psock = packet_socket_new(netdev->name);
	/* Make sure we only see packets from the machine under test. */
	packet_socket_set_filter(netdev->psock,
				 NULL,
				 &config->live_local_ip);  /* client IP */

	return (struct netdev *)netdev;
}

static void local_netdev_free(struct netdev *a_netdev)
{
	struct local_netdev *netdev = to_local_netdev(a_netdev);

	if (netdev->psock)
		packet_socket_free(netdev->psock);
	if (netdev->tun_fd >= 0) {
		close(netdev->tun_fd);
#if defined(__FreeBSD__) || defined(__OpenBSD__) || defined(__NetBSD__)
		if ((netdev->name != NULL) && !netdev->persistent) {
			char *cleanup_command = NULL;

			asprintf(&cleanup_command,
			         "/sbin/ifconfig %s destroy > /dev/null 2>&1",
			         netdev->name);
			system(cleanup_command);
			free(cleanup_command);
		}
#endif
	}
	if (netdev->ipv4_control_fd >= 0)
		close(netdev->ipv4_control_fd);
	if (netdev->ipv6_control_fd >= 0)
		close(netdev->ipv6_control_fd);
	if (netdev->name != NULL)
		free(netdev->name);
	memset(netdev, 0, sizeof(*netdev));  /* paranoia to help catch bugs */
	free(netdev);
}

#if defined(__FreeBSD__) || defined(__OpenBSD__) || defined(__NetBSD__) || defined(__APPLE__)
/* According to `man 4 tun` on OpenBSD: "Each packet read or written
 * is prefixed with a tunnel header consisting of a 4-byte network
 * byte order integer containing the address family in the case of
 * layer 3 tunneling." Similarly, on FreeBSD and NetBSD one must use
 * ioctl(TUNSIFHEAD) and prepend an address family, in order to be
 * able to send IPv6 packets (otherwise FreeBSD and NetBSD assume the
 * packets are IPv4).
 */
static void bsd_tun_write(struct local_netdev *netdev,
			  struct packet *packet)
{
	int address_family = htonl(packet_address_family(packet));
	struct iovec vector[2] = {
		{ &address_family, sizeof(address_family) },
		{ packet_start(packet), packet->ip_bytes }
	};

	if (writev(netdev->tun_fd, vector, ARRAY_SIZE(vector)) < 0)
		die_perror("BSD tun write()");
}
#endif /* defined(__FreeBSD__) || defined(__OpenBSD__) || defined(__NetBSD__) || defined(__APPLE__) */

#ifdef linux
static void linux_tun_write(struct local_netdev *netdev,
			    struct packet *packet)
{
	if (write(netdev->tun_fd, packet_start(packet), packet->ip_bytes) < 0)
		die_perror("Linux tun write()");
}
#endif  /* linux */

static int local_netdev_send(struct netdev *a_netdev,
			     struct packet *packet)
{
	struct local_netdev *netdev = to_local_netdev(a_netdev);

	assert(packet->ip_bytes > 0);
	/* We do IPv4 and IPv6 */
	assert(packet->ipv4 || packet->ipv6);
	/* We only do SCTP, TCP, UDP, UDPLite and ICMP */
	assert(packet->sctp || packet->tcp || packet->udp || packet->udplite ||
	       packet->icmpv4 || packet->icmpv6);

	DEBUGP("local_netdev_send\n");

#if defined(__FreeBSD__) || defined(__OpenBSD__) || defined(__NetBSD__) || defined(__APPLE__)
	bsd_tun_write(netdev, packet);
#endif /* defined(__FreeBSD__) || defined(__OpenBSD__) || defined(__NetBSD__) || defined(__APPLE__) */

#ifdef linux
	linux_tun_write(netdev, packet);
#endif  /* linux */

	return STATUS_OK;
}

/* Read the given number of packets out of the tun device. We read
 * these packets so that the kernel can exercise its normal code paths
 * for packet transmit completion, since this code path may feed back
 * to TCP behavior; e.g., see the Linux patch "tcp: avoid retransmits
 * of TCP packets hanging in host queues".  We don't need to actually
 * need the packet contents, but on Linux we need to read at least 1
 * byte of packet data to consume the packet.
 */
static void local_netdev_read_queue(struct local_netdev *netdev,
				    int num_packets)
{
	char buf[1];
	int i = 0, in_bytes = 0;

	for (i = 0; i < num_packets; ++i) {
		in_bytes = read(netdev->tun_fd, buf, sizeof(buf));
		assert(in_bytes <= (int)sizeof(buf));

		if (in_bytes < 0) {
			if (errno == EINTR)
				continue;
			else
				die_perror("tun read()");
		}
	}
}

static int local_netdev_receive(struct netdev *a_netdev, u8 udp_encaps,
				struct packet **packet, char **error)
{
	struct local_netdev *netdev = to_local_netdev(a_netdev);
	int status = STATUS_ERR;
	int num_packets = 0;

	DEBUGP("local_netdev_receive\n");

	status = netdev_receive_loop(netdev->psock, DIRECTION_OUTBOUND,
				     udp_encaps,packet, &num_packets, error);
	local_netdev_read_queue(netdev, num_packets);
	return status;
}

int netdev_receive_loop(struct packet_socket *psock,
			enum direction_t direction,
			u8 udp_encaps,
			struct packet **packet,
			int *num_packets,
			char **error)
{
	u16 ether_type;

	assert(*packet == NULL);	/* should be no packet yet */

	*num_packets = 0;
	while (1) {
		int in_bytes = 0;
		enum packet_parse_result_t result;

		*packet = packet_new(PACKET_READ_BYTES);

		/* Sniff the next outbound packet from the kernel under test. */
		if (packet_socket_receive(psock, direction, &ether_type,
					  *packet, &in_bytes))
			continue;

		++*num_packets;
		result = parse_packet(*packet, in_bytes, ether_type, udp_encaps,
				      error);

		if (result == PACKET_OK)
			return STATUS_OK;

		packet_free(*packet);
		*packet = NULL;

		if (result == PACKET_BAD)
			return STATUS_ERR;

		DEBUGP("parse_result:%d; error parsing packet: %s\n",
		       result, *error);
	}

	assert(!"should not be reached");
	return STATUS_ERR;	/* not reached */
}

struct netdev_ops local_netdev_ops = {
	.free = local_netdev_free,
	.send = local_netdev_send,
	.receive = local_netdev_receive,
};
