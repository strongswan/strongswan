#include "socket_vpp_socket.h"

#include <daemon.h>
#include <errno.h>
#include <ip_packet.h>
#include <ipsec.h>
#include <kernel_vpp_shared.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <threading/thread.h>
#include <unistd.h>
#include <vlibapi/api.h>
#include <vlibmemory/api.h>
#include <vpp/api/vpe_msg_enum.h>

#define vl_typedefs
#include <vpp/api/vpe_all_api_h.h>
#undef vl_typedefs

#define READ_PATH "/tmp/strongswan-uds-socket"

typedef struct private_socket_vpp_socket_t private_socket_vpp_socket_t;
typedef struct vpp_packetdesc_t vpp_packetdesc_t;
typedef struct ether_header_t ether_header_t;

/**
 * Private data of an socket_t object
 */
struct private_socket_vpp_socket_t {

	/**
	 * public functions
	 */
	socket_vpp_socket_t public;

	/**
	 * Configured IKEv2 port
	 */
	uint16_t port;

	/**
	 * Configured port for NAT-T
	 */
	uint16_t natt;

	/**
	 * maximum packet size to receive
	 */
	int max_packet;

	/**
	 * socket
	 */
	int sock;

	/**
	 * Write socket
	 */
	struct sockaddr_un write_addr;

	/**
	 * Read socket
	 */
	struct sockaddr_un read_addr;

	vac_t *vac;
};

/**
 * VPP punt socket action
 */
enum {
	PUNT_L2 = 0,
	PUNT_IP4_ROUTED,
	PUNT_IP6_ROUTED,
};

/**
 * VPP punt socket packet descriptor header
 */
struct vpp_packetdesc_t {
	/** RX or TX interface */
	u_int sw_if_index;
	/** action */
	int action;
} __attribute__((packed));

/**
 * Ethernet header
 */
struct ether_header_t {
	/** src MAC */
	uint8_t src[6];
	/** dst MAC */
	uint8_t dst[6];
	/** EtherType */
	uint16_t type;
} __attribute__((packed));

METHOD(socket_t, receiver, status_t, private_socket_vpp_socket_t *this,
	   packet_t **out)
{
	char buf[this->max_packet];
	packet_t *pkt;
	host_t *src = NULL, *dst = NULL;
	int bytes_read = 0;
	bool old;
	struct pollfd pfd[] = {
		{
			.fd = this->sock,
			.events = POLLIN,
		},
	};

	NDBG2("waiting for data on vpp sockets");
	old = thread_cancelability(TRUE);
	if (poll(pfd, countof(pfd), -1) <= 0)
	{
		thread_cancelability(old);
		NDBG1("poll failed");
		return FAILED;
	}
	thread_cancelability(old);

	if (pfd[0].revents & POLLIN)
	{
		struct msghdr msg;
		struct iovec iov[3];
		vpp_packetdesc_t packetdesc;
		ether_header_t eh;
		ip_packet_t *packet;
		chunk_t raw, data;

		iov[0].iov_base = &packetdesc;
		iov[0].iov_len = sizeof(packetdesc);
		iov[1].iov_base = &eh;
		iov[1].iov_len = sizeof(eh);
		iov[2].iov_base = buf;
		iov[2].iov_len = this->max_packet;
		msg.msg_iov = iov;
		msg.msg_iovlen = 3;
		msg.msg_name = &this->read_addr;
		msg.msg_namelen = sizeof(this->read_addr);
		msg.msg_control = 0;
		msg.msg_controllen = 0;
		msg.msg_flags = 0;

		bytes_read = recvmsg(pfd[0].fd, &msg, 0);
		if (bytes_read < 0)
		{
			NDBG1("error reading vpp socket: %s", strerror(errno));
			return FAILED;
		}
		NDBG3("received vpp packet %b", buf, bytes_read);

		raw = chunk_create(buf, bytes_read);
		packet = ip_packet_create(raw);
		if (!packet)
		{
			NDBG1("invalid IP packet read from vpp socket");
		}
		src = packet->get_source(packet);
		dst = packet->get_destination(packet);
		pkt = packet_create();
		pkt->set_source(pkt, src);
		pkt->set_destination(pkt, dst);
		NDBG2("received vpp packet: from %#H to %#H", src, dst);
		data = packet->get_payload(packet);
		/* remove UDP header */
		data = chunk_skip(data, 8);
		pkt->set_data(pkt, chunk_clone(data));
	}
	else
	{
		return FAILED;
	}

	*out = pkt;
	return SUCCESS;
}

METHOD(socket_t, sender, status_t, private_socket_vpp_socket_t *this,
	   packet_t *packet)
{
	struct msghdr msg;
	struct iovec iov[2];
	vpp_packetdesc_t packetdesc;
	ssize_t bytes_sent;
	chunk_t data, raw;
	host_t *src, *dst;
	int family;
	ip_packet_t *ip_packet;

	src = packet->get_source(packet);
	dst = packet->get_destination(packet);
	data = packet->get_data(packet);
	if (!src->get_port(src))
	{
		src->set_port(src, this->port);
	}

	NDBG2("sending vpp packet: from %#H to %#H", src, dst);

	family = dst->get_family(dst);

	packetdesc.sw_if_index = 0;
	if (family == AF_INET)
	{
		packetdesc.action = PUNT_IP4_ROUTED;
	}
	else
	{
		packetdesc.action = PUNT_IP6_ROUTED;
	}

	ip_packet = ip_packet_create_udp_from_data(src, dst, data);
	if (!ip_packet)
	{
		NDBG1("create IP packet failed");
		return FAILED;
	}
	raw = ip_packet->get_encoding(ip_packet);
	memset(&msg, 0, sizeof(struct msghdr));
	iov[0].iov_base = &packetdesc;
	iov[0].iov_len = sizeof(packetdesc);
	iov[1].iov_base = raw.ptr;
	iov[1].iov_len = raw.len;
	msg.msg_iov = iov;
	msg.msg_iovlen = 2;
	msg.msg_name = &this->write_addr;
	msg.msg_namelen = sizeof(this->write_addr);
	msg.msg_flags = 0;
	msg.msg_control = NULL;
	msg.msg_controllen = 0;

	bytes_sent = sendmsg(this->sock, &msg, 0);
	if (bytes_sent < 0)
	{
		NDBG1("error writing to vpp socket: %s", strerror(errno));
		return FAILED;
	}

	return SUCCESS;
}

METHOD(socket_t, get_port, uint16_t, private_socket_vpp_socket_t *this,
	   bool nat)
{
	return this->port;
}

METHOD(socket_t, supported_families, socket_family_t,
	   private_socket_vpp_socket_t *this)
{
	return SOCKET_FAMILY_BOTH;
}

METHOD(socket_t, destroy, void, private_socket_vpp_socket_t *this)
{
	close(this->sock);
	unlink(this->read_addr.sun_path);
	free(this);
}

static int
register_punt_port(private_socket_vpp_socket_t *this, uint16_t port,
				   char *read_path)
{
	char *out;
	int out_len;
	vl_api_punt_socket_register_t *mp;
	vl_api_punt_socket_register_reply_t *rmp;

	/* Register IPv4 punt socket for IKEv2 port in VPP */
	mp = vl_msg_api_alloc_zero(sizeof(*mp));
	mp->_vl_msg_id = htons(VL_API_PUNT_SOCKET_REGISTER);
	mp->header_version = htonl(1);

	mp->punt.type = PUNT_API_TYPE_L4;
	vl_api_punt_type_t_endian(&mp->punt.type);

	mp->punt.punt.l4.af = ADDRESS_IP4;
	vl_api_address_family_t_endian(&mp->punt.punt.l4.af);

	mp->punt.punt.l4.protocol = IP_API_PROTO_UDP;
	vl_api_ip_proto_t_endian(&mp->punt.punt.l4.protocol);

	mp->punt.punt.l4.port = htons(port);
	strncpy(mp->pathname, read_path, sizeof(mp->pathname));
	if (this->vac->send(this->vac, (char *)mp, sizeof(*mp), &out, &out_len))
	{
		LDBG1("send register vpp ip4 punt socket fail on port %d", port);
		return -1;
	}
	rmp = (void *)out;
	if (rmp->retval)
	{
		LDBG1("register vpp ip4 punt socket fail on port %d with rv: %E", port,
			  rmp->retval);
		return -1;
	}

	/* Register IPv6 punt socket for IKEv2 port in VPP */
	mp->punt.punt.l4.af = ADDRESS_IP6;
	vl_api_address_family_t_endian(&mp->punt.punt.l4.af);

	if (this->vac->send(this->vac, (char *)mp, sizeof(*mp), &out, &out_len))
	{
		LDBG1("send register vpp ip6 punt socket fail on port %d", port);
		return -1;
	}
	rmp = (void *)out;
	if (rmp->retval)
	{
		LDBG1("register vpp ip6 punt socket fail on port %d with rv: %E", port,
			  rmp->retval);
		return -1;
	}

	/* cheat, make sure pathname is NUL terminated */
	rmp->pathname[sizeof(rmp->pathname) - 1] = 0;
	LDBG3("Registered vpp punt socket on port %d successfully with "
		  "returned "
		  "write path: %s",
		  port, rmp->pathname);

	this->sock = socket(AF_UNIX, SOCK_DGRAM, 0);
	if (this->sock < 0)
	{
		LDBG1("opening vpp socket failed: %m");
		return -1;
	}

	/* There should be only one write path returned by VPP */
	if (this->write_addr.sun_family == 0)
	{
		strncpy(this->write_addr.sun_path, rmp->pathname,
				sizeof(this->write_addr.sun_path));
		this->write_addr.sun_family = AF_UNIX;
	}
	else if (strncmp(this->write_addr.sun_path, rmp->pathname,
					 sizeof(this->write_addr.sun_path)) != 0)
	{
		LDBG1("More than one write path returned by VPP. Previous one is: %s, "
			  "now is: %s",
			  this->write_addr.sun_path, rmp->pathname);
		return -1;
	}

	return 0;
}

/*
 * See header for description
 */
socket_vpp_socket_t *
socket_vpp_socket_create()
{
	private_socket_vpp_socket_t *this;
	char *read_path;

	INIT(this,
		 .public =
			 {
				 .socket =
					 {
						 .send = _sender,
						 .receive = _receiver,
						 .get_port = _get_port,
						 .supported_families = _supported_families,
						 .destroy = _destroy,
					 },
			 },
		 .max_packet = lib->settings->get_int(lib->settings, "%s.max_packet",
											  PACKET_MAX_DEFAULT, lib->ns),
		 .port = lib->settings->get_int(lib->settings, "%s.port",
										IKEV2_UDP_PORT, lib->ns),
		 .natt = lib->settings->get_int(lib->settings, "%s.port_nat_t",
										IKEV2_NATT_PORT, lib->ns), );

	this->vac = lib->get(lib, "kernel-vpp-vac");
	if (!this->vac)
	{
		LDBG1("no vac available (plugin missing?)");
	}

	read_path = lib->settings->get_str(
		lib->settings, "%s.plugins.socket-vpp.path", READ_PATH, lib->ns);
	memset(&this->write_addr, 0, sizeof(this->write_addr));

	if (this->port && (register_punt_port(this, this->port, read_path) != 0))
	{
		LDBG1("Register punt port %d fail", this->port);
		return NULL;
	}

	if (this->natt)
	{
		if (this->natt == this->port)
		{
			LDBG1("IKE NAT Port (%d) cannot be the same as IKE Port (%d)",
				  this->natt, this->port);
			return NULL;
		}

		if (register_punt_port(this, this->natt, read_path) != 0)
		{
			LDBG1("Register punt port %d fail", this->port);
			return NULL;
		}
	}

	/* Bind read path */
	memset(&this->read_addr, 0, sizeof(this->read_addr));
	strncpy(this->read_addr.sun_path, read_path,
			sizeof(this->read_addr.sun_path));
	this->read_addr.sun_family = AF_UNIX;
	unlink(this->read_addr.sun_path);
	if (bind(this->sock, (struct sockaddr *)&this->read_addr,
			 sizeof(this->read_addr)) < 0)
	{
		LDBG1("binding vpp read socket failed: %m");
		close(this->sock);
		return NULL;
	}

	LDBG1("registered punt port");
	return &this->public;
}

/*
 * fd.io coding-style-patch-verification: CLANG
 */
