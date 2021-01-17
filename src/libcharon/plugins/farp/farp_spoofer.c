/*
 * Copyright (C) 2010 Martin Willi
 * Copyright (C) 2010 revosec AG
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the
 * Free Software Foundation; either version 2 of the License, or (at your
 * option) any later version.  See <http://www.fsf.org/copyleft/gpl.txt>.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
 * or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License
 * for more details.
 */
/*
 * For the Apple BPF implementation.
 *
 * Copyright (C) 2020 Dan James <sddj@me.com>
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 */
#include "farp_spoofer.h"

#include <errno.h>
#include <unistd.h>
#if !defined(__APPLE__) && !defined(__FreeBSD__)
#include <sys/socket.h>
#include <linux/if_arp.h>
#include <linux/if_ether.h>
#include <linux/filter.h>
#else
#include <fcntl.h>
#include <ifaddrs.h>
#include <net/bpf.h>
#include <net/ethernet.h>
#include <net/if.h>
#include <net/if_arp.h>
#include <net/if_dl.h>
#endif /* !defined(__APPLE__) && !defined(__FreeBSD__) */
#include <sys/ioctl.h>

#include <daemon.h>
#include <threading/thread.h>
#include <processing/jobs/callback_job.h>

typedef struct private_farp_spoofer_t private_farp_spoofer_t;

/**
 * Private data of an farp_spoofer_t object.
 */
struct private_farp_spoofer_t {

	/**
	 * Public farp_spoofer_t interface.
	 */
	farp_spoofer_t public;

	/**
	 * Listener that knows active addresses
	 */
	farp_listener_t *listener;

#if!defined(__APPLE__) && !defined(__FreeBSD__)
	/**
	 * RAW socket for ARP requests
	 */
	int skt;
#else
	/**
	 * Linked list of interface handlers
	 */
	linked_list_t *handlers;
#endif /* !defined(__APPLE__) && !defined(__FreeBSD__) */
};

/**
 * IP over Ethernet ARP message
 */
typedef struct __attribute__((packed)) {
	uint16_t hardware_type;
	uint16_t protocol_type;
	uint8_t hardware_size;
	uint8_t protocol_size;
	uint16_t opcode;
	uint8_t sender_mac[6];
	uint8_t sender_ip[4];
	uint8_t target_mac[6];
	uint8_t target_ip[4];
} arp_t;

#if !defined(__APPLE__) && !defined(__FreeBSD__)
/**
 * Send faked ARP response
 */
static void send_arp(private_farp_spoofer_t *this,
					 arp_t *arp, struct sockaddr_ll *addr)
{
	struct ifreq req;
	char tmp[4];

	req.ifr_ifindex = addr->sll_ifindex;
	if (ioctl(this->skt, SIOCGIFNAME, &req) == 0 &&
		ioctl(this->skt, SIOCGIFHWADDR, &req) == 0 &&
		req.ifr_hwaddr.sa_family == ARPHRD_ETHER)
	{
		memcpy(arp->target_mac, arp->sender_mac, 6);
		memcpy(arp->sender_mac, req.ifr_hwaddr.sa_data, 6);

		memcpy(tmp, arp->sender_ip, 4);
		memcpy(arp->sender_ip, arp->target_ip, 4);
		memcpy(arp->target_ip, tmp, 4);

		arp->opcode = htons(ARPOP_REPLY);

		sendto(this->skt, arp, sizeof(*arp), 0,
			   (struct sockaddr*)addr, sizeof(*addr));
	}
}

/**
 * ARP request receiving
 */
static bool receive_arp(private_farp_spoofer_t *this)
{
	struct sockaddr_ll addr;
	socklen_t addr_len = sizeof(addr);
	arp_t arp;
	ssize_t len;
	host_t *local, *remote;

	len = recvfrom(this->skt, &arp, sizeof(arp), MSG_DONTWAIT,
				   (struct sockaddr*)&addr, &addr_len);
	if (len == sizeof(arp))
	{
		local = host_create_from_chunk(AF_INET,
									chunk_create((char*)&arp.sender_ip, 4), 0);
		remote = host_create_from_chunk(AF_INET,
									chunk_create((char*)&arp.target_ip, 4), 0);
		if (this->listener->has_tunnel(this->listener, local, remote))
		{
			send_arp(this, &arp, &addr);
		}
		local->destroy(local);
		remote->destroy(remote);
	}

	return TRUE;
}

METHOD(farp_spoofer_t, destroy, void,
	private_farp_spoofer_t *this)
{
	lib->watcher->remove(lib->watcher, this->skt);
	close(this->skt);
	free(this);
}

/**
 * See header
 */
farp_spoofer_t *farp_spoofer_create(farp_listener_t *listener)
{
	private_farp_spoofer_t *this;
	struct sock_filter arp_request_filter_code[] = {
		BPF_STMT(BPF_LD+BPF_H+BPF_ABS, offsetof(arp_t, protocol_type)),
		BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, ETH_P_IP, 0, 9),
		BPF_STMT(BPF_LD+BPF_B+BPF_ABS, offsetof(arp_t, hardware_size)),
		BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, 6, 0, 7),
		BPF_STMT(BPF_LD+BPF_B+BPF_ABS, offsetof(arp_t, protocol_size)),
		BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, 4, 0, 5),
		BPF_STMT(BPF_LD+BPF_H+BPF_ABS, offsetof(arp_t, opcode)),
		BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, ARPOP_REQUEST, 0, 3),
		BPF_STMT(BPF_LD+BPF_W+BPF_LEN, 0),
		BPF_JUMP(BPF_JMP+BPF_JGE+BPF_K, sizeof(arp_t), 0, 1),
		BPF_STMT(BPF_RET+BPF_K, sizeof(arp_t)),
		BPF_STMT(BPF_RET+BPF_K, 0),
	};
	struct sock_fprog arp_request_filter = {
		sizeof(arp_request_filter_code) / sizeof(struct sock_filter),
		arp_request_filter_code,
	};

	INIT(this,
		.public = {
			.destroy = _destroy,
		},
		.listener = listener,
	);

	this->skt = socket(AF_PACKET, SOCK_DGRAM, htons(ETH_P_ARP));
	if (this->skt == -1)
	{
		DBG1(DBG_NET, "opening ARP packet socket failed: %s", strerror(errno));
		free(this);
		return NULL;
	}

	if (setsockopt(this->skt, SOL_SOCKET, SO_ATTACH_FILTER,
				   &arp_request_filter, sizeof(arp_request_filter)) < 0)
	{
		DBG1(DBG_NET, "installing ARP packet filter failed: %s",
			 strerror(errno));
		close(this->skt);
		free(this);
		return NULL;
	}

	lib->watcher->add(lib->watcher, this->skt, WATCHER_READ,
					  (watcher_cb_t)receive_arp, this);

	return &this->public;
}

#else

/**
 * A handler is required for each interface.
 */
struct farp_handler_t
{
	/**
	 * Reference to the private farp spoofer.
	 */
	private_farp_spoofer_t *this;
	/**
	 * The name of the interface to be handled.
	 */
	char* name;
	/**
	 * The IPv4 address of this interface.
	 */
	u_int8_t ipv4[4];
	/**
	 * The Ethernet mac of this interface.
	 */
	u_int8_t mac[6];
	/**
	 * The BPF file descriptor for this interface.
	 */
	int fd;
	/**
	 * The BPF packet buffer length as read from the BPF fd.
	 */
	size_t buflen;
	/**
	 * An allocated buffer for receiving packets from BPF.
	 */
	u_int8_t* bufdat;
};
typedef struct farp_handler_t farp_handler_t;

/**
 * An Ethernet frame for an ARP packet.
 */
struct frame_t
{
	struct ether_header e;
	arp_t a;
};
typedef struct frame_t frame_t;

/**
 * Find and open an available BPF device.
 */
static int
bpf_open()
{
	static int no_cloning_bpf = 0;
	/* Enough space for: /dev/bpf000\0 */
	char device[12];
	int n = no_cloning_bpf ? 0 : -1;
	int fd;

	do
	{
		if (n < 0)
		{
			snprintf(device, sizeof(device), "/dev/bpf");
		}
		else
		{
			snprintf(device, sizeof(device), "/dev/bpf%d", n);
		}

		fd = open(device, O_RDWR);

		if (n++ < 0 && fd < 0 && errno == ENOENT)
		{
			no_cloning_bpf = 1;
			errno = EBUSY;
		}
	} while (fd < 0 && errno == EBUSY && n < 1000);

	return fd;
}

/**
 * Free resources used by a handler.
 */
static void
handler_free(farp_handler_t* h)
{
	if (h->fd >= 0)
	{
		lib->watcher->remove(lib->watcher, h->fd);
		close(h->fd);
		h->fd = -1;
	}
	if (h->bufdat)
	{
		free(h->bufdat);
		h->bufdat = NULL;
	}
	if (h->name)
	{
		free(h->name);
		h->name = NULL;
	}
	h->this = NULL;
	free(h);
}

/**
 * Find the handler for the named interface, creating one if needed.
 */
static farp_handler_t*
handler_find(private_farp_spoofer_t* this, char* interface_name)
{
	farp_handler_t *i = NULL;
	enumerator_t *enumerator;

	enumerator = this->handlers->create_enumerator(this->handlers);
	while (enumerator->enumerate(enumerator, &i)
			&& strcmp(i->name, interface_name) != 0)
	{
		i = NULL;
	}
	enumerator->destroy(enumerator);

	if (!i)
	{
		i = malloc_thing(farp_handler_t);
		if (i)
		{
			memset(i, 0, sizeof(farp_handler_t));
			i->this = this;
			i->name = strdup(interface_name);
			if (i->name)
			{
				this->handlers->insert_last(this->handlers, i);
			}
			else
			{
				free(i);
				i = NULL;
			}
		}
	}

	return i;
}

/**
 * Send an ARP response for the given ARP request.
 */
static void
handler_send(farp_handler_t* h, arp_t* arpreq)
{
	frame_t frame;
	ssize_t n;

	memcpy(frame.e.ether_dhost, arpreq->sender_mac, sizeof(arpreq->sender_mac));
	memcpy(frame.e.ether_shost, h->mac, sizeof(h->mac));
	frame.e.ether_type = htons(ETHERTYPE_ARP);

	frame.a.hardware_type = htons(1);
	frame.a.protocol_type = htons(ETHERTYPE_IP);
	frame.a.hardware_size = arpreq->hardware_size;
	frame.a.protocol_size = arpreq->protocol_size;
	frame.a.opcode = htons(ARPOP_REPLY);
	memcpy(frame.a.sender_mac, h->mac, sizeof(h->mac));
	memcpy(frame.a.sender_ip, arpreq->target_ip, sizeof(arpreq->target_ip));
	memcpy(frame.a.target_mac, arpreq->sender_mac, sizeof(arpreq->sender_mac));
	memcpy(frame.a.target_ip, arpreq->sender_ip, sizeof(arpreq->sender_ip));

	DBG1(DBG_NET, "farp %s", h->name);
	DBG1(DBG_NET, "  ether destination %02x.%02x.%02x.%02x.%02x.%02x",
	     frame.e.ether_dhost[0], frame.e.ether_dhost[1],
		 frame.e.ether_dhost[2], frame.e.ether_dhost[3],
		 frame.e.ether_dhost[4], frame.e.ether_dhost[5]);
	DBG1(DBG_NET, "  ether source      %02x.%02x.%02x.%02x.%02x.%02x",
	     frame.e.ether_shost[0], frame.e.ether_shost[1],
		 frame.e.ether_shost[2], frame.e.ether_shost[3],
		 frame.e.ether_shost[4], frame.e.ether_shost[5]);
	DBG1(DBG_NET, "  arp ht=%d pt=%d hs=%d ps=%d op=%d",
	     ntohs(frame.a.hardware_type), ntohs(frame.a.protocol_type),
	     frame.a.hardware_size, frame.a.protocol_size, ntohs(frame.a.opcode));
	DBG1(DBG_NET, "  arp sender %02x.%02x.%02x.%02x.%02x.%02x %d.%d.%d.%d",
	     frame.a.sender_mac[0], frame.a.sender_mac[1], frame.a.sender_mac[2],
	     frame.a.sender_mac[3], frame.a.sender_mac[4], frame.a.sender_mac[5],
	     frame.a.sender_ip[0], frame.a.sender_ip[1],
		 frame.a.sender_ip[2], frame.a.sender_ip[3]);
	DBG1(DBG_NET, "  arp target %02x.%02x.%02x.%02x.%02x.%02x %d.%d.%d.%d",
	     frame.a.target_mac[0], frame.a.target_mac[1], frame.a.target_mac[2],
	     frame.a.target_mac[3], frame.a.target_mac[4], frame.a.target_mac[5],
	     frame.a.target_ip[0], frame.a.target_ip[1],
		 frame.a.target_ip[2], frame.a.target_ip[3]);

	n = write(h->fd, &frame, sizeof(frame));
	if (n != sizeof(frame))
	{
		DBG1(DBG_NET, "arp reply failed: code=%d msg=%s", n, strerror(errno));
	}
}

/**
 * Receive and examine the available ARP requests. If a tunnel exists, send an
 * ARP response back out the same interface.
 */
static bool
handler_onarp(farp_handler_t* h)
{
	u_int8_t* p = h->bufdat;
	ssize_t n = read(h->fd, h->bufdat, h->buflen);
	struct bpf_hdr* bh;
	struct ether_header* eh;
	arp_t* a;
	host_t* lcl;
	host_t* rmt;

	if (n <= 0)
	{
		DBG1(DBG_NET, "farp %s closed: code=%d msg=%s", h->name, n,
			 strerror(errno));
		return -1;
	}

	while (p < h->bufdat + n)
	{
		bh = (struct bpf_hdr*)p;
		eh = (struct ether_header *)(p + bh->bh_hdrlen);
		a = (arp_t*)(p + bh->bh_hdrlen + sizeof(struct ether_header));
	
		lcl = host_create_from_chunk(AF_INET, chunk_create(a->sender_ip, 4), 0);
		rmt = host_create_from_chunk(AF_INET, chunk_create(a->target_ip, 4), 0);
		if (h->this->listener->has_tunnel(h->this->listener, lcl, rmt))
		{
			DBG1(DBG_NET, "Found tunnel %s %d.%d.%d.%d <-> %d.%d.%d.%d",
			     h->name,
			     a->sender_ip[0], a->sender_ip[1],
				 a->sender_ip[2], a->sender_ip[3],
			     a->target_ip[0], a->target_ip[1],
				 a->target_ip[2], a->target_ip[3]);
			handler_send(h, a);
		/* Noisy, only useful for debugging.
		}
		else
		{
			DBG1(DBG_NET, "No tunnel %s %d.%d.%d.%d <-> %d.%d.%d.%d",
				 h->name,
				 a->sender_ip[0], a->sender_ip[1],
				 a->sender_ip[2], a->sender_ip[3],
				 a->target_ip[0], a->target_ip[1],
				 a->target_ip[2], a->target_ip[3]);
		*/
		}
		rmt->destroy(rmt);
		lcl->destroy(lcl);

		p += BPF_WORDALIGN(bh->bh_hdrlen + bh->bh_caplen);
	}

	return TRUE;
}

/**
 * Create an initialize a BPF handler for interface specified in the farp
 * handler. This entails opening a BPF device, binding it to the interface,
 * setting the packet filter, and allocating a buffer for receiving packets.
 */
static int
setup_handler(private_farp_spoofer_t* this, farp_handler_t* h)
{
	int status;
	struct bpf_insn instructions[] = {
		BPF_STMT(BPF_LD+BPF_W+BPF_LEN, 0),
		BPF_JUMP(BPF_JMP+BPF_JGE+BPF_K,
				 sizeof(struct ether_header) + sizeof(arp_t), 0, 11),
		BPF_STMT(BPF_LD+BPF_H+BPF_ABS,
				 offsetof(struct  ether_header, ether_type)),
		BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, ETHERTYPE_ARP, 0, 9),
		BPF_STMT(BPF_LD+BPF_H+BPF_ABS,
				 sizeof(struct ether_header) + offsetof(arp_t, protocol_type)),
		BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, ETHERTYPE_IP, 0, 7),
		BPF_STMT(BPF_LD+BPF_B+BPF_ABS,
				 sizeof(struct ether_header) + offsetof(arp_t, hardware_size)),
		BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, 6, 0, 5),
		BPF_STMT(BPF_LD+BPF_B+BPF_ABS,
				 sizeof(struct ether_header) + offsetof(arp_t, protocol_size)),
		BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, 4, 0, 3),
		BPF_STMT(BPF_LD+BPF_H+BPF_ABS,
				 sizeof(struct ether_header) + offsetof(arp_t, opcode)),
		BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, ARPOP_REQUEST, 0, 1),
		BPF_STMT(BPF_RET+BPF_K, 14 + sizeof(arp_t)),
		BPF_STMT(BPF_RET+BPF_K, 0)
	};
	u_int32_t disable = 1;
	u_int32_t enable = 1;
	u_int32_t dlt = 0;
	struct bpf_program program;
	struct ifreq req;

	snprintf(req.ifr_name, sizeof(req.ifr_name), "%s", h->name);

	if ((h->fd = bpf_open()) < 0)
	{
		DBG1(DBG_NET, "bpf_open(%s): code=%d msg=%s", h->name, h->fd,
			 strerror(errno));
		return h->fd;
	}

	if ((status = ioctl(h->fd, BIOCSETIF, &req)) < 0)
	{
		DBG1(DBG_NET, "BIOCSETIF(%s): code=%d msg=%s", h->name, status,
			 strerror(errno));
		return status;
	}

	if ((status = ioctl(h->fd, BIOCSHDRCMPLT, &enable)) < 0)
	{
		DBG1(DBG_NET, "BIOCSHDRCMPLT(%s): code=%d msg=%s", h->name, status,
			 strerror(errno));
		return status;
	}

	if ((status = ioctl(h->fd, BIOCSSEESENT, &disable)) < 0)
	{
		DBG1(DBG_NET, "BIOCSSEESENT(%s): code=%d msg=%s", h->name, status,
			 strerror(errno));
		return status;
	}

	if ((status = ioctl(h->fd, BIOCIMMEDIATE, &enable)) < 0)
	{
		DBG1(DBG_NET, "BIOCIMMEDIATE(%s): code=%d msg=%s", h->name, status,
			 strerror(errno));
		return status;
	}

	if ((status = ioctl(h->fd, BIOCGDLT, &dlt)) < 0)
	{
		return status;
	}
	if (dlt != DLT_EN10MB)
	{
		errno = EINVAL;
		DBG1(DBG_NET, "BIOCGDLT(%s): code=%d msg=%s", h->name, -1,
			 strerror(errno));
		return -1;
	}

	program.bf_len = sizeof(instructions) / sizeof(struct bpf_insn);
	program.bf_insns = &instructions[0];

	if ((status = ioctl(h->fd, BIOCSETF, &program)) < 0)
	{
		DBG1(DBG_NET, "BIOCSETF(%s): code=%d msg=%s", h->name, status,
			 strerror(errno));
		return status;
	}

	if ((status = ioctl(h->fd, BIOCGBLEN, &h->buflen)) < 0)
	{
		DBG1(DBG_NET, "BIOCGBLEN(%s): code=%d msg=%s", h->name, status,
			 strerror(errno));
		return status;
	}

	if ((h->bufdat = malloc(h->buflen)) == NULL)
	{
		DBG1(DBG_NET, "malloc(%s, %lu): failed", h->name, h->buflen);
		errno = ENOMEM;
		return -1;
	}

	lib->watcher->add(lib->watcher, h->fd, WATCHER_READ,
					  (watcher_cb_t) handler_onarp, h);

	return 0;
}

/**
 * Create a handler for each BPF capable interface. The interface must have an
 * Ethernet MAC address, an IPv4 address, and use an EN10MB data link layer.
 */
static int
setup_handlers(private_farp_spoofer_t* this)
{
	int status;
	struct ifaddrs* ifas;
	struct ifaddrs* ifa;
	struct sockaddr_dl* dl;
	struct sockaddr_in* in;
	farp_handler_t* h;
	enumerator_t *enumerator;

	if ((status = getifaddrs(&ifas)) < 0)
	{
		DBG1(DBG_NET, "farp cannot find interfaces: code=%d msg=%s", status,
			 strerror(errno));
		return -1;
	}
	for (ifa = ifas; ifa != NULL; ifa = ifa->ifa_next)
	{
		switch (ifa->ifa_addr->sa_family)
		{
		case AF_LINK:
			dl = (struct sockaddr_dl*)ifa->ifa_addr;
			if (dl->sdl_alen == 6)
			{
				h = handler_find(this, ifa->ifa_name);
				if (h)
				{
					memcpy(h->mac, &dl->sdl_data[dl->sdl_nlen], dl->sdl_alen);
					h->fd++;
				}
			}
			break;
		case AF_INET:
			in = (struct sockaddr_in*)ifa->ifa_addr;
			if (in->sin_addr.s_addr != 0)
			{
				h = handler_find(this, ifa->ifa_name);
				if (h)
				{
					memcpy(h->ipv4, &in->sin_addr.s_addr,
						   sizeof(in->sin_addr.s_addr));
					h->fd++;
				}
			}
			break;
		default:
			break;
		}
	}
	freeifaddrs(ifas);

	enumerator = this->handlers->create_enumerator(this->handlers);
	while (enumerator->enumerate(enumerator, &h))
	{
		if (h->fd < 2)
		{
			h->fd = -1;
			this->handlers->remove_at(this->handlers, enumerator);
			handler_free(h);
		}
		else if (setup_handler(this, h) < 0)
		{
			this->handlers->remove_at(this->handlers, enumerator);
			handler_free(h);
		}
		else
		{
			DBG1(DBG_NET, "Listening for ARP requests on %s ipv4=%d.%d.%d.%d"
				 " ether=%02x.%02x.%02x.%02x.%02x.%02x",
			     h->name, h->ipv4[0], h->ipv4[1], h->ipv4[2], h->ipv4[3],
			     h->mac[0], h->mac[1], h->mac[2],
				 h->mac[3], h->mac[4], h->mac[5]);
		}
	}
	enumerator->destroy(enumerator);

	return this->handlers->get_count(this->handlers) > 0 ? 0 : -1;
}

/**
 * Cleanup the handlers used by this plugin.
 */
METHOD(farp_spoofer_t, destroy, void, private_farp_spoofer_t *this)
{
	farp_handler_t* h;
	enumerator_t *enumerator;

	enumerator = this->handlers->create_enumerator(this->handlers);
	while (enumerator->enumerate(enumerator, &h))
	{
		handler_free(h);
	}
	enumerator->destroy(enumerator);
	this->handlers->destroy(this->handlers);
	free(this);
}

/**
 * See header
 */
farp_spoofer_t *farp_spoofer_create(farp_listener_t *listener)
{
	private_farp_spoofer_t *this;

	INIT(this,
		.public = {
			.destroy = _destroy,
		},
		.listener = listener,
		.handlers = linked_list_create(),
	);

	if (setup_handlers(this) < 0)
	{
		this->public.destroy(&this->public);
		return NULL;
	}

	return &this->public;
}

#endif /* !defined(__APPLE__) && !defined(__FreeBSD__) */
