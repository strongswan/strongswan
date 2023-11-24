/*
 * Copyright (C) 2021 Tobias Brunner
 * Copyright (C) 2010 Martin Willi
 *
 * Copyright (C) secunet Security Networks AG
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
 * For the Apple BPF implementation and refactoring packet handling.
 *
 * Copyright (C) 2020 Dan James <sddj@me.com>
 * Copyright (C) 2023 Dan James <sddj@me.com>
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
#include <sys/ioctl.h>

#if !defined(__APPLE__) && !defined(__FreeBSD__)
#include <sys/socket.h>
#include <linux/if_arp.h>
#include <linux/if_ether.h>
#include <linux/filter.h>
#else
#include <net/bpf.h>
#include <net/if_arp.h>
#include <net/if_dl.h>
#endif /* !defined(__APPLE__) && !defined(__FreeBSD__) */

#include <net/ethernet.h>
#include <daemon.h>
#include <pf_handler.h>
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

	/**
	 * RAW socket for ARP requests
	 */
	pf_handler_t *pf_handler;
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
	uint8_t sender_mac[ETHER_ADDR_LEN];
	uint8_t sender_ip[4];
	uint8_t target_mac[ETHER_ADDR_LEN];
	uint8_t target_ip[4];
} arp_t;

#if !defined(__APPLE__) && !defined(__FreeBSD__)
/**
 * Send faked ARP response
 */
static void send_arp(char *if_name, int if_index, chunk_t *mac, int fd,
					 arp_t *arp, host_t *sender, host_t *target)
{
	char tmp[4];
#if DEBUG_LEVEL >= 1
	chunk_t sender_mac = chunk_create((u_char*)arp->sender_mac, ETHER_ADDR_LEN);

	DBG1(DBG_NET, "ARP %H is-at %#B to %H (%#B) on %s",
		 target, mac, sender, &sender_mac, if_name);
#endif

		memcpy(arp->target_mac, arp->sender_mac, 6);
		memcpy(arp->sender_mac, mac->ptr, 6);

		memcpy(tmp, arp->sender_ip, 4);
		memcpy(arp->sender_ip, arp->target_ip, 4);
		memcpy(arp->target_ip, tmp, 4);

		arp->opcode = htons(ARPOP_REPLY);

	struct sockaddr_ll addr = {
		.sll_family = AF_PACKET,
		.sll_protocol = htons(ETH_P_ARP),
		.sll_ifindex = if_index,
		.sll_hatype = ARPHRD_ETHER,
		.sll_pkttype = PACKET_OTHERHOST,
		.sll_halen = ETHER_ADDR_LEN
	};
	memcpy(addr.sll_addr, arp->target_mac, ETHER_ADDR_LEN);

	ssize_t len = sendto(fd, arp, sizeof(*arp), 0,
						 (const struct sockaddr*)&addr, sizeof(addr));
	if (len != sizeof(*arp)) {
		DBG1(DBG_NET, "ARP failed to send response to %H (%#B)"
			 "[fd=%d buf=%p n=%d addr=%p addr_len=%d]: %s",
			 target, mac,
			 fd, arp, sizeof(*arp), &addr, sizeof(addr),
			 strerror(errno));
	}
}

#else /* !defined(__APPLE__) && !defined(__FreeBSD__) */

/**
 * An Ethernet frame for an ARP packet.
 */
struct frame_t {
	struct ether_header e;
	arp_t a;
};

typedef struct frame_t frame_t;

/**
 * Send an ARP response for the given ARP request.
 */
static void send_arp(char *if_name, int if_index, chunk_t *mac, int fd,
					 const arp_t *arpreq, host_t *sender, host_t *target)
{
	frame_t frame;
	ssize_t n;
#if DEBUG_LEVEL >= 1
	chunk_t sender_mac = chunk_create((u_char*)arpreq->sender_mac, ETHER_ADDR_LEN);

	DBG1(DBG_NET, "ARP %H is-at %#B to %H (%#B) on %s",
		 target, mac, sender, &sender_mac, if_name);
#endif

	memcpy(frame.e.ether_dhost, arpreq->sender_mac, ETHER_ADDR_LEN);
	memcpy(frame.e.ether_shost, mac->ptr, ETHER_ADDR_LEN);
	frame.e.ether_type = htons(ETHERTYPE_ARP);

	frame.a.hardware_type = htons(1);
	frame.a.protocol_type = htons(ETHERTYPE_IP);
	frame.a.hardware_size = arpreq->hardware_size;
	frame.a.protocol_size = arpreq->protocol_size;
	frame.a.opcode = htons(ARPOP_REPLY);
	memcpy(frame.a.sender_mac, mac->ptr, ETHER_ADDR_LEN);
	memcpy(frame.a.sender_ip, arpreq->target_ip, sizeof(arpreq->target_ip));
	memcpy(frame.a.target_mac, arpreq->sender_mac, sizeof(arpreq->sender_mac));
	memcpy(frame.a.target_ip, arpreq->sender_ip, sizeof(arpreq->sender_ip));

	n = write(fd, &frame, sizeof(frame));
	if (n != sizeof(frame))
	{
		DBG1(DBG_NET, "sending ARP reply failed: %s", strerror(errno));
	}
}

#endif /* !defined(__APPLE__) && !defined(__FreeBSD__) */

static void handle_arp_pkt(void *_this, char *if_name, int if_index, chunk_t *mac,
						   int fd, void *_packet, size_t len) {
	const private_farp_spoofer_t *this = (private_farp_spoofer_t *) _this;
	arp_t *a = (arp_t *) _packet;
	host_t *sender;
	host_t *target;

	if (len == sizeof(arp_t)) {
		sender = host_create_from_chunk(AF_INET,
										chunk_create((char*)a->sender_ip, 4), 0);
		target = host_create_from_chunk(AF_INET,
										chunk_create((char*)a->target_ip, 4), 0);
		if (sender && target) {
			if (this->listener->has_tunnel(this->listener, sender, target)) {
				send_arp(if_name, if_index, mac, fd, a, sender, target);
			} else {
			  DBG2(DBG_NET, "ARP no tunnel between %H <-> %H", target, sender);
			}
		} else {
		  DBG1(DBG_NET, "ARP missing host sender=%s target=%s",
			   sender ? "t" : "f", target ? "t" : "f");
		}
		DESTROY_IF(target);
		DESTROY_IF(sender);
	} else {
	  DBG1(DBG_NET, "ARP wrong size expected=%d != actual=%d", sizeof(arp_t), len);
	}
}

/**
 * Cleanup the handlers used by this plugin.
 */
METHOD(farp_spoofer_t, destroy, void, private_farp_spoofer_t *this)
{
	this->pf_handler->destroy(this->pf_handler);
	free(this);
}

/**
 * See header
 */
farp_spoofer_t *farp_spoofer_create(farp_listener_t *listener)
{
#if !defined(__APPLE__) && !defined(__FreeBSD__)
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
#else
	const size_t skip_eth = sizeof(struct ether_header);
	struct bpf_insn instructions[] = {
		BPF_STMT(BPF_LD+BPF_W+BPF_LEN, 0),
		BPF_JUMP(BPF_JMP+BPF_JGE+BPF_K, skip_eth + sizeof(arp_t), 0, 11),
		BPF_STMT(BPF_LD+BPF_H+BPF_ABS, offsetof(struct ether_header, ether_type)),
		BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, ETHERTYPE_ARP, 0, 9),
		BPF_STMT(BPF_LD+BPF_H+BPF_ABS, skip_eth + offsetof(arp_t, protocol_type)),
		BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, ETHERTYPE_IP, 0, 7),
		BPF_STMT(BPF_LD+BPF_B+BPF_ABS, skip_eth + offsetof(arp_t, hardware_size)),
		BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, 6, 0, 5),
		BPF_STMT(BPF_LD+BPF_B+BPF_ABS, skip_eth + offsetof(arp_t, protocol_size)),
		BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, 4, 0, 3),
		BPF_STMT(BPF_LD+BPF_H+BPF_ABS, skip_eth + offsetof(arp_t, opcode)),
		BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, ARPOP_REQUEST, 0, 1),
		BPF_STMT(BPF_RET+BPF_K, 14 + sizeof(arp_t)),
		BPF_STMT(BPF_RET+BPF_K, 0)
	};
	struct bpf_program arp_request_filter = {
		sizeof(instructions) / sizeof(struct bpf_insn),
		&instructions[0]
	};
#endif
	private_farp_spoofer_t *this;

	INIT(this,
		.public = {
			.destroy = _destroy,
		},
		.listener = listener,
	);

	this->pf_handler = pf_handler_create(this, "ARP", 0,
										 handle_arp_pkt, &arp_request_filter);
	if (!this->pf_handler)
	{
		destroy(this);
		return NULL;
	}
	return &this->public;
}
