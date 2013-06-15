/*
 * Copyright (C) 2013 Tobias Brunner
 * Hochschule fuer Technik Rapperswil
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

#include "kernel_libipsec_router.h"

#include <daemon.h>
#include <ipsec.h>
#include <networking/tun_device.h>
#include <processing/jobs/callback_job.h>

typedef struct private_kernel_libipsec_router_t private_kernel_libipsec_router_t;

/**
 * Private data
 */
struct private_kernel_libipsec_router_t {

	/**
	 * Public interface
	 */
	kernel_libipsec_router_t public;

	/**
	 * TUN device
	 */
	tun_device_t *tun;
};

/**
 * Outbound callback
 */
static void send_esp(void *data, esp_packet_t *packet)
{
	charon->sender->send_no_marker(charon->sender, (packet_t*)packet);
}

/**
 * Receiver callback
 */
static void receiver_esp_cb(void *data, packet_t *packet)
{
	ipsec->processor->queue_inbound(ipsec->processor,
									esp_packet_create_from_packet(packet));
}

/**
 * Inbound callback
 */
static void deliver_plain(private_kernel_libipsec_router_t *this,
						  ip_packet_t *packet)
{
	this->tun->write_packet(this->tun, packet->get_encoding(packet));
	packet->destroy(packet);
}

/**
 * Job handling outbound plaintext packets
 */
static job_requeue_t handle_plain(private_kernel_libipsec_router_t *this)
{
	chunk_t raw;

	if (this->tun->read_packet(this->tun, &raw))
	{
		ip_packet_t *packet;

		packet = ip_packet_create(raw);
		if (packet)
		{
			ipsec->processor->queue_outbound(ipsec->processor, packet);
		}
		else
		{
			DBG1(DBG_KNL, "invalid IP packet read from TUN device");
		}
	}
	return JOB_REQUEUE_DIRECT;
}

METHOD(kernel_libipsec_router_t, destroy, void,
	private_kernel_libipsec_router_t *this)
{
	charon->receiver->del_esp_cb(charon->receiver,
								(receiver_esp_cb_t)receiver_esp_cb);
	ipsec->processor->unregister_outbound(ipsec->processor,
										 (ipsec_outbound_cb_t)send_esp);
	ipsec->processor->unregister_inbound(ipsec->processor,
										 (ipsec_inbound_cb_t)deliver_plain);
	free(this);
}

/*
 * See header file
 */
kernel_libipsec_router_t *kernel_libipsec_router_create(tun_device_t *tun)
{
	private_kernel_libipsec_router_t *this;

	INIT(this,
		.public = {
			.destroy = _destroy,
		},
		.tun = lib->get(lib, "kernel-libipsec-tun"),
	);

	ipsec->processor->register_outbound(ipsec->processor, send_esp, NULL);
	ipsec->processor->register_inbound(ipsec->processor,
									(ipsec_inbound_cb_t)deliver_plain, this);
	charon->receiver->add_esp_cb(charon->receiver,
									(receiver_esp_cb_t)receiver_esp_cb, NULL);
	lib->processor->queue_job(lib->processor,
			(job_t*)callback_job_create((callback_job_cb_t)handle_plain, this,
									NULL, (callback_job_cancel_t)return_false));

	return &this->public;
}
