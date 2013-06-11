/*
 * Copyright (C) 2012-2013 Tobias Brunner
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

#include "kernel_libipsec_plugin.h"
#include "kernel_libipsec_ipsec.h"

#include <daemon.h>
#include <ipsec.h>
#include <networking/tun_device.h>
#include <processing/jobs/callback_job.h>
#include <utils/debug.h>

#define TUN_DEFAULT_MTU 1400

typedef struct private_kernel_libipsec_plugin_t private_kernel_libipsec_plugin_t;

/**
 * private data of "kernel" libipsec plugin
 */
struct private_kernel_libipsec_plugin_t {

	/**
	 * implements plugin interface
	 */
	kernel_libipsec_plugin_t public;

	/**
	 * TUN device created by this plugin
	 */
	tun_device_t *tun;

};

METHOD(plugin_t, get_name, char*,
	private_kernel_libipsec_plugin_t *this)
{
	return "kernel-libipsec";
}

/**
 * Outbound callback
 */
static void send_esp(void *data, esp_packet_t *packet)
{
	charon->sender->send_no_marker(charon->sender, (packet_t*)packet);
}

/**
 * Inbound callback
 */
static void deliver_plain(private_kernel_libipsec_plugin_t *this,
						  ip_packet_t *packet)
{
	this->tun->write_packet(this->tun, packet->get_encoding(packet));
	packet->destroy(packet);
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
 * Job handling outbound plaintext packets
 */
static job_requeue_t handle_plain(private_kernel_libipsec_plugin_t *this)
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

/**
 * Initialize/deinitialize sender and receiver
 */
static bool packet_handler_cb(private_kernel_libipsec_plugin_t *this,
							  plugin_feature_t *feature, bool reg, void *arg)
{
	if (reg)
	{
		ipsec->processor->register_outbound(ipsec->processor, send_esp, NULL);
		ipsec->processor->register_inbound(ipsec->processor,
									(ipsec_inbound_cb_t)deliver_plain, this);
		charon->receiver->add_esp_cb(charon->receiver,
									(receiver_esp_cb_t)receiver_esp_cb, NULL);
		lib->processor->queue_job(lib->processor,
			(job_t*)callback_job_create((callback_job_cb_t)handle_plain, this,
									NULL, (callback_job_cancel_t)return_false));
	}
	else
	{
		charon->receiver->del_esp_cb(charon->receiver,
									(receiver_esp_cb_t)receiver_esp_cb);
		ipsec->processor->unregister_outbound(ipsec->processor,
											 (ipsec_outbound_cb_t)send_esp);
		ipsec->processor->unregister_inbound(ipsec->processor,
											 (ipsec_inbound_cb_t)deliver_plain);
	}
	return TRUE;
}

METHOD(plugin_t, get_features, int,
	private_kernel_libipsec_plugin_t *this, plugin_feature_t *features[])
{
	static plugin_feature_t f[] = {
		PLUGIN_CALLBACK(kernel_ipsec_register, kernel_libipsec_ipsec_create),
			PLUGIN_PROVIDE(CUSTOM, "kernel-ipsec"),
		PLUGIN_CALLBACK((plugin_feature_callback_t)packet_handler_cb, NULL),
			PLUGIN_PROVIDE(CUSTOM, "kernel-libipsec-handler"),
				PLUGIN_DEPENDS(CUSTOM, "libcharon-receiver"),
	};
	*features = f;
	return countof(f);
}

METHOD(plugin_t, destroy, void,
	private_kernel_libipsec_plugin_t *this)
{
	if (this->tun)
	{
		lib->set(lib, "kernel-libipsec-tun", NULL);
		this->tun->destroy(this->tun);
	}
	libipsec_deinit();
	free(this);
}

/*
 * see header file
 */
plugin_t *kernel_libipsec_plugin_create()
{
	private_kernel_libipsec_plugin_t *this;

	INIT(this,
		.public = {
			.plugin = {
				.get_name = _get_name,
				.get_features = _get_features,
				.destroy = _destroy,
			},
		},
	);

	if (!libipsec_init())
	{
		DBG1(DBG_LIB, "initialization of libipsec failed");
		destroy(this);
		return NULL;
	}

	this->tun = tun_device_create("ipsec%d");
	if (!this->tun)
	{
		DBG1(DBG_KNL, "failed to create TUN device");
		destroy(this);
		return NULL;
	}
	if (!this->tun->set_mtu(this->tun, TUN_DEFAULT_MTU) ||
		!this->tun->up(this->tun))
	{
		DBG1(DBG_KNL, "failed to configure TUN device");
		destroy(this);
		return NULL;
	}
	lib->set(lib, "kernel-libipsec-tun", this->tun);

	/* set TUN device as default to install VIPs */
	lib->settings->set_str(lib->settings, "%s.install_virtual_ip_on",
						   this->tun->get_name(this->tun), charon->name);
	return &this->public.plugin;
}
