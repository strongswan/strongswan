/*
 * Copyright (C) 2010 Martin Willi
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

#include "android_plugin.h"
#include "android_logger.h"
#include "android_handler.h"
#include "android_creds.h"

#include <hydra.h>
#include <daemon.h>

typedef struct private_android_plugin_t private_android_plugin_t;

/**
 * Private data of an android_plugin_t object.
 */
struct private_android_plugin_t {

	/**
	 * Public android_plugin_t interface.
	 */
	android_plugin_t public;

	/**
	 * Android specific logger
	 */
	android_logger_t *logger;

	/**
	 * Android specific DNS handler
	 */
	android_handler_t *handler;

	/**
	 * Android specific credential set
	 */
	android_creds_t *creds;

};

METHOD(plugin_t, destroy, void,
	   private_android_plugin_t *this)
{
	hydra->attributes->remove_handler(hydra->attributes,
									  &this->handler->handler);
	charon->credentials->remove_set(charon->credentials, &this->creds->set);
	charon->bus->remove_listener(charon->bus, &this->logger->listener);
	this->creds->destroy(this->creds);
	this->handler->destroy(this->handler);
	this->logger->destroy(this->logger);
	free(this);
}

/**
 * See header
 */
plugin_t *android_plugin_create()
{
	private_android_plugin_t *this;

	INIT(this,
		.public.plugin = {
			.destroy = _destroy,
		},
		.logger = android_logger_create(),
		.handler = android_handler_create(),
		.creds = android_creds_create(),
	);

	charon->bus->add_listener(charon->bus, &this->logger->listener);
	charon->credentials->add_set(charon->credentials, &this->creds->set);
	hydra->attributes->add_handler(hydra->attributes, &this->handler->handler);

	return &this->public.plugin;
}

