/*
 * Copyright (C) 2023 Andreas Steffen
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

#include "tun_device_manager.h"

#include <utils/debug.h>

typedef struct private_tun_device_manager_t private_tun_device_manager_t;

/**
 * private data of tun_device_manager
 */
struct private_tun_device_manager_t {

	/**
	 * public functions
	 */
	tun_device_manager_t public;

	/**
	 * constructor function to create tun_device instances
	 */
	tun_device_constructor_t constructor;
};

METHOD(tun_device_manager_t, add_tun_device, void,
	private_tun_device_manager_t *this, tun_device_constructor_t constructor)
{
	if (!this->constructor)
	{
		this->constructor = constructor;
	}
}

METHOD(tun_device_manager_t, remove_tun_device, void,
	private_tun_device_manager_t *this, tun_device_constructor_t constructor)
{
	if (this->constructor == constructor)
	{
		this->constructor = NULL;
	}
}

METHOD(tun_device_manager_t, create, tun_device_t*,
	private_tun_device_manager_t *this, const char *name_tmpl)
{
	if (this->constructor)
	{
		return this->constructor(name_tmpl);
	}
	else
	{
		return tun_device_create(name_tmpl);
	}
}

METHOD(tun_device_manager_t, destroy, void,
	private_tun_device_manager_t *this)
{
	free(this);
}

/*
 * See header
 */
tun_device_manager_t *tun_device_manager_create()
{
	private_tun_device_manager_t *this;

	INIT(this,
			.public = {
				.add_tun_device = _add_tun_device,
				.remove_tun_device = _remove_tun_device,
				.create = _create,
				.destroy = _destroy,
			},
	);

	return &this->public;
}
