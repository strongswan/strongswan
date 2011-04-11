/*
 * Copyright (C) 2008 Tobias Brunner
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


#include "kernel_pfkey_plugin.h"

#include "kernel_pfkey_ipsec.h"

#include <hydra.h>

typedef struct private_kernel_pfkey_plugin_t private_kernel_pfkey_plugin_t;

/**
 * private data of kernel PF_KEY plugin
 */
struct private_kernel_pfkey_plugin_t {
	/**
	 * implements plugin interface
	 */
	kernel_pfkey_plugin_t public;
};

METHOD(plugin_t, get_name, char*,
	private_kernel_pfkey_plugin_t *this)
{
	return "kernel-pfkey";
}

METHOD(plugin_t, destroy, void,
	private_kernel_pfkey_plugin_t *this)
{
	hydra->kernel_interface->remove_ipsec_interface(hydra->kernel_interface,
						(kernel_ipsec_constructor_t)kernel_pfkey_ipsec_create);
	free(this);
}

/*
 * see header file
 */
plugin_t *kernel_pfkey_plugin_create()
{
	private_kernel_pfkey_plugin_t *this;

	INIT(this,
		.public = {
			.plugin = {
				.get_name = _get_name,
				.reload = (void*)return_false,
				.destroy = _destroy,
			},
		},
	);
	hydra->kernel_interface->add_ipsec_interface(hydra->kernel_interface,
						(kernel_ipsec_constructor_t)kernel_pfkey_ipsec_create);

	return &this->public.plugin;
}
