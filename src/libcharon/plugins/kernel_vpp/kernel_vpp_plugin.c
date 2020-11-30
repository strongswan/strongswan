/*
 * Copyright (C) 2020 LabN Consulting, L.L.C.
 * Copyright (C) 2018 PANTHEON.tech.
 *
 * Copyright (C) 2008 Tobias Brunner
 * HSR Hochschule fuer Technik Rapperswil
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
#include <library.h>
#include <utils/debug.h>
#include <utils/printf_hook/printf_hook.h>
#include <vlibapi/api.h>
#include <vlibmemory/api.h>
#include <vpp/api/vpe_msg_enum.h>

#include <vnet/api_errno.h>

#define vl_typedefs
#include <vpp/api/vpe_all_api_h.h>
#undef vl_typedefs

#include "kernel_vpp_ipsec.h"
#include "kernel_vpp_net.h"
#include "kernel_vpp_plugin.h"
#include "kernel_vpp_shared.h"

typedef struct private_kernel_vpp_plugin_t private_kernel_vpp_plugin_t;

/**
 * private data of kernel vpp plugin
 */
struct private_kernel_vpp_plugin_t {
	/**
	 * implements plugin interface
	 */
	kernel_vpp_plugin_t public;

	vac_t *vac;
};

METHOD(plugin_t, get_name, char *, private_kernel_vpp_plugin_t *this)
{
	return "kernel-vpp";
}

METHOD(plugin_t, get_features, int, private_kernel_vpp_plugin_t *this,
	   plugin_feature_t *features[])
{
	static plugin_feature_t f[] = {
		PLUGIN_CALLBACK(kernel_ipsec_register, kernel_vpp_ipsec_create),
		PLUGIN_PROVIDE(CUSTOM, "kernel-ipsec"),
		PLUGIN_CALLBACK(kernel_net_register, kernel_vpp_net_create),
		PLUGIN_PROVIDE(CUSTOM, "kernel-net"),
	};
	*features = f;
	return countof(f);
}

METHOD(plugin_t, destroy, void, private_kernel_vpp_plugin_t *this)
{
	if (this->vac)
	{
		lib->set(lib, "kernel-vpp-vac", NULL);
		this->vac->destroy(this->vac);
	}
	free(this);
}

static int
vpp_api_error_printf_hook(printf_hook_data_t *data, printf_hook_spec_t *spec,
						  const void *const *args)
{
	int rv, val = *((int *)(args[0]));
	u8 *error = format(NULL, "%U (%d)", format_vnet_api_errno, val, val);

	vec_terminate_c_string(error);
	if (spec->minus)
	{
		rv = print_in_hook(data, "%-*s", spec->width, error);
	}
	else
	{
		rv = print_in_hook(data, "%*s", spec->width, error);
	}
	vec_free(error);

	return rv;
}

#if 0
static int
vpp_user_iformat_printf_hook(printf_hook_data_t *data, printf_hook_spec_t *spec,
							 const void *const *args)
{
	u8 *(*user)(u8 *, va_list *) = (u8 * (*user)(u8 *, va_list *)) args[0];
	int rv, val = *((int *)(args[1]));

	u8 *s = format(NULL, "%U", user, val);
	vec_terminate_c_string(s);

	if (spec->minus)
	{
		rv = print_in_hook(data, "%-*s", spec->width, s);
	}
	else
	{
		rv = print_in_hook(data, "%*s", spec->width, s);
	}
	vec_free(s);

	return rv;
}

static int
vpp_user_pformat_printf_hook(printf_hook_data_t *data, printf_hook_spec_t *spec,
							 const void *const *args)
{
	u8 *(*user)(u8 *, va_list *) = (u8 * (*user)(u8 *, va_list *)) args[0];
	void *val = *(void **)args[1];
	int rv;

	u8 *s = format(NULL, "%U", user, val);
	vec_terminate_c_string(s);

	if (spec->minus)
	{
		rv = print_in_hook(data, "%-*s", spec->width, s);
	}
	else
	{
		rv = print_in_hook(data, "%*s", spec->width, s);
	}
	vec_free(s);

	return rv;
}
#endif

plugin_t *
kernel_vpp_plugin_create()
{
	private_kernel_vpp_plugin_t *this;

	INIT(this,
		 .public = {
			 .plugin =
				 {
					 .get_name = _get_name,
					 .get_features = _get_features,
					 .destroy = _destroy,
				 },
		 }, );

	this->vac = vac_create("strongswan");
	if (!this->vac)
	{
		DBG1(DBG_KNL, "vac_create failed");
		destroy(this);
		return NULL;
	}

	lib->printf_hook->add_handler(
		lib->printf_hook, 'E', vpp_api_error_printf_hook,
		PRINTF_HOOK_ARGTYPE_INT, PRINTF_HOOK_ARGTYPE_END);
#if 0
	lib->printf_hook->add_handler(
		lib->printf_hook, 'U', vpp_user_pformat_printf_hook,
		PRINTF_HOOK_ARGTYPE_POINTER, PRINTF_HOOK_ARGTYPE_POINTER,
		PRINTF_HOOK_ARGTYPE_END);
	lib->printf_hook->add_handler(
		lib->printf_hook, 'X', vpp_user_iformat_printf_hook,
		PRINTF_HOOK_ARGTYPE_POINTER, PRINTF_HOOK_ARGTYPE_INT,
		PRINTF_HOOK_ARGTYPE_END);
#endif

	lib->set(lib, "kernel-vpp-vac", this->vac);

	return &this->public.plugin;
}

/*
 * fd.io coding-style-patch-verification: CLANG
 *
 * Local Variables:
 * c-file-style: "bsd"
 * c-basic-offset: 4
 * tab-width: 4
 * indent-tabs-mode: t
 * End:
 */
