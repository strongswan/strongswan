/*
 * Copyright (C) 2013-2020 Tobias Brunner
 * Copyright (C) 2008 Martin Willi
 * HSR Hochschule fuer Technik Rapperswil
 * Copyright (C) 2015 Lubomir Rintel
 * Copyright (C) 2005 David Zeuthen
 * Copyright (C) 2005-2008 Dan Williams
 *
 * Based on NetworkManager's vpnc plugin
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

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#define _GNU_SOURCE
#include <dlfcn.h>

#include <glib.h>
#include <glib/gi18n-lib.h>

#include <NetworkManager.h>

#include "nm-strongswan-plugin.h"

#define STRONGSWAN_PLUGIN_NAME    _("IPsec/IKEv2 (strongswan)")
#define STRONGSWAN_PLUGIN_DESC    _("IPsec with the IKEv2 key exchange protocol.")
#define STRONGSWAN_PLUGIN_SERVICE "org.freedesktop.NetworkManager.strongswan"
#define STRONGSWAN_EDITOR_GTK3    "libnm-vpn-plugin-strongswan-editor.so"
#define STRONGSWAN_EDITOR_GTK4    "libnm-gtk4-vpn-plugin-strongswan-editor.so"
#define STRONGSWAN_EDITOR_FACTORY "strongswan_editor_new"

/************** plugin class **************/

enum {
	PROP_0,
	PROP_NAME,
	PROP_DESC,
	PROP_SERVICE
};

static void strongswan_plugin_ui_interface_init (NMVpnEditorPluginInterface *iface_class);

G_DEFINE_TYPE_EXTENDED (StrongswanPluginUi, strongswan_plugin_ui, G_TYPE_OBJECT, 0,
						G_IMPLEMENT_INTERFACE (NM_TYPE_VPN_EDITOR_PLUGIN,
											   strongswan_plugin_ui_interface_init))

static NMVpnEditor *
get_editor (NMVpnEditorPlugin *iface, NMConnection *connection, GError **error)
{
	static struct {
		NMVpnEditor *(*factory)(NMConnection*, GError**);
		void *dl_module;
		char *file;
	} cache = {};
	NMVpnEditor *editor;
	char *file;

	g_return_val_if_fail (NM_IS_CONNECTION (connection), NULL);
	g_return_val_if_fail (!error || !*error, NULL);

	/* check for a GTK3-only symbol to decide which editor to load */
	if (dlsym(RTLD_DEFAULT, "gtk_container_add"))
	{
		file = STRONGSWAN_EDITOR_GTK3;
	}
	else
	{

		file = STRONGSWAN_EDITOR_GTK4;
	}

	if (cache.factory)
	{	/* we can't switch GTK versions */
		g_return_val_if_fail (cache.file && !strcmp(cache.file, file), NULL);
	}
	else
	{
		Dl_info plugin_info;
		void *dl_module;
		char *module_path = NULL;
		char *dirname = NULL;
		NMVpnEditor *(*factory)(NMConnection*, GError**);

		if (!dladdr(get_editor, &plugin_info))
		{
			g_set_error (error, NM_VPN_PLUGIN_ERROR, NM_VPN_PLUGIN_ERROR_FAILED,
						 _("unable to determine plugin path: %s"), dlerror());
			return NULL;
		}
		dirname = g_path_get_dirname (plugin_info.dli_fname);
		module_path = g_build_filename (dirname, file, NULL);
		g_free(dirname);

		dl_module = dlopen(module_path, RTLD_LAZY | RTLD_LOCAL);
		if (!dl_module)
		{
			if (!g_file_test (module_path, G_FILE_TEST_EXISTS))
			{
				g_set_error (error, G_FILE_ERROR, G_FILE_ERROR_NOENT,
							 _("missing plugin file '%s'"), module_path);
				g_free(module_path);
				return NULL;
			}
			g_set_error (error, NM_VPN_PLUGIN_ERROR, NM_VPN_PLUGIN_ERROR_FAILED,
						 _("unable to load editor plugin: %s"), dlerror ());
			g_free(module_path);
			return NULL;
		}
		g_free(module_path);

		factory = dlsym (dl_module, STRONGSWAN_EDITOR_FACTORY);
		if (!factory)
		{
			g_set_error (error, NM_VPN_PLUGIN_ERROR, NM_VPN_PLUGIN_ERROR_FAILED,
						 _("cannot load factory %s from plugin: %s"),
						 STRONGSWAN_EDITOR_FACTORY, dlerror ());
			dlclose (dl_module);
			return NULL;
		}
		cache.factory = factory;
		cache.dl_module = dl_module;
		cache.file = strdup(file);
	}

	editor = cache.factory (connection, error);
	if (!editor)
	{
		if (error && !*error)
		{
			g_set_error_literal (error, NM_VPN_PLUGIN_ERROR,
								 NM_VPN_PLUGIN_ERROR_FAILED,
								 _("unknown error creating editor instance"));
			return NULL;
		}
		return NULL;
	}
	g_return_val_if_fail (NM_IS_VPN_EDITOR (editor), NULL);
	return editor;
}

static guint32
get_capabilities (NMVpnEditorPlugin *iface)
{
	return NM_VPN_EDITOR_PLUGIN_CAPABILITY_IPV6;
}

static void
get_property (GObject *object, guint prop_id,
			  GValue *value, GParamSpec *pspec)
{
	switch (prop_id) {
	case PROP_NAME:
		g_value_set_string (value, STRONGSWAN_PLUGIN_NAME);
		break;
	case PROP_DESC:
		g_value_set_string (value, STRONGSWAN_PLUGIN_DESC);
		break;
	case PROP_SERVICE:
		g_value_set_string (value, STRONGSWAN_PLUGIN_SERVICE);
		break;
	default:
		G_OBJECT_WARN_INVALID_PROPERTY_ID (object, prop_id, pspec);
		break;
	}
}

static void
strongswan_plugin_ui_class_init (StrongswanPluginUiClass *req_class)
{
	GObjectClass *object_class = G_OBJECT_CLASS (req_class);

	object_class->get_property = get_property;

	g_object_class_override_property (object_class,
									  PROP_NAME,
									  NM_VPN_EDITOR_PLUGIN_NAME);

	g_object_class_override_property (object_class,
									  PROP_DESC,
									  NM_VPN_EDITOR_PLUGIN_DESCRIPTION);

	g_object_class_override_property (object_class,
									  PROP_SERVICE,
									  NM_VPN_EDITOR_PLUGIN_SERVICE);
}

static void
strongswan_plugin_ui_init (StrongswanPluginUi *plugin)
{
}

static void
strongswan_plugin_ui_interface_init (NMVpnEditorPluginInterface *iface_class)
{
	/* interface implementation */
	iface_class->get_editor = get_editor;
	iface_class->get_capabilities = get_capabilities;
	/* TODO: implement delete_connection to purge associated secrets */
}

G_MODULE_EXPORT NMVpnEditorPlugin *
nm_vpn_editor_plugin_factory (GError **error)
{
	g_return_val_if_fail (!error || !*error, NULL);

	return g_object_new (STRONGSWAN_TYPE_PLUGIN_UI, NULL);
}
