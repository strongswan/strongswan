/*
 * Copyright (C) 2008 Martin Willi
 * Hochschule fuer Technik Rapperswil
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
 *
 * $Id$
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <errno.h>
#include <stdlib.h>
#include <glib/gi18n-lib.h>
#include <string.h>
#include <gtk/gtk.h>
#include <glade/glade.h>

#define NM_VPN_API_SUBJECT_TO_CHANGE

#include <nm-vpn-plugin-ui-interface.h>
#include <nm-setting-vpn.h>
#include <nm-setting-connection.h>
#include <nm-setting-ip4-config.h>

#include "nm-strongswan.h"

#define STRONGSWAN_PLUGIN_NAME    _("IPsec/IKEv2 (strongswan)")
#define STRONGSWAN_PLUGIN_DESC    _("IPsec with the IKEv2 key exchange protocol.")
#define STRONGSWAN_PLUGIN_SERVICE "org.freedesktop.NetworkManager.strongswan"
#define NM_DBUS_SERVICE_STRONGSWAN "org.freedesktop.NetworkManager.strongswan"

/************** plugin class **************/

static void strongswan_plugin_ui_interface_init (NMVpnPluginUiInterface *iface_class);

G_DEFINE_TYPE_EXTENDED (StrongswanPluginUi, strongswan_plugin_ui, G_TYPE_OBJECT, 0,
						G_IMPLEMENT_INTERFACE (NM_TYPE_VPN_PLUGIN_UI_INTERFACE,
											   strongswan_plugin_ui_interface_init))

/************** UI widget class **************/

static void strongswan_plugin_ui_widget_interface_init (NMVpnPluginUiWidgetInterface *iface_class);

G_DEFINE_TYPE_EXTENDED (StrongswanPluginUiWidget, strongswan_plugin_ui_widget, G_TYPE_OBJECT, 0,
						G_IMPLEMENT_INTERFACE (NM_TYPE_VPN_PLUGIN_UI_WIDGET_INTERFACE,
											   strongswan_plugin_ui_widget_interface_init))

#define STRONGSWAN_PLUGIN_UI_WIDGET_GET_PRIVATE(o) (G_TYPE_INSTANCE_GET_PRIVATE ((o), STRONGSWAN_TYPE_PLUGIN_UI_WIDGET, StrongswanPluginUiWidgetPrivate))

typedef struct {
	GladeXML *xml;
	GtkWidget *widget;
} StrongswanPluginUiWidgetPrivate;


#define STRONGSWAN_PLUGIN_UI_ERROR strongswan_plugin_ui_error_quark ()

static GQuark
strongswan_plugin_ui_error_quark (void)
{
	static GQuark error_quark = 0;

	if (G_UNLIKELY (error_quark == 0))
		error_quark = g_quark_from_static_string ("strongswan-plugin-ui-error-quark");

	return error_quark;
}

#define ENUM_ENTRY(NAME, DESC) { NAME, "" #NAME "", DESC }

GType
strongswan_plugin_ui_error_get_type (void)
{
	static GType etype = 0;

	if (etype == 0) {
		static const GEnumValue values[] = {
			/* Unknown error. */
			ENUM_ENTRY (STRONGSWAN_PLUGIN_UI_ERROR_UNKNOWN, "UnknownError"),
			/* The specified property was invalid. */
			ENUM_ENTRY (STRONGSWAN_PLUGIN_UI_ERROR_INVALID_PROPERTY, "InvalidProperty"),
			/* The specified property was missing and is required. */
			ENUM_ENTRY (STRONGSWAN_PLUGIN_UI_ERROR_MISSING_PROPERTY, "MissingProperty"),
			{ 0, 0, 0 }
		};
		etype = g_enum_register_static ("StrongswanPluginUiError", values);
	}
	return etype;
}

static gboolean
check_validity (StrongswanPluginUiWidget *self, GError **error)
{
	StrongswanPluginUiWidgetPrivate *priv = STRONGSWAN_PLUGIN_UI_WIDGET_GET_PRIVATE (self);
	GtkWidget *widget;
	char *str;

	widget = glade_xml_get_widget (priv->xml, "address-entry");
	str = (char *) gtk_entry_get_text (GTK_ENTRY (widget));
	if (!str || !strlen (str)) {
		g_set_error (error,
		             STRONGSWAN_PLUGIN_UI_ERROR,
		             STRONGSWAN_PLUGIN_UI_ERROR_INVALID_PROPERTY,
		             "address");
		return FALSE;
	}

	widget = glade_xml_get_widget (priv->xml, "user-entry");
	str = (char *) gtk_entry_get_text (GTK_ENTRY (widget));
	if (!str || !strlen (str)) {
		g_set_error (error,
		             STRONGSWAN_PLUGIN_UI_ERROR,
		             STRONGSWAN_PLUGIN_UI_ERROR_INVALID_PROPERTY,
		             "user");
		return FALSE;
	}

	return TRUE;
}

static void
stuff_changed_cb (GtkWidget *widget, gpointer user_data)
{
	g_signal_emit_by_name (STRONGSWAN_PLUGIN_UI_WIDGET (user_data), "changed");
}

static gboolean
init_plugin_ui (StrongswanPluginUiWidget *self, NMConnection *connection, GError **error)
{
	StrongswanPluginUiWidgetPrivate *priv = STRONGSWAN_PLUGIN_UI_WIDGET_GET_PRIVATE (self);
	NMSettingVPN *settings;
	GtkWidget *widget;
	char *value;
	gboolean active;
	
	settings = NM_SETTING_VPN(nm_connection_get_setting(connection, NM_TYPE_SETTING_VPN));
	if (!settings)
		return FALSE;
	widget = glade_xml_get_widget (priv->xml, "address-entry");
	if (!widget)
		return FALSE;
	value = g_hash_table_lookup (settings->data, "address");
	if (value)
		gtk_entry_set_text (GTK_ENTRY (widget), value);
	g_signal_connect (G_OBJECT (widget), "changed", G_CALLBACK (stuff_changed_cb), self);

	widget = glade_xml_get_widget (priv->xml, "user-entry");
	if (!widget)
		return FALSE;
	value = g_hash_table_lookup (settings->data, "user");
	if (value)
		gtk_entry_set_text (GTK_ENTRY (widget), value);
	g_signal_connect (G_OBJECT (widget), "changed", G_CALLBACK (stuff_changed_cb), self);
	
	widget = glade_xml_get_widget (priv->xml, "virtual-check");
	if (!widget)
		return FALSE;
	value = g_hash_table_lookup (settings->data, "virtual");
	if (value && strcmp(value, "yes") == 0)
	{
		gtk_toggle_button_set_active(GTK_TOGGLE_BUTTON(widget), TRUE);
	}
	g_signal_connect (G_OBJECT (widget), "toggled", G_CALLBACK (stuff_changed_cb), self);
	
	widget = glade_xml_get_widget (priv->xml, "encap-check");
	if (!widget)
		return FALSE;
	value = g_hash_table_lookup (settings->data, "encap");
	if (value && strcmp(value, "yes") == 0)
	{
		gtk_toggle_button_set_active(GTK_TOGGLE_BUTTON(widget), TRUE);
	}
	g_signal_connect (G_OBJECT (widget), "toggled", G_CALLBACK (stuff_changed_cb), self);
	
	widget = glade_xml_get_widget (priv->xml, "ipcomp-check");
	if (!widget)
		return FALSE;
	value = g_hash_table_lookup (settings->data, "ipcomp");
	if (value && strcmp(value, "yes") == 0)
	{
		gtk_toggle_button_set_active(GTK_TOGGLE_BUTTON(widget), TRUE);
	}
	g_signal_connect (G_OBJECT (widget), "toggled", G_CALLBACK (stuff_changed_cb), self);

	return TRUE;
}

static GObject *
get_widget (NMVpnPluginUiWidgetInterface *iface)
{
	StrongswanPluginUiWidget *self = STRONGSWAN_PLUGIN_UI_WIDGET (iface);
	StrongswanPluginUiWidgetPrivate *priv = STRONGSWAN_PLUGIN_UI_WIDGET_GET_PRIVATE (self);

	return G_OBJECT (priv->widget);
}

static gboolean
update_connection (NMVpnPluginUiWidgetInterface *iface,
                   NMConnection *connection,
                   GError **error)
{
	StrongswanPluginUiWidget *self = STRONGSWAN_PLUGIN_UI_WIDGET (iface);
	StrongswanPluginUiWidgetPrivate *priv = STRONGSWAN_PLUGIN_UI_WIDGET_GET_PRIVATE (self);
	NMSettingVPN *settings;
	GtkWidget *widget;
	GValue *value;
	gboolean active;
	char *str;
	GtkTreeModel *model;
	GtkTreeIter iter;

	if (!check_validity (self, error))
		return FALSE;
	settings = NM_SETTING_VPN (nm_setting_vpn_new ());
	settings->service_type = g_strdup (NM_DBUS_SERVICE_STRONGSWAN);

	widget = glade_xml_get_widget (priv->xml, "address-entry");
	str = (char *) gtk_entry_get_text (GTK_ENTRY (widget));
	if (str && strlen (str)) {
		g_hash_table_insert (settings->data, g_strdup ("address"), g_strdup(str));
	}

	widget = glade_xml_get_widget (priv->xml, "user-entry");
	str = (char *) gtk_entry_get_text (GTK_ENTRY (widget));
	if (str && strlen (str)) {
		g_hash_table_insert (settings->data, g_strdup ("user"), g_strdup(str));
	}

	widget = glade_xml_get_widget (priv->xml, "virtual-check");
	active = gtk_toggle_button_get_active(GTK_TOGGLE_BUTTON(widget));
	g_hash_table_insert (settings->data, g_strdup ("virtual"),
			             g_strdup(active ? "yes" : "no"));
	                     
	widget = glade_xml_get_widget (priv->xml, "encap-check");
	active = gtk_toggle_button_get_active(GTK_TOGGLE_BUTTON(widget));
	g_hash_table_insert (settings->data, g_strdup ("encap"),
			             g_strdup(active ? "yes" : "no"));
	                     
	widget = glade_xml_get_widget (priv->xml, "ipcomp-check");
	active = gtk_toggle_button_get_active(GTK_TOGGLE_BUTTON(widget));
	g_hash_table_insert (settings->data, g_strdup ("ipcomp"),
			             g_strdup(active ? "yes" : "no"));

	nm_connection_add_setting (connection, NM_SETTING (settings));
	return TRUE;
}

static NMVpnPluginUiWidgetInterface *
nm_vpn_plugin_ui_widget_interface_new (NMConnection *connection, GError **error)
{
	NMVpnPluginUiWidgetInterface *object;
	StrongswanPluginUiWidgetPrivate *priv;
	char *glade_file;

	if (error)
		g_return_val_if_fail (*error == NULL, NULL);

	object = NM_VPN_PLUGIN_UI_WIDGET_INTERFACE (g_object_new (STRONGSWAN_TYPE_PLUGIN_UI_WIDGET, NULL));
	if (!object) {
		g_set_error (error, STRONGSWAN_PLUGIN_UI_ERROR, 0, "could not create strongswan object");
		return NULL;
	}

	priv = STRONGSWAN_PLUGIN_UI_WIDGET_GET_PRIVATE (object);

	glade_file = g_strdup_printf ("%s/%s", GLADEDIR, "nm-strongswan-dialog.glade");
	priv->xml = glade_xml_new (glade_file, "strongswan-vbox", GETTEXT_PACKAGE);
	if (priv->xml == NULL) {
		g_set_error (error, STRONGSWAN_PLUGIN_UI_ERROR, 0,
		             "could not load required resources at %s", glade_file);
		g_free (glade_file);
		g_object_unref (object);
		return NULL;
	}
	g_free (glade_file);

	priv->widget = glade_xml_get_widget (priv->xml, "strongswan-vbox");
	if (!priv->widget) {
		g_set_error (error, STRONGSWAN_PLUGIN_UI_ERROR, 0, "could not load UI widget");
		g_object_unref (object);
		return NULL;
	}
	g_object_ref_sink (priv->widget);

	if (!init_plugin_ui (STRONGSWAN_PLUGIN_UI_WIDGET (object), connection, error)) {
		g_object_unref (object);
		return NULL;
	}

	return object;
}

static void
dispose (GObject *object)
{
	StrongswanPluginUiWidget *plugin = STRONGSWAN_PLUGIN_UI_WIDGET (object);
	StrongswanPluginUiWidgetPrivate *priv = STRONGSWAN_PLUGIN_UI_WIDGET_GET_PRIVATE (plugin);

	if (priv->widget)
		g_object_unref (priv->widget);

	if (priv->xml)
		g_object_unref (priv->xml);

	G_OBJECT_CLASS (strongswan_plugin_ui_widget_parent_class)->dispose (object);
}

static void
strongswan_plugin_ui_widget_class_init (StrongswanPluginUiWidgetClass *req_class)
{
	GObjectClass *object_class = G_OBJECT_CLASS (req_class);

	g_type_class_add_private (req_class, sizeof (StrongswanPluginUiWidgetPrivate));

	object_class->dispose = dispose;
}

static void
strongswan_plugin_ui_widget_init (StrongswanPluginUiWidget *plugin)
{
}

static void
strongswan_plugin_ui_widget_interface_init (NMVpnPluginUiWidgetInterface *iface_class)
{
	/* interface implementation */
	iface_class->get_widget = get_widget;
	iface_class->update_connection = update_connection;
}

static guint32
get_capabilities (NMVpnPluginUiInterface *iface)
{
	return 0;
}

static NMVpnPluginUiWidgetInterface *
ui_factory (NMVpnPluginUiInterface *iface, NMConnection *connection, GError **error)
{
	return nm_vpn_plugin_ui_widget_interface_new (connection, error);
}

static void
get_property (GObject *object, guint prop_id,
			  GValue *value, GParamSpec *pspec)
{
	switch (prop_id) {
	case NM_VPN_PLUGIN_UI_INTERFACE_PROP_NAME:
		g_value_set_string (value, STRONGSWAN_PLUGIN_NAME);
		break;
	case NM_VPN_PLUGIN_UI_INTERFACE_PROP_DESC:
		g_value_set_string (value, STRONGSWAN_PLUGIN_DESC);
		break;
	case NM_VPN_PLUGIN_UI_INTERFACE_PROP_SERVICE:
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
									  NM_VPN_PLUGIN_UI_INTERFACE_PROP_NAME,
									  NM_VPN_PLUGIN_UI_INTERFACE_NAME);

	g_object_class_override_property (object_class,
									  NM_VPN_PLUGIN_UI_INTERFACE_PROP_DESC,
									  NM_VPN_PLUGIN_UI_INTERFACE_DESC);

	g_object_class_override_property (object_class,
									  NM_VPN_PLUGIN_UI_INTERFACE_PROP_SERVICE,
									  NM_VPN_PLUGIN_UI_INTERFACE_SERVICE);
}

static void
strongswan_plugin_ui_init (StrongswanPluginUi *plugin)
{
}

static void
strongswan_plugin_ui_interface_init (NMVpnPluginUiInterface *iface_class)
{
	/* interface implementation */
	iface_class->ui_factory = ui_factory;
	iface_class->get_capabilities = get_capabilities;
}


G_MODULE_EXPORT NMVpnPluginUiInterface *
nm_vpn_plugin_ui_factory (GError **error)
{
	if (error)
		g_return_val_if_fail (*error == NULL, NULL);

	return NM_VPN_PLUGIN_UI_INTERFACE (g_object_new (STRONGSWAN_TYPE_PLUGIN_UI, NULL));
}

