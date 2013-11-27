/*
 * Copyright (C) 2013 Tobias Brunner
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
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <glib.h>
#include <glib/gi18n-lib.h>
#include <gtk/gtk.h>

#define NM_VPN_API_SUBJECT_TO_CHANGE

#include <nm-vpn-plugin-ui-interface.h>
#include <nm-setting-vpn.h>
#include <nm-setting-connection.h>

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
	GtkBuilder *builder;
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

	widget = GTK_WIDGET (gtk_builder_get_object (priv->builder, "address-entry"));
	str = (char *) gtk_entry_get_text (GTK_ENTRY (widget));
	if (!str || !strlen (str)) {
		g_set_error (error,
					 STRONGSWAN_PLUGIN_UI_ERROR,
					 STRONGSWAN_PLUGIN_UI_ERROR_INVALID_PROPERTY,
					 "address");
		return FALSE;
	}
	return TRUE;
}

static void update_layout (GtkWidget *widget, StrongswanPluginUiWidgetPrivate *priv)
{
	switch (gtk_combo_box_get_active (GTK_COMBO_BOX (widget)))
	{
		default:
			gtk_combo_box_set_active (GTK_COMBO_BOX (widget), 0);
			/* FALL */
		case 0:
			gtk_widget_show (GTK_WIDGET (gtk_builder_get_object (priv->builder, "usercert-label")));
			gtk_widget_show (GTK_WIDGET (gtk_builder_get_object (priv->builder, "usercert-button")));
			gtk_widget_show (GTK_WIDGET (gtk_builder_get_object (priv->builder, "userkey-label")));
			gtk_widget_show (GTK_WIDGET (gtk_builder_get_object (priv->builder, "userkey-button")));
			gtk_widget_hide (GTK_WIDGET (gtk_builder_get_object (priv->builder, "user-label")));
			gtk_widget_hide (GTK_WIDGET (gtk_builder_get_object (priv->builder, "user-entry")));
			break;
		case 1:
			gtk_widget_show (GTK_WIDGET (gtk_builder_get_object (priv->builder, "usercert-label")));
			gtk_widget_show (GTK_WIDGET (gtk_builder_get_object (priv->builder, "usercert-button")));
			gtk_widget_hide (GTK_WIDGET (gtk_builder_get_object (priv->builder, "user-label")));
			gtk_widget_hide (GTK_WIDGET (gtk_builder_get_object (priv->builder, "user-entry")));
			gtk_widget_hide (GTK_WIDGET (gtk_builder_get_object (priv->builder, "userkey-label")));
			gtk_widget_hide (GTK_WIDGET (gtk_builder_get_object (priv->builder, "userkey-button")));
			break;
		case 2:
			gtk_widget_hide (GTK_WIDGET (gtk_builder_get_object (priv->builder, "usercert-label")));
			gtk_widget_hide (GTK_WIDGET (gtk_builder_get_object (priv->builder, "usercert-button")));
			gtk_widget_hide (GTK_WIDGET (gtk_builder_get_object (priv->builder, "user-label")));
			gtk_widget_hide (GTK_WIDGET (gtk_builder_get_object (priv->builder, "user-entry")));
			gtk_widget_hide (GTK_WIDGET (gtk_builder_get_object (priv->builder, "userkey-label")));
			gtk_widget_hide (GTK_WIDGET (gtk_builder_get_object (priv->builder, "userkey-button")));
			break;
		case 3:
		case 4:
			gtk_widget_show (GTK_WIDGET (gtk_builder_get_object (priv->builder, "user-label")));
			gtk_widget_show (GTK_WIDGET (gtk_builder_get_object (priv->builder, "user-entry")));
			gtk_widget_hide (GTK_WIDGET (gtk_builder_get_object (priv->builder, "usercert-label")));
			gtk_widget_hide (GTK_WIDGET (gtk_builder_get_object (priv->builder, "usercert-button")));
			gtk_widget_hide (GTK_WIDGET (gtk_builder_get_object (priv->builder, "userkey-label")));
			gtk_widget_hide (GTK_WIDGET (gtk_builder_get_object (priv->builder, "userkey-button")));
			break;
	}

}

static void
settings_changed_cb (GtkWidget *widget, gpointer user_data)
{
	StrongswanPluginUiWidget *self = STRONGSWAN_PLUGIN_UI_WIDGET (user_data);
	StrongswanPluginUiWidgetPrivate *priv = STRONGSWAN_PLUGIN_UI_WIDGET_GET_PRIVATE (self);

	if (widget == GTK_WIDGET (gtk_builder_get_object (priv->builder, "method-combo")))
	{
		update_layout(GTK_WIDGET (gtk_builder_get_object (priv->builder, "method-combo")), priv);
	}
	g_signal_emit_by_name (STRONGSWAN_PLUGIN_UI_WIDGET (user_data), "changed");
}

static gboolean
init_plugin_ui (StrongswanPluginUiWidget *self, NMConnection *connection, GError **error)
{
	StrongswanPluginUiWidgetPrivate *priv = STRONGSWAN_PLUGIN_UI_WIDGET_GET_PRIVATE (self);
	NMSettingVPN *settings;
	GtkWidget *widget;
	const char *value;

	settings = NM_SETTING_VPN(nm_connection_get_setting(connection, NM_TYPE_SETTING_VPN));
	widget = GTK_WIDGET (gtk_builder_get_object (priv->builder, "address-entry"));
	value = nm_setting_vpn_get_data_item (settings, "address");
	if (value)
		gtk_entry_set_text (GTK_ENTRY (widget), value);
	g_signal_connect (G_OBJECT (widget), "changed", G_CALLBACK (settings_changed_cb), self);

	widget = GTK_WIDGET (gtk_builder_get_object (priv->builder, "certificate-button"));
	value = nm_setting_vpn_get_data_item (settings, "certificate");
	if (value)
		gtk_file_chooser_set_filename (GTK_FILE_CHOOSER (widget), value);
	g_signal_connect (G_OBJECT (widget), "selection-changed", G_CALLBACK (settings_changed_cb), self);

	widget = GTK_WIDGET (gtk_builder_get_object (priv->builder, "user-label"));
	gtk_widget_set_no_show_all (widget, TRUE);
	widget = GTK_WIDGET (gtk_builder_get_object (priv->builder, "user-entry"));
	gtk_widget_set_no_show_all (widget, TRUE);
	value = nm_setting_vpn_get_data_item (settings, "user");
	if (value)
		gtk_entry_set_text (GTK_ENTRY (widget), value);
	g_signal_connect (G_OBJECT (widget), "changed", G_CALLBACK (settings_changed_cb), self);

	widget = GTK_WIDGET (gtk_builder_get_object (priv->builder, "method-combo"));
	gtk_combo_box_text_append_text (GTK_COMBO_BOX_TEXT (widget), _("Certificate/private key"));
	gtk_combo_box_text_append_text (GTK_COMBO_BOX_TEXT (widget), _("Certificate/ssh-agent"));
	gtk_combo_box_text_append_text (GTK_COMBO_BOX_TEXT (widget), _("Smartcard"));
	gtk_combo_box_text_append_text (GTK_COMBO_BOX_TEXT (widget), _("EAP"));
	gtk_combo_box_text_append_text (GTK_COMBO_BOX_TEXT (widget), _("Pre-shared key"));
	value = nm_setting_vpn_get_data_item (settings, "method");
	if (value) {
		if (g_strcmp0 (value, "key") == 0) {
			gtk_combo_box_set_active (GTK_COMBO_BOX (widget), 0);
		}
		if (g_strcmp0 (value, "agent") == 0) {
			gtk_combo_box_set_active (GTK_COMBO_BOX (widget), 1);
		}
		if (g_strcmp0 (value, "smartcard") == 0) {
			gtk_combo_box_set_active (GTK_COMBO_BOX (widget), 2);
		}
		if (g_strcmp0 (value, "eap") == 0) {
			gtk_combo_box_set_active (GTK_COMBO_BOX (widget), 3);
		}
		if (g_strcmp0 (value, "psk") == 0) {
			gtk_combo_box_set_active (GTK_COMBO_BOX (widget), 4);
		}
	}
	if (gtk_combo_box_get_active (GTK_COMBO_BOX (widget)) == -1)
	{
		gtk_combo_box_set_active (GTK_COMBO_BOX (widget), 0);
	}
	update_layout (widget, priv);
	g_signal_connect (G_OBJECT (widget), "changed", G_CALLBACK (settings_changed_cb), self);

	widget = GTK_WIDGET (gtk_builder_get_object (priv->builder, "usercert-label"));
	gtk_widget_set_no_show_all (widget, TRUE);
	widget = GTK_WIDGET (gtk_builder_get_object (priv->builder, "usercert-button"));
	gtk_widget_set_no_show_all (widget, TRUE);
	value = nm_setting_vpn_get_data_item (settings, "usercert");
	if (value)
		gtk_file_chooser_set_filename (GTK_FILE_CHOOSER (widget), value);
	g_signal_connect (G_OBJECT (widget), "selection-changed", G_CALLBACK (settings_changed_cb), self);

	widget = GTK_WIDGET (gtk_builder_get_object (priv->builder, "userkey-label"));
	gtk_widget_set_no_show_all (widget, TRUE);
	widget = GTK_WIDGET (gtk_builder_get_object (priv->builder, "userkey-button"));
	gtk_widget_set_no_show_all (widget, TRUE);
	value = nm_setting_vpn_get_data_item (settings, "userkey");
	if (value)
		gtk_file_chooser_set_filename (GTK_FILE_CHOOSER (widget), value);
	g_signal_connect (G_OBJECT (widget), "selection-changed", G_CALLBACK (settings_changed_cb), self);

	widget = GTK_WIDGET (gtk_builder_get_object (priv->builder, "virtual-check"));
	value = nm_setting_vpn_get_data_item (settings, "virtual");
	if (value && strcmp(value, "yes") == 0)
	{
		gtk_toggle_button_set_active(GTK_TOGGLE_BUTTON(widget), TRUE);
	}
	g_signal_connect (G_OBJECT (widget), "toggled", G_CALLBACK (settings_changed_cb), self);

	widget = GTK_WIDGET (gtk_builder_get_object (priv->builder, "encap-check"));
	value = nm_setting_vpn_get_data_item (settings, "encap");
	if (value && strcmp(value, "yes") == 0)
	{
		gtk_toggle_button_set_active(GTK_TOGGLE_BUTTON(widget), TRUE);
	}
	g_signal_connect (G_OBJECT (widget), "toggled", G_CALLBACK (settings_changed_cb), self);

	widget = GTK_WIDGET (gtk_builder_get_object (priv->builder, "ipcomp-check"));
	value = nm_setting_vpn_get_data_item (settings, "ipcomp");
	if (value && strcmp(value, "yes") == 0)
	{
		gtk_toggle_button_set_active(GTK_TOGGLE_BUTTON(widget), TRUE);
	}
	g_signal_connect (G_OBJECT (widget), "toggled", G_CALLBACK (settings_changed_cb), self);

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
	gboolean active;
	char *str;

	if (!check_validity (self, error))
		return FALSE;
	settings = NM_SETTING_VPN (nm_setting_vpn_new ());

	g_object_set (settings, NM_SETTING_VPN_SERVICE_TYPE,
				  NM_DBUS_SERVICE_STRONGSWAN, NULL);

	widget = GTK_WIDGET (gtk_builder_get_object (priv->builder, "address-entry"));
	str = (char *) gtk_entry_get_text (GTK_ENTRY (widget));
	if (str && strlen (str)) {
		nm_setting_vpn_add_data_item (settings, "address", str);
	}

	widget = GTK_WIDGET (gtk_builder_get_object (priv->builder, "certificate-button"));
	str = (char *) gtk_file_chooser_get_filename (GTK_FILE_CHOOSER (widget));
	if (str) {
		nm_setting_vpn_add_data_item (settings, "certificate", str);
	}

	widget = GTK_WIDGET (gtk_builder_get_object (priv->builder, "method-combo"));
	switch (gtk_combo_box_get_active (GTK_COMBO_BOX (widget)))
	{
		default:
		case 0:
			widget = GTK_WIDGET (gtk_builder_get_object (priv->builder, "userkey-button"));
			str = (char *) gtk_file_chooser_get_filename (GTK_FILE_CHOOSER (widget));
			if (str) {
				nm_setting_vpn_add_data_item (settings, "userkey", str);
			}
			widget = GTK_WIDGET (gtk_builder_get_object (priv->builder, "usercert-button"));
			str = (char *) gtk_file_chooser_get_filename (GTK_FILE_CHOOSER (widget));
			if (str) {
				nm_setting_vpn_add_data_item (settings, "usercert", str);
			}
			str = "key";
			break;
		case 1:
			widget = GTK_WIDGET (gtk_builder_get_object (priv->builder, "usercert-button"));
			str = (char *) gtk_file_chooser_get_filename (GTK_FILE_CHOOSER (widget));
			if (str) {
				nm_setting_vpn_add_data_item (settings, "usercert", str);
			}
			str = "agent";
			break;
		case 2:
			str = "smartcard";
			break;
		case 3:
			widget = GTK_WIDGET (gtk_builder_get_object (priv->builder, "user-entry"));
			str = (char *) gtk_entry_get_text (GTK_ENTRY (widget));
			if (str && strlen (str)) {
				nm_setting_vpn_add_data_item (settings, "user", str);
			}
			str = "eap";
			break;
		case 4:
			widget = GTK_WIDGET (gtk_builder_get_object (priv->builder, "user-entry"));
			str = (char *) gtk_entry_get_text (GTK_ENTRY (widget));
			if (str && strlen (str)) {
				nm_setting_vpn_add_data_item (settings, "user", str);
			}
			str = "psk";
			break;
	}
	nm_setting_vpn_add_data_item (settings, "method", str);

	widget = GTK_WIDGET (gtk_builder_get_object (priv->builder, "virtual-check"));
	active = gtk_toggle_button_get_active(GTK_TOGGLE_BUTTON(widget));
	nm_setting_vpn_add_data_item (settings, "virtual", active ? "yes" : "no");

	widget = GTK_WIDGET (gtk_builder_get_object (priv->builder, "encap-check"));
	active = gtk_toggle_button_get_active(GTK_TOGGLE_BUTTON(widget));
	nm_setting_vpn_add_data_item (settings, "encap", active ? "yes" : "no");

	widget = GTK_WIDGET (gtk_builder_get_object (priv->builder, "ipcomp-check"));
	active = gtk_toggle_button_get_active(GTK_TOGGLE_BUTTON(widget));
	nm_setting_vpn_add_data_item (settings, "ipcomp", active ? "yes" : "no");

	nm_setting_set_secret_flags (NM_SETTING (settings), "password",
								 NM_SETTING_SECRET_FLAG_AGENT_OWNED, NULL);

	nm_connection_add_setting (connection, NM_SETTING (settings));
	return TRUE;
}

static NMVpnPluginUiWidgetInterface *
nm_vpn_plugin_ui_widget_interface_new (NMConnection *connection, GError **error)
{
	NMVpnPluginUiWidgetInterface *object;
	StrongswanPluginUiWidgetPrivate *priv;
	char *ui_file;

	if (error)
		g_return_val_if_fail (*error == NULL, NULL);

	object = NM_VPN_PLUGIN_UI_WIDGET_INTERFACE (g_object_new (STRONGSWAN_TYPE_PLUGIN_UI_WIDGET, NULL));
	if (!object) {
		g_set_error (error, STRONGSWAN_PLUGIN_UI_ERROR, 0, "could not create strongswan object");
		return NULL;
	}

	priv = STRONGSWAN_PLUGIN_UI_WIDGET_GET_PRIVATE (object);
	ui_file = g_strdup_printf ("%s/%s", UIDIR, "nm-strongswan-dialog.ui");
	priv->builder = gtk_builder_new ();

	gtk_builder_set_translation_domain (priv->builder, GETTEXT_PACKAGE);

	if (!gtk_builder_add_from_file (priv->builder, ui_file, error)) {
		g_warning ("Couldn't load builder file: %s",
		           error && *error ? (*error)->message : "(unknown)");
		g_clear_error (error);
		g_set_error (error, STRONGSWAN_PLUGIN_UI_ERROR, 0,
		             "could not load required resources at %s", ui_file);
		g_free (ui_file);
		g_object_unref (object);
		return NULL;
	}
	g_free (ui_file);

	priv->widget = GTK_WIDGET (gtk_builder_get_object (priv->builder, "strongswan-vbox")	);
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

	if (priv->builder)
		g_object_unref (priv->builder);

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
	/* TODO: implement delete_connection to purge associated secrets */
}


G_MODULE_EXPORT NMVpnPluginUiInterface *
nm_vpn_plugin_ui_factory (GError **error)
{
	if (error)
		g_return_val_if_fail (*error == NULL, NULL);

	return NM_VPN_PLUGIN_UI_INTERFACE (g_object_new (STRONGSWAN_TYPE_PLUGIN_UI, NULL));
}
