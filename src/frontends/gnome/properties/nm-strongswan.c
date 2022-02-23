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

#include <glib.h>
#include <glib/gi18n-lib.h>
#include <gtk/gtk.h>

#ifdef NM_STRONGSWAN_OLD
#define NM_VPN_LIBNM_COMPAT
#include <nm-vpn-plugin-ui-interface.h>
#include <nm-setting-vpn.h>
#include <nm-setting-connection.h>
#include <nm-ui-utils.h>
#else
#include <NetworkManager.h>
#include <nma-ui-utils.h>
#endif

#include "nm-strongswan.h"

#define STRONGSWAN_PLUGIN_NAME    _("IPsec/IKEv2 (strongswan)")
#define STRONGSWAN_PLUGIN_DESC    _("IPsec with the IKEv2 key exchange protocol.")
#define STRONGSWAN_PLUGIN_SERVICE "org.freedesktop.NetworkManager.strongswan"
#define NM_DBUS_SERVICE_STRONGSWAN "org.freedesktop.NetworkManager.strongswan"

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

/************** UI widget class **************/

static void strongswan_plugin_ui_widget_interface_init (NMVpnEditorInterface *iface_class);

typedef struct {
	GtkBuilder *builder;
	GtkWidget *widget;
} StrongswanPluginUiWidgetPrivate;

G_DEFINE_TYPE_EXTENDED (StrongswanPluginUiWidget, strongswan_plugin_ui_widget, G_TYPE_OBJECT, 0,
						G_ADD_PRIVATE (StrongswanPluginUiWidget)
						G_IMPLEMENT_INTERFACE (NM_TYPE_VPN_EDITOR,
											   strongswan_plugin_ui_widget_interface_init))

#define STRONGSWAN_PLUGIN_UI_WIDGET_GET_PRIVATE(o) ((StrongswanPluginUiWidgetPrivate*)strongswan_plugin_ui_widget_get_instance_private(o))

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
	widget = GTK_WIDGET (gtk_builder_get_object (priv->builder, "method-combo"));
	switch (gtk_combo_box_get_active (GTK_COMBO_BOX (widget)))
	{
		case 3:
		{
			widget = GTK_WIDGET (gtk_builder_get_object (priv->builder, "passwd-entry"));
			switch (nma_utils_menu_to_secret_flags(widget))
			{
				case NM_SETTING_SECRET_FLAG_NONE:
				case NM_SETTING_SECRET_FLAG_AGENT_OWNED:
					str = (char *) gtk_entry_get_text (GTK_ENTRY (widget));
					if (str && strlen (str) < 20) {
						g_set_error (error,
									 STRONGSWAN_PLUGIN_UI_ERROR,
									 STRONGSWAN_PLUGIN_UI_ERROR_INVALID_PROPERTY,
									 "password is too short");
						return FALSE;
					}
					break;
				default:
					break;
			}
		}
	}
	return TRUE;
}

static void update_user_field (StrongswanPluginUiWidgetPrivate *priv, gboolean enabled)
{
	gtk_widget_set_sensitive (GTK_WIDGET (gtk_builder_get_object (priv->builder, "user-label")), enabled);
	gtk_widget_set_sensitive (GTK_WIDGET (gtk_builder_get_object (priv->builder, "user-entry")), enabled);
}

static void update_pass_field (StrongswanPluginUiWidgetPrivate *priv, gboolean enabled)
{
	gtk_widget_set_sensitive (GTK_WIDGET (gtk_builder_get_object (priv->builder, "passwd-show")), enabled);
	gtk_widget_set_sensitive (GTK_WIDGET (gtk_builder_get_object (priv->builder, "passwd-label")), enabled);
	gtk_widget_set_sensitive (GTK_WIDGET (gtk_builder_get_object (priv->builder, "passwd-entry")), enabled);
}

static void update_cert_fields (StrongswanPluginUiWidgetPrivate *priv, gboolean enabled)
{
	GtkWidget *widget = GTK_WIDGET (gtk_builder_get_object (priv->builder, "cert-combo"));
	gboolean cert = FALSE, key = FALSE;

	switch (gtk_combo_box_get_active (GTK_COMBO_BOX (widget)))
	{
		default:
			gtk_combo_box_set_active (GTK_COMBO_BOX (widget), 0);
			/* FALL */
		case 0:
			update_pass_field (priv, TRUE);
			cert = key = TRUE;
			break;
		case 1:
			cert = TRUE;
			break;
		case 2:
			break;
	}

	gtk_widget_set_sensitive (GTK_WIDGET (gtk_builder_get_object (priv->builder, "cert-label")), enabled);
	gtk_widget_set_sensitive (GTK_WIDGET (gtk_builder_get_object (priv->builder, "cert-combo")), enabled);
	gtk_widget_set_sensitive (GTK_WIDGET (gtk_builder_get_object (priv->builder, "usercert-label")), enabled && cert);
	gtk_widget_set_sensitive (GTK_WIDGET (gtk_builder_get_object (priv->builder, "usercert-button")), enabled && cert);
	gtk_widget_set_sensitive (GTK_WIDGET (gtk_builder_get_object (priv->builder, "userkey-label")), enabled && key);
	gtk_widget_set_sensitive (GTK_WIDGET (gtk_builder_get_object (priv->builder, "userkey-button")), enabled && key);
}

static void update_sensitive (StrongswanPluginUiWidgetPrivate *priv)
{
	GtkWidget *widget = GTK_WIDGET (gtk_builder_get_object (priv->builder, "method-combo"));

	switch (gtk_combo_box_get_active (GTK_COMBO_BOX (widget)))
	{
		default:
			gtk_combo_box_set_active (GTK_COMBO_BOX (widget), 0);
			/* FALL */
		case 0:
			update_user_field (priv, TRUE);
			update_pass_field (priv, TRUE);
			update_cert_fields (priv, FALSE);
			break;
		case 1:
		case 2:
			update_user_field (priv, FALSE);
			update_pass_field (priv, FALSE);
			update_cert_fields (priv, TRUE);
			break;
		case 3:
			update_user_field (priv, FALSE);
			update_pass_field (priv, TRUE);
			update_cert_fields (priv, FALSE);
			break;
	}

}

static void
settings_changed_cb (GtkWidget *widget, gpointer user_data)
{
	StrongswanPluginUiWidget *self = STRONGSWAN_PLUGIN_UI_WIDGET (user_data);
	StrongswanPluginUiWidgetPrivate *priv = STRONGSWAN_PLUGIN_UI_WIDGET_GET_PRIVATE (self);

	if (widget == GTK_WIDGET (gtk_builder_get_object (priv->builder, "method-combo")) ||
		widget == GTK_WIDGET (gtk_builder_get_object (priv->builder, "cert-combo")))
	{
		update_sensitive (priv);
	}
	g_signal_emit_by_name (STRONGSWAN_PLUGIN_UI_WIDGET (user_data), "changed");
}

static void
show_toggled_cb (GtkCheckButton *button, StrongswanPluginUiWidget *self)
{
	StrongswanPluginUiWidgetPrivate *priv = STRONGSWAN_PLUGIN_UI_WIDGET_GET_PRIVATE (self);
	GtkWidget *widget;
	gboolean visible;

	visible = gtk_toggle_button_get_active (GTK_TOGGLE_BUTTON (button));

	widget = GTK_WIDGET (gtk_builder_get_object (priv->builder, "passwd-entry"));
	gtk_entry_set_visibility (GTK_ENTRY (widget), visible);
}

static void
toggle_proposal_cb(GtkCheckButton *button, StrongswanPluginUiWidget *self)
{
	StrongswanPluginUiWidgetPrivate *priv = STRONGSWAN_PLUGIN_UI_WIDGET_GET_PRIVATE (self);
	gboolean visible = gtk_toggle_button_get_active(GTK_TOGGLE_BUTTON(button));
	gtk_widget_set_sensitive(GTK_WIDGET(gtk_builder_get_object(priv->builder, "ike-entry")), visible);
	gtk_widget_set_sensitive(GTK_WIDGET(gtk_builder_get_object(priv->builder, "esp-entry")), visible);
}

static void
password_storage_changed_cb (GObject *entry, GParamSpec *pspec, gpointer user_data)
{
	settings_changed_cb (NULL, STRONGSWAN_PLUGIN_UI_WIDGET (user_data));
}

static void
init_password_icon (StrongswanPluginUiWidget *self, NMSettingVpn *settings,
					const char *secret_key, const char *entry_name)
{
	StrongswanPluginUiWidgetPrivate *priv = STRONGSWAN_PLUGIN_UI_WIDGET_GET_PRIVATE (self);
	GtkWidget *entry;
	const char *value = NULL;
	NMSettingSecretFlags pw_flags = NM_SETTING_SECRET_FLAG_NONE;

	/* If there's already a password and the password type can't be found in
	 * the VPN settings, default to saving it.  Otherwise, always ask for it.
	 */
	entry = GTK_WIDGET (gtk_builder_get_object (priv->builder, entry_name));

	nma_utils_setup_password_storage (entry, 0, NM_SETTING (settings), secret_key, TRUE, FALSE);

	/* If there's no password and no flags in the setting,
	 * initialize flags as "always-ask".
	 */
	if (settings)
	{
		nm_setting_get_secret_flags (NM_SETTING (settings), secret_key, &pw_flags, NULL);
	}

	value = gtk_entry_get_text (GTK_ENTRY (entry));
	if ((!value || !*value) && (pw_flags == NM_SETTING_SECRET_FLAG_NONE))
	{
		nma_utils_update_password_storage (entry, NM_SETTING_SECRET_FLAG_NOT_SAVED,
										   NM_SETTING (settings), secret_key);
	}

	g_signal_connect (entry, "notify::secondary-icon-name",
					  G_CALLBACK (password_storage_changed_cb), self);
}

static gboolean
init_plugin_ui (StrongswanPluginUiWidget *self, NMConnection *connection, GError **error)
{
	StrongswanPluginUiWidgetPrivate *priv = STRONGSWAN_PLUGIN_UI_WIDGET_GET_PRIVATE (self);
	NMSettingVpn *settings;
	GtkWidget *widget;
	const char *value, *method;

	settings = NM_SETTING_VPN(nm_connection_get_setting(connection, NM_TYPE_SETTING_VPN));

	method = nm_setting_vpn_get_data_item (settings, "method");

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

	widget = GTK_WIDGET (gtk_builder_get_object (priv->builder, "remote-identity-entry"));
	value = nm_setting_vpn_get_data_item (settings, "remote-identity");
	if (value)
		gtk_entry_set_text (GTK_ENTRY (widget), value);
	g_signal_connect (G_OBJECT (widget), "changed", G_CALLBACK (settings_changed_cb), self);

	widget = GTK_WIDGET (gtk_builder_get_object (priv->builder, "server-port-entry"));
	value = nm_setting_vpn_get_data_item (settings, "server-port");
	if (value)
		gtk_entry_set_text (GTK_ENTRY (widget), value);
	g_signal_connect (G_OBJECT (widget), "changed", G_CALLBACK (settings_changed_cb), self);

	widget = GTK_WIDGET (gtk_builder_get_object (priv->builder, "local-identity-entry"));
	value = nm_setting_vpn_get_data_item (settings, "local-identity");
	/* fallback to the username for old PSK configs */
	if (!value && method && g_strcmp0 (method, "psk") == 0)
		value = nm_setting_vpn_get_data_item (settings, "user");
	if (value)
		gtk_entry_set_text (GTK_ENTRY (widget), value);
	g_signal_connect (G_OBJECT (widget), "changed", G_CALLBACK (settings_changed_cb), self);

	widget = GTK_WIDGET (gtk_builder_get_object (priv->builder, "user-entry"));
	value = nm_setting_vpn_get_data_item (settings, "user");
	/* PSK auth now uses local identity, see above */
	if (value && method && g_strcmp0 (method, "psk") != 0)
		gtk_entry_set_text (GTK_ENTRY (widget), value);
	g_signal_connect (G_OBJECT (widget), "changed", G_CALLBACK (settings_changed_cb), self);

	widget = GTK_WIDGET (gtk_builder_get_object (priv->builder, "passwd-show"));
	g_signal_connect (G_OBJECT (widget), "toggled", G_CALLBACK (show_toggled_cb), self);
	widget = GTK_WIDGET (gtk_builder_get_object (priv->builder, "passwd-entry"));
	value = nm_setting_vpn_get_secret (settings, "password");
	if (value)
		gtk_entry_set_text (GTK_ENTRY (widget), value);
	g_signal_connect (G_OBJECT (widget), "changed", G_CALLBACK (settings_changed_cb), self);
	init_password_icon (self, settings, "password", "passwd-entry");

	widget = GTK_WIDGET (gtk_builder_get_object (priv->builder, "method-combo"));
	gtk_combo_box_text_append_text (GTK_COMBO_BOX_TEXT (widget), _("EAP (Username/Password)"));
	gtk_combo_box_text_append_text (GTK_COMBO_BOX_TEXT (widget), _("Certificate"));
	gtk_combo_box_text_append_text (GTK_COMBO_BOX_TEXT (widget), _("EAP-TLS"));
	gtk_combo_box_text_append_text (GTK_COMBO_BOX_TEXT (widget), _("Pre-shared key"));
	if (method) {
		if (g_strcmp0 (method, "eap") == 0) {
			gtk_combo_box_set_active (GTK_COMBO_BOX (widget), 0);
		}
		if (g_strcmp0 (method, "cert") == 0 ||
			g_strcmp0 (method, "key") == 0 ||
			g_strcmp0 (method, "agent") == 0 ||
			g_strcmp0 (method, "smartcard") == 0)
		{
			gtk_combo_box_set_active (GTK_COMBO_BOX (widget), 1);
		}
		if (g_strcmp0 (method, "eap-tls") == 0) {
			gtk_combo_box_set_active (GTK_COMBO_BOX (widget), 2);
		}
		if (g_strcmp0 (method, "psk") == 0) {
			gtk_combo_box_set_active (GTK_COMBO_BOX (widget), 3);
		}
	}
	if (gtk_combo_box_get_active (GTK_COMBO_BOX (widget)) == -1)
	{
		gtk_combo_box_set_active (GTK_COMBO_BOX (widget), 0);
	}
	g_signal_connect (G_OBJECT (widget), "changed", G_CALLBACK (settings_changed_cb), self);

	widget = GTK_WIDGET (gtk_builder_get_object (priv->builder, "cert-combo"));
	gtk_combo_box_text_append_text (GTK_COMBO_BOX_TEXT (widget), _("Certificate/private key"));
	gtk_combo_box_text_append_text (GTK_COMBO_BOX_TEXT (widget), _("Certificate/ssh-agent"));
	gtk_combo_box_text_append_text (GTK_COMBO_BOX_TEXT (widget), _("Smartcard"));
	value = nm_setting_vpn_get_data_item (settings, "cert-source");
	if (!value) {
		value = method;
	}
	if (value) {
		if (g_strcmp0 (value, "file") == 0 ||
			g_strcmp0 (value, "key") == 0)
		{
			gtk_combo_box_set_active (GTK_COMBO_BOX (widget), 0);
		}
		if (g_strcmp0 (value, "agent") == 0) {
			gtk_combo_box_set_active (GTK_COMBO_BOX (widget), 1);
		}
		if (g_strcmp0 (value, "smartcard") == 0) {
			gtk_combo_box_set_active (GTK_COMBO_BOX (widget), 2);
		}
	}
	if (gtk_combo_box_get_active (GTK_COMBO_BOX (widget)) == -1)
	{
		gtk_combo_box_set_active (GTK_COMBO_BOX (widget), 0);
	}
	g_signal_connect (G_OBJECT (widget), "changed", G_CALLBACK (settings_changed_cb), self);
	update_sensitive (priv);

	widget = GTK_WIDGET (gtk_builder_get_object (priv->builder, "usercert-button"));
	value = nm_setting_vpn_get_data_item (settings, "usercert");
	if (value)
		gtk_file_chooser_set_filename (GTK_FILE_CHOOSER (widget), value);
	g_signal_connect (G_OBJECT (widget), "selection-changed", G_CALLBACK (settings_changed_cb), self);

	widget = GTK_WIDGET (gtk_builder_get_object (priv->builder, "userkey-button"));
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

	widget = GTK_WIDGET (gtk_builder_get_object (priv->builder, "proposal-check"));
	value = nm_setting_vpn_get_data_item(settings, "proposal");
	if (value && strcmp(value, "yes") == 0)
		gtk_toggle_button_set_active(GTK_TOGGLE_BUTTON(widget), TRUE);
	else
		toggle_proposal_cb(GTK_CHECK_BUTTON(widget), self);
	g_signal_connect (G_OBJECT (widget), "toggled", G_CALLBACK (toggle_proposal_cb), self);

	widget = GTK_WIDGET(gtk_builder_get_object(priv->builder, "ike-entry"));
	value = nm_setting_vpn_get_data_item(settings, "ike");
	if (value)
	{
		value = g_strdelimit (g_strdup (value), ";", ',');
		gtk_entry_set_text (GTK_ENTRY (widget), value);
		g_free ((char*)value);
	}
	g_signal_connect (G_OBJECT (widget), "changed", G_CALLBACK (settings_changed_cb), self);

	widget = GTK_WIDGET(gtk_builder_get_object(priv->builder, "esp-entry"));
	value = nm_setting_vpn_get_data_item(settings, "esp");
	if (value)
	{
		value = g_strdelimit (g_strdup (value), ";", ',');
		gtk_entry_set_text (GTK_ENTRY (widget), value);
		g_free ((char*)value);
	}
	g_signal_connect (G_OBJECT (widget), "changed", G_CALLBACK (settings_changed_cb), self);

	return TRUE;
}

static GObject *
get_widget (NMVpnEditor *iface)
{
	StrongswanPluginUiWidget *self = STRONGSWAN_PLUGIN_UI_WIDGET (iface);
	StrongswanPluginUiWidgetPrivate *priv = STRONGSWAN_PLUGIN_UI_WIDGET_GET_PRIVATE (self);

	return G_OBJECT (priv->widget);
}

static void
save_password_and_flags (NMSettingVpn *settings, GtkBuilder *builder,
						 const char *entry_name, const char *secret_key)
{
	NMSettingSecretFlags flags;
	const char *password;
	GtkWidget *entry;

	/* Get secret flags */
	entry = GTK_WIDGET (gtk_builder_get_object (builder, entry_name));
	flags = nma_utils_menu_to_secret_flags (entry);

	/* Save password and convert flags to legacy data items */
	switch (flags) {
		case NM_SETTING_SECRET_FLAG_NONE:
			/* FALL */
		case NM_SETTING_SECRET_FLAG_AGENT_OWNED:
			password = gtk_entry_get_text (GTK_ENTRY (entry));
			if (password && strlen (password))
			{
				nm_setting_vpn_add_secret (settings, secret_key, password);
			}
			break;
		default:
			break;
	}

	/* Set new secret flags */
	nm_setting_set_secret_flags (NM_SETTING (settings), secret_key, flags, NULL);
}


static void
save_file_chooser (NMSettingVpn *settings, GtkBuilder *builder,
				   const char *name, const char *key)
{
	GtkWidget *chooser;
	char *str;

	chooser = GTK_WIDGET (gtk_builder_get_object (builder, name));
	str = (char *) gtk_file_chooser_get_filename (GTK_FILE_CHOOSER (chooser));
	if (str) {
		nm_setting_vpn_add_data_item (settings, key, str);
	}
}

static void
save_entry (NMSettingVpn *settings, GtkBuilder *builder,
			const char *name, const char *key)
{
	GtkWidget *entry;
	const char *str;

	entry = GTK_WIDGET (gtk_builder_get_object (builder, name));
	str = (char *) gtk_entry_get_text (GTK_ENTRY (entry));
	if (str && strlen (str)) {
		nm_setting_vpn_add_data_item (settings, key, str);
	}
}

static void
save_cert (NMSettingVpn *settings, GtkBuilder *builder)
{
	GtkWidget *widget;
	gboolean cert = FALSE, key = FALSE;
	char *str;

	widget = GTK_WIDGET (gtk_builder_get_object (builder, "cert-combo"));
	switch (gtk_combo_box_get_active (GTK_COMBO_BOX (widget)))
	{
		default:
		case 0:
			save_password_and_flags (settings, builder, "passwd-entry",
									 "password");
			cert = key = TRUE;
			str = "file";
			break;
		case 1:
			cert = TRUE;
			str = "agent";
			break;
		case 2:
			nm_setting_set_secret_flags (NM_SETTING (settings), "password",
										 NM_SETTING_SECRET_FLAG_NOT_SAVED, NULL);
			str = "smartcard";
			break;
	}
	nm_setting_vpn_add_data_item (settings, "cert-source", str);

	if (cert) {
		save_file_chooser (settings, builder, "usercert-button", "usercert");
	}
	if (key) {
		save_file_chooser (settings, builder, "userkey-button", "userkey");
	}
}

static gboolean
update_connection (NMVpnEditor *iface,
				   NMConnection *connection,
				   GError **error)
{
	StrongswanPluginUiWidget *self = STRONGSWAN_PLUGIN_UI_WIDGET (iface);
	StrongswanPluginUiWidgetPrivate *priv = STRONGSWAN_PLUGIN_UI_WIDGET_GET_PRIVATE (self);
	NMSettingVpn *settings;
	GtkWidget *widget;
	gboolean active;
	char *str;

	if (!check_validity (self, error))
		return FALSE;
	settings = NM_SETTING_VPN (nm_setting_vpn_new ());

	g_object_set (settings, NM_SETTING_VPN_SERVICE_TYPE,
				  NM_DBUS_SERVICE_STRONGSWAN, NULL);

	save_entry (settings, priv->builder, "address-entry", "address");
	save_file_chooser (settings, priv->builder, "certificate-button", "certificate");
	save_entry (settings, priv->builder, "remote-identity-entry", "remote-identity");
	save_entry (settings, priv->builder, "server-port-entry", "server-port");
	save_entry (settings, priv->builder, "local-identity-entry", "local-identity");

	widget = GTK_WIDGET (gtk_builder_get_object (priv->builder, "method-combo"));
	switch (gtk_combo_box_get_active (GTK_COMBO_BOX (widget)))
	{
		default:
		case 0:
			save_entry (settings, priv->builder, "user-entry", "user");
			save_password_and_flags (settings, priv->builder, "passwd-entry", "password");
			str = "eap";
			break;
		case 1:
			save_cert (settings, priv->builder);
			str = "cert";
			break;
		case 2:
			save_cert (settings, priv->builder);
			str = "eap-tls";
			break;
		case 3:
			save_entry (settings, priv->builder, "user-entry", "user");
			save_password_and_flags (settings, priv->builder, "passwd-entry", "password");
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

	widget = GTK_WIDGET (gtk_builder_get_object (priv->builder, "proposal-check"));
	active = gtk_toggle_button_get_active(GTK_TOGGLE_BUTTON(widget));
	nm_setting_vpn_add_data_item (settings, "proposal", active ? "yes" : "no");

	widget = GTK_WIDGET (gtk_builder_get_object (priv->builder, "ike-entry"));
	str = (char *) gtk_entry_get_text (GTK_ENTRY (widget));
	if (str && strlen (str)) {
		str = g_strdelimit (g_strdup (str), ",", ';');
		nm_setting_vpn_add_data_item (settings, "ike", str);
		g_free (str);
	}

	widget = GTK_WIDGET (gtk_builder_get_object (priv->builder, "esp-entry"));
	str = (char *) gtk_entry_get_text (GTK_ENTRY (widget));
	if (str && strlen (str)) {
		str = g_strdelimit (g_strdup (str), ",", ';');
		nm_setting_vpn_add_data_item (settings, "esp", str);
		g_free (str);
	}

	nm_connection_add_setting (connection, NM_SETTING (settings));
	return TRUE;
}

static NMVpnEditor *
nm_vpn_plugin_ui_widget_interface_new (NMConnection *connection, GError **error)
{
	NMVpnEditor *object;
	StrongswanPluginUiWidgetPrivate *priv;
	char *ui_file;

	if (error)
		g_return_val_if_fail (*error == NULL, NULL);

	object = g_object_new (STRONGSWAN_TYPE_PLUGIN_UI_WIDGET, NULL);
	if (!object) {
		g_set_error (error, STRONGSWAN_PLUGIN_UI_ERROR, 0, "could not create strongswan object");
		return NULL;
	}

	priv = STRONGSWAN_PLUGIN_UI_WIDGET_GET_PRIVATE ((StrongswanPluginUiWidget*)object);
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
	GtkWidget *widget;

	widget = GTK_WIDGET (gtk_builder_get_object (priv->builder, "passwd-entry"));
	g_signal_handlers_disconnect_by_func (G_OBJECT (widget), G_CALLBACK (password_storage_changed_cb), plugin);

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

	object_class->dispose = dispose;
}

static void
strongswan_plugin_ui_widget_init (StrongswanPluginUiWidget *plugin)
{
}

static void
strongswan_plugin_ui_widget_interface_init (NMVpnEditorInterface *iface_class)
{
	/* interface implementation */
	iface_class->get_widget = get_widget;
	iface_class->update_connection = update_connection;
}

static guint32
get_capabilities (NMVpnEditorPlugin *iface)
{
	return NM_VPN_EDITOR_PLUGIN_CAPABILITY_IPV6;
}

static NMVpnEditor *
get_editor (NMVpnEditorPlugin *iface, NMConnection *connection, GError **error)
{
	return nm_vpn_plugin_ui_widget_interface_new (connection, error);
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
	if (error)
		g_return_val_if_fail (*error == NULL, NULL);

	return g_object_new (STRONGSWAN_TYPE_PLUGIN_UI, NULL);
}
