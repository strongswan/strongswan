/*
 * Copyright (C) 2010 Tobias Brunner
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

#include <hildon/hildon.h>
#include <libosso.h>

#include "strongswan-status.h"
#include "strongswan-connections.h"

#define STRONGSWAN_STATUS_GET_PRIVATE(object) \
	(G_TYPE_INSTANCE_GET_PRIVATE ((object), \
								  STRONGSWAN_TYPE_STATUS, \
								  StrongswanStatusPrivate))

#define OSSO_CHARON_NAME	"charon"
#define OSSO_CHARON_SERVICE	"org.strongswan."OSSO_CHARON_NAME
#define OSSO_CHARON_OBJECT	"/org/strongswan/"OSSO_CHARON_NAME
#define OSSO_CHARON_IFACE	"org.strongswan."OSSO_CHARON_NAME

#define ICON_SIZE_STATUS 18
#define ICON_SIZE_BUTTON 48

typedef enum
{
	STATUS_DISCONNECTED,
	STATUS_CONNECTING,
	STATUS_CONNECTED,
} StrongswanConnectionStatus;

struct _StrongswanStatusPrivate
{
	struct {
		GdkPixbuf *status_open;
		GdkPixbuf *status_close;
		GdkPixbuf *button_open;
		GdkPixbuf *button_close;
	} icons;

	GtkWidget *dialog;
	GtkWidget *button;
	GtkWidget *image;
	GtkWidget *selector;
	GtkWidget *box;

	osso_context_t *context;

	StrongswanConnections *conns;

	StrongswanConnectionStatus status;
	gchar *current;
};

HD_DEFINE_PLUGIN_MODULE_EXTENDED (StrongswanStatus, strongswan_status, \
		HD_TYPE_STATUS_MENU_ITEM, {}, { \
			strongswan_connection_register (G_TYPE_MODULE (plugin)); \
			strongswan_connections_register (G_TYPE_MODULE (plugin)); }, {});

static void
update_status_menu (StrongswanStatus *plugin)
{
	StrongswanStatusPrivate *priv = plugin->priv;
	switch (priv->status)
	{
		case STATUS_DISCONNECTED:
		{
			hildon_button_set_value (HILDON_BUTTON (priv->button),
									 "Not connected");
			hd_status_plugin_item_set_status_area_icon (
											HD_STATUS_PLUGIN_ITEM (plugin),
											priv->icons.status_open);
			gtk_image_set_from_pixbuf (GTK_IMAGE (priv->image),
									   priv->icons.button_open);
			break;
		}
		case STATUS_CONNECTING:
		{
			gchar *msg = g_strdup_printf ("Connecting to %s...", priv->current);
			hildon_button_set_value (HILDON_BUTTON (priv->button), msg);
			g_free (msg);
			break;
		}
		case STATUS_CONNECTED:
		{
			gchar *msg = g_strdup_printf ("Connected to %s", priv->current);
			hildon_button_set_value (HILDON_BUTTON (priv->button), msg);
			g_free (msg);
			hd_status_plugin_item_set_status_area_icon (
											HD_STATUS_PLUGIN_ITEM (plugin),
											priv->icons.status_close);
			gtk_image_set_from_pixbuf (GTK_IMAGE (priv->image),
									   priv->icons.button_close);
			break;
		}
	}
}

static void
update_dialog_connecting (StrongswanStatus *plugin)
{
	StrongswanStatusPrivate *priv = plugin->priv;

	gtk_widget_set_sensitive (priv->box, FALSE);
	hildon_gtk_window_set_progress_indicator (GTK_WINDOW (priv->dialog), 1);
}

static void
update_dialog_default (StrongswanStatus *plugin)
{
	StrongswanStatusPrivate *priv = plugin->priv;

	gtk_widget_set_sensitive (priv->box, TRUE);
	hildon_gtk_window_set_progress_indicator (GTK_WINDOW (priv->dialog), 0);
}

static void
dialog_response (GtkDialog *dialog, gint response_id, StrongswanStatus *plugin)
{
	StrongswanStatusPrivate *priv = plugin->priv;
	gtk_widget_destroy (priv->dialog);
	priv->dialog = NULL;
}

static void
connect_callback (const gchar* interface, const gchar* method,
				  osso_rpc_t *retval, StrongswanStatus *plugin)
{
	gchar *msg = NULL;
	StrongswanStatusPrivate *priv = plugin->priv;

	if (retval->type == DBUS_TYPE_STRING)
	{	/* unfortunately, this is the only indication that an error occured
		 * for asynchronous calls */
		msg = g_strdup_printf ("Failed to initiate connection: %s",
							   retval->value.s);
	}
	else if (retval->type != DBUS_TYPE_BOOLEAN)
	{
		msg = g_strdup_printf ("Failed to initiate connection: return type");
	}
	else if (!retval->value.b)
	{
		msg = g_strdup_printf ("Failed to connect to %s", priv->current);
	}

	if (msg)
	{
		/* connecting failed */
		priv->current = (g_free (priv->current), NULL);
		priv->status = STATUS_DISCONNECTED;
	}
	else
	{
		msg = g_strdup_printf ("Successfully connected to %s", priv->current);
		priv->status = STATUS_CONNECTED;
	}

	hildon_banner_show_information (NULL, NULL, msg);
	g_free (msg);

	update_status_menu (plugin);

	if (priv->dialog)
	{
		update_dialog_default (plugin);
		gtk_dialog_response (GTK_DIALOG (priv->dialog), GTK_RESPONSE_OK);
	}
}

static gboolean
get_password (StrongswanStatus *plugin, gchar **password)
{
	StrongswanStatusPrivate *priv = plugin->priv;
	gboolean result = FALSE;

	GtkWidget *dialog = gtk_dialog_new_with_buttons (
									"Connecting...",
									GTK_WINDOW(priv->dialog),
									GTK_DIALOG_MODAL | GTK_DIALOG_NO_SEPARATOR,
									GTK_STOCK_CANCEL,
									GTK_RESPONSE_CANCEL,
									GTK_STOCK_OK,
									GTK_RESPONSE_OK,
									NULL);
	GtkWidget *vbox = GTK_DIALOG (dialog)->vbox;
	GtkSizeGroup *group = gtk_size_group_new (GTK_SIZE_GROUP_HORIZONTAL);

	GtkWidget *pass = hildon_entry_new (HILDON_SIZE_AUTO);
	hildon_gtk_entry_set_placeholder_text (GTK_ENTRY (pass), "Password");
	hildon_gtk_entry_set_input_mode (GTK_ENTRY (pass),
									 HILDON_GTK_INPUT_MODE_FULL |
									 HILDON_GTK_INPUT_MODE_INVISIBLE);
	GtkWidget *pcap = hildon_caption_new (group,
										  "Password",
										  pass,
										  NULL,
										  HILDON_CAPTION_OPTIONAL);
	gtk_box_pack_start (GTK_BOX (vbox), pcap, TRUE, TRUE, 0);
	gtk_widget_show_all (dialog);

	gint retval = gtk_dialog_run (GTK_DIALOG (dialog));
	if (retval == GTK_RESPONSE_OK)
	{
		*password = g_strdup (gtk_entry_get_text (GTK_ENTRY (pass)));
		result = TRUE;
	}
	gtk_widget_destroy (dialog);
	return result;
}

static void
connect_clicked (HildonButton *button, StrongswanStatus *plugin)
{
	StrongswanStatusPrivate *priv = plugin->priv;

	priv->current = hildon_touch_selector_get_current_text (
									HILDON_TOUCH_SELECTOR (priv->selector));
	priv->status = STATUS_CONNECTING;
	update_dialog_connecting (plugin);
	update_status_menu (plugin);

	StrongswanConnection *conn = strongswan_connections_get_connection (
															priv->conns,
															priv->current);
	if (!conn)
	{	/* emulate a callback call */
		osso_rpc_t retval;
		retval.type = DBUS_TYPE_STRING;
		retval.value.s = g_strdup ("not found");
		connect_callback (NULL, NULL, &retval, plugin);
		osso_rpc_free_val (&retval);
		return;
	}

	/* this call on the system bus is only needed to start charon as root */
	osso_rpc_t retval;
	osso_return_t result;
	result = osso_rpc_run_system (priv->context,
								  OSSO_CHARON_SERVICE,
								  OSSO_CHARON_OBJECT,
								  OSSO_CHARON_IFACE,
								  "Start",
								  &retval,
								  DBUS_TYPE_INVALID);
	osso_rpc_free_val (&retval);
	if (result != OSSO_OK)
	{
		retval.type = DBUS_TYPE_STRING;
		retval.value.s = g_strdup ("couldn't connect to charon");
		connect_callback (NULL, NULL, &retval, plugin);
		osso_rpc_free_val (&retval);
		return;
	}

	gchar *c_host, *c_cert, *c_user, *c_pass;

	if (!get_password (plugin, &c_pass))
	{
		update_dialog_default (plugin);
		return;
	}

	g_object_get (conn,
				  "host", &c_host,
				  "cert", &c_cert,
				  "user", &c_user,
				  NULL);

	osso_rpc_async_run (priv->context,
						OSSO_CHARON_SERVICE,
						OSSO_CHARON_OBJECT,
						OSSO_CHARON_IFACE,
						"Connect",
						(osso_rpc_async_f*)connect_callback,
						plugin,
						DBUS_TYPE_STRING, priv->current,
						DBUS_TYPE_STRING, c_host,
						DBUS_TYPE_STRING, c_cert,
						DBUS_TYPE_STRING, c_user,
						DBUS_TYPE_STRING, c_pass,
						DBUS_TYPE_INVALID);

	g_free (c_host);
	g_free (c_cert);
	g_free (c_user);
	g_free (c_pass);
}

static void
disconnect_clicked (HildonButton *button, StrongswanStatus *plugin)
{
	osso_return_t result;
	osso_rpc_t retval;
	gchar *msg;
	StrongswanStatusPrivate *priv = plugin->priv;

	gtk_widget_set_sensitive (priv->box, FALSE);
	hildon_gtk_window_set_progress_indicator (GTK_WINDOW (priv->dialog), 1);

	result = osso_rpc_run_system (priv->context,
						OSSO_CHARON_SERVICE,
						OSSO_CHARON_OBJECT,
						OSSO_CHARON_IFACE,
						"Disconnect",
						&retval,
						DBUS_TYPE_INVALID);

	gtk_widget_set_sensitive (priv->box, TRUE);
	hildon_gtk_window_set_progress_indicator (GTK_WINDOW (priv->dialog), 0);

	if (result == OSSO_OK)
	{
		msg = g_strdup_printf ("Successfully disconnected from %s",
							   priv->current);
	}
	else
	{
		msg = g_strdup_printf ("Failed to disconnect from %s", priv->current);
	}
	hildon_banner_show_information (NULL, NULL, msg);
	g_free (msg);

	priv->current = (g_free (priv->current), NULL);
	priv->status = STATUS_DISCONNECTED;

	update_status_menu (plugin);

	gtk_dialog_response (GTK_DIALOG (priv->dialog), GTK_RESPONSE_OK);
}

static void
setup_dialog_disconnected (StrongswanStatus *plugin)
{
	StrongswanStatusPrivate *priv = plugin->priv;

	GtkWidget *vbox = GTK_DIALOG (priv->dialog)->vbox;
	GtkWidget *hbox = gtk_hbox_new (FALSE, 0);
	priv->box = hbox;
	GtkWidget *button = hildon_picker_button_new (
							HILDON_SIZE_FINGER_HEIGHT |
							HILDON_SIZE_AUTO_WIDTH,
							HILDON_BUTTON_ARRANGEMENT_HORIZONTAL);
	hildon_button_set_title (HILDON_BUTTON (button), "Connection:");
	gtk_box_pack_start (GTK_BOX (hbox), button, TRUE, TRUE, 0);

	GtkWidget *selector = hildon_touch_selector_new ();
	priv->selector = selector;
	GtkTreeModel *model = strongswan_connections_get_model (priv->conns);
	hildon_touch_selector_append_text_column (
							HILDON_TOUCH_SELECTOR (selector),
							model,
							TRUE);
	hildon_picker_button_set_selector (HILDON_PICKER_BUTTON (button),
									   HILDON_TOUCH_SELECTOR (selector));

	button = hildon_button_new_with_text (
							HILDON_SIZE_FINGER_HEIGHT |
							HILDON_SIZE_AUTO_WIDTH,
							HILDON_BUTTON_ARRANGEMENT_HORIZONTAL,
							"Connect", NULL);
	gtk_box_pack_start (GTK_BOX (hbox), button, FALSE, FALSE, 0);
	gtk_box_pack_start (GTK_BOX (vbox), hbox, FALSE, FALSE, 0);
	g_signal_connect (button, "clicked", G_CALLBACK (connect_clicked),
					  plugin);
}

static void
setup_dialog_connected (StrongswanStatus *plugin)
{
	StrongswanStatusPrivate *priv = plugin->priv;

	GtkWidget *vbox = GTK_DIALOG (priv->dialog)->vbox;
	GtkWidget *hbox = gtk_hbox_new (FALSE, 0);
	priv->box = hbox;
	GtkWidget *button = hildon_button_new_with_text (
							HILDON_SIZE_FINGER_HEIGHT |
							HILDON_SIZE_AUTO_WIDTH,
							HILDON_BUTTON_ARRANGEMENT_HORIZONTAL,
							"Disconnect", priv->current);
	hildon_button_set_style (HILDON_BUTTON (button),
							 HILDON_BUTTON_STYLE_PICKER);
	g_signal_connect (button, "clicked", G_CALLBACK (disconnect_clicked),
					  plugin);
	gtk_box_pack_start (GTK_BOX (hbox), button, TRUE, TRUE, 0);
	gtk_box_pack_start (GTK_BOX (vbox), hbox, FALSE, FALSE, 0);
}

static void
button_clicked (HildonButton *button,  StrongswanStatus *plugin)
{
	StrongswanStatusPrivate *priv = plugin->priv;

	priv->dialog = gtk_dialog_new ();
	gtk_window_set_title (GTK_WINDOW (priv->dialog),  "strongSwan VPN");
	g_signal_connect (priv->dialog, "response",
					  G_CALLBACK (dialog_response), plugin);

	switch (priv->status)
	{
		case STATUS_DISCONNECTED:
			setup_dialog_disconnected (plugin);
			break;
		case STATUS_CONNECTING:
			setup_dialog_disconnected (plugin);
			update_dialog_connecting (plugin);
			break;
		case STATUS_CONNECTED:
			setup_dialog_connected (plugin);
			break;
	}

	gtk_widget_show_all (priv->dialog);
}

static GdkPixbuf*
load_icon (GtkIconTheme *theme, const gchar *name, gint size)
{
	GdkPixbuf *icon = NULL;
	GdkPixbuf *loaded = gtk_icon_theme_load_icon (theme, name, size,
												  GTK_ICON_LOOKUP_NO_SVG, NULL);
	if (loaded)
	{	/* so we don't have to listen for theme changes, we copy the icon */
		icon = gdk_pixbuf_copy (loaded);
		g_object_unref (loaded);
	}
	return icon;
}

static void
load_icons (StrongswanStatusPrivate *priv)
{
	GtkIconTheme *theme = gtk_icon_theme_get_default ();
	priv->icons.status_open = load_icon (theme, "strongswan_lock_open",
										 ICON_SIZE_STATUS);
	priv->icons.status_close = load_icon (theme, "strongswan_lock_close",
										  ICON_SIZE_STATUS);
	priv->icons.button_open = load_icon (theme, "strongswan_lock_open",
										 ICON_SIZE_BUTTON);
	priv->icons.button_close = load_icon (theme, "strongswan_lock_close",
										  ICON_SIZE_BUTTON);
	if (!priv->icons.status_open || !priv->icons.button_open)
	{
		hildon_banner_show_information (NULL, NULL, "failed to load icons");
	}
}

static void
strongswan_status_init (StrongswanStatus *plugin)
{
	StrongswanStatusPrivate *priv = STRONGSWAN_STATUS_GET_PRIVATE (plugin);
	plugin->priv = priv;

	priv->context = osso_initialize (OSSO_STATUS_SERVICE, "0.0.1", TRUE, NULL);
	if (!priv->context)
	{
		return;
	}

	priv->conns = strongswan_connections_new ();

	load_icons(priv);

	hd_status_plugin_item_set_status_area_icon (HD_STATUS_PLUGIN_ITEM (plugin),
												priv->icons.status_open);

	GtkWidget *button = hildon_button_new_with_text (
							HILDON_SIZE_FINGER_HEIGHT | HILDON_SIZE_AUTO_WIDTH,
							HILDON_BUTTON_ARRANGEMENT_VERTICAL,
							"strongSwan VPN", "Not connected");
	hildon_button_set_style (HILDON_BUTTON (button),
							 HILDON_BUTTON_STYLE_PICKER);
	priv->button = button;
	gtk_container_add (GTK_CONTAINER (plugin), button);

	GtkWidget *image = gtk_image_new_from_pixbuf (priv->icons.button_open);
	priv->image = image;
	hildon_button_set_image (HILDON_BUTTON (button), image);

	gtk_button_set_alignment (GTK_BUTTON (button), 0.0, 0.5);

	g_signal_connect (button, "clicked", G_CALLBACK (button_clicked), plugin);

	gtk_widget_show_all (GTK_WIDGET (plugin));
}

static void
strongswan_status_dispose (GObject *object)
{
	StrongswanStatusPrivate *priv = STRONGSWAN_STATUS (object)->priv;
	if (priv->conns)
	{
		priv->conns = (g_object_unref (priv->conns), NULL);
	}
	if (priv->icons.status_open)
	{
		g_object_unref (priv->icons.status_open);
		priv->icons.status_open = NULL;
	}
	if (priv->icons.status_close)
	{
		g_object_unref (priv->icons.status_close);
		priv->icons.status_close = NULL;
	}
	if (priv->icons.button_open)
	{
		g_object_unref (priv->icons.button_open);
		priv->icons.button_open = NULL;
	}
	if (priv->icons.button_close)
	{
		g_object_unref (priv->icons.button_close);
		priv->icons.button_close = NULL;
	}
	G_OBJECT_CLASS (strongswan_status_parent_class)->dispose (object);
}

static void
strongswan_status_finalize (GObject *object)
{
	StrongswanStatusPrivate *priv = STRONGSWAN_STATUS (object)->priv;
	priv->current = (g_free (priv->current), NULL);
	G_OBJECT_CLASS (strongswan_status_parent_class)->finalize (object);
}

static void
strongswan_status_class_finalize (StrongswanStatusClass *klass)
{
}

static void
strongswan_status_class_init (StrongswanStatusClass *klass)
{
	GObjectClass *object_class = G_OBJECT_CLASS (klass);

	object_class->dispose = strongswan_status_dispose;
	object_class->finalize = strongswan_status_finalize;

	g_type_class_add_private (klass, sizeof (StrongswanStatusPrivate));
}
