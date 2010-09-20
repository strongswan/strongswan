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

	gchar *current;
};

HD_DEFINE_PLUGIN_MODULE_EXTENDED (StrongswanStatus, strongswan_status, \
		HD_TYPE_STATUS_MENU_ITEM, {}, { \
			strongswan_connection_register (G_TYPE_MODULE (plugin)); \
			strongswan_connections_register (G_TYPE_MODULE (plugin)); }, {});

static void
dialog_response (GtkDialog *dialog, gint response_id, StrongswanStatus *plugin)
{
	StrongswanStatusPrivate *priv = plugin->priv;
	g_object_unref (priv->dialog);
	priv->dialog = NULL;
}

static void
connect_clicked (HildonButton *button, StrongswanStatus *plugin)
{
	StrongswanStatusPrivate *priv = plugin->priv;
	gtk_dialog_response (GTK_DIALOG (priv->dialog), GTK_RESPONSE_OK);
}

static void
disconnect_clicked (HildonButton *button, StrongswanStatus *plugin)
{
	StrongswanStatusPrivate *priv = plugin->priv;
	gtk_dialog_response (GTK_DIALOG (priv->dialog), GTK_RESPONSE_OK);
}

static void
button_clicked (HildonButton *button,  StrongswanStatus *plugin)
{
	StrongswanStatusPrivate *priv = plugin->priv;

	priv->dialog = gtk_dialog_new ();
	gtk_window_set_title (GTK_WINDOW (priv->dialog),  "strongSwan VPN");
	g_signal_connect (priv->dialog, "response",
					  G_CALLBACK (dialog_response), plugin);

	GtkWidget *vbox = GTK_DIALOG (priv->dialog)->vbox;

	if (priv->current)
	{
		/* connected case */
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
	else
	{
		/* unconnected case */
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

	gtk_widget_show_all (priv->dialog);
}

static void
load_icons (StrongswanStatusPrivate *priv)
{
	GtkIconTheme *theme = gtk_icon_theme_get_default ();
	priv->icons.status_open = gtk_icon_theme_load_icon (theme,
								"strongswan_lock_open",
								ICON_SIZE_STATUS, GTK_ICON_LOOKUP_NO_SVG, NULL);
	priv->icons.status_close = gtk_icon_theme_load_icon (theme,
								"strongswan_lock_close",
								ICON_SIZE_STATUS, GTK_ICON_LOOKUP_NO_SVG, NULL);
	priv->icons.button_open = gtk_icon_theme_load_icon (theme,
								"strongswan_lock_open",
								ICON_SIZE_BUTTON, GTK_ICON_LOOKUP_NO_SVG, NULL);
	priv->icons.button_close = gtk_icon_theme_load_icon (theme,
								"strongswan_lock_close",
								ICON_SIZE_BUTTON, GTK_ICON_LOOKUP_NO_SVG, NULL);
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
	if (priv->dialog)
	{
		priv->dialog = (g_object_unref (priv->dialog), NULL);
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
