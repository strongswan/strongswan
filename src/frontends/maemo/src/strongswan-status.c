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

#define STRONGSWAN_STATUS_GET_PRIVATE(object) \
	(G_TYPE_INSTANCE_GET_PRIVATE ((object), \
								  STRONGSWAN_TYPE_STATUS, \
								  StrongswanStatusPrivate))

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

	GtkWidget *button;
	GtkWidget *image;
};

HD_DEFINE_PLUGIN_MODULE_EXTENDED (StrongswanStatus, strongswan_status, \
		HD_TYPE_STATUS_MENU_ITEM, {}, { \
			strongswan_connection_register (G_TYPE_MODULE (plugin)); \
			strongswan_connections_register (G_TYPE_MODULE (plugin)); }, {});

static void
button_clicked (HildonButton *button,  StrongswanStatus *plugin)
{
	StrongswanStatusPrivate *priv = plugin->priv;
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
