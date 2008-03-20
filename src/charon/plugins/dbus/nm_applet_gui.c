/*
 * Copyright (C) 2007 Martin Willi
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
 *
 * $Id$
 */

#include <glade/glade.h>

#define NM_VPN_API_SUBJECT_TO_CHANGE
#include <nm-vpn-ui-interface.h>


typedef struct private_nm_applet_gui_t private_nm_applet_gui_t;

/**
 * Private data of an nm_applet_gui_t object.
 */
struct private_nm_applet_gui_t {

	/**
	 * Implements NetworkManagerVpnUI interface.
	 */
	NetworkManagerVpnUI public;
	
	/**
	 * callback registered by NM to update validity
	 */
	NetworkManagerVpnUIDialogValidityCallback callback;
	 
	/**
	 * loaded Glade XML interface description
	 */
	GladeXML *xml;
	
	/**
	 * root widget to return to druid
	 */
	GtkWidget *widget;
	
	/**
	 * name of the connection
	 */
	GtkEntry *name;
	
	/**
	 * gateway address
	 */
	GtkEntry *gateway;
	
	/**
	 * username
	 */
	GtkEntry *user;
};

static const char *get_display_name(private_nm_applet_gui_t *this)
{
	return "strongSwan (IPsec/IKEv2)";
}

static const char *get_service_name(private_nm_applet_gui_t *this)
{
	return "org.freedesktop.NetworkManager.strongswan";
}

static GtkWidget *get_widget(private_nm_applet_gui_t *this, GSList *properties,
							 GSList *routes, const char *connection_name)
{
	GSList *i;

	gtk_entry_set_text(this->name, "");
	gtk_entry_set_text(this->gateway, "");
	gtk_entry_set_text(this->user, "");
	
	if (connection_name)
	{
		gtk_entry_set_text(this->name, connection_name);
	}

	while (properties)
	{
		const char *key;
		const char *value;

		key = properties->data;
		properties = g_slist_next(properties);
		if (properties)
		{
			value = properties->data;
			if (strcmp(key, "gateway") == 0)
			{
			    gtk_entry_set_text(this->gateway, value);
			}
			if (strcmp(key, "user") == 0)
			{
			    gtk_entry_set_text(this->user, value);
			}
			properties = g_slist_next(properties);
		}
	}
	return this->widget;
}

static GSList *get_properties(private_nm_applet_gui_t *this)
{
	GSList *props = NULL;
	
	props = g_slist_append(props, g_strdup("gateway"));
	props = g_slist_append(props, g_strdup(gtk_entry_get_text(this->gateway)));
	props = g_slist_append(props, g_strdup("user"));
	props = g_slist_append(props, g_strdup(gtk_entry_get_text(this->user)));
	
	return props;
}

static GSList *get_routes(private_nm_applet_gui_t *this)
{
	return NULL;
}

static char *get_connection_name(private_nm_applet_gui_t *this)
{
	const char *name;
	
	name = gtk_entry_get_text(this->name);
	if (name != NULL)
	{
		return g_strdup(name);
	}
	return NULL;
}

static gboolean is_valid(private_nm_applet_gui_t *this)
{
	return TRUE;
}

static void set_validity_changed_callback(private_nm_applet_gui_t *this,
						    NetworkManagerVpnUIDialogValidityCallback callback,
						    gpointer user_data)
{
	this->callback = callback;
}

static void get_confirmation_details(private_nm_applet_gui_t *this, gchar **retval)
{
	*retval = g_strdup_printf("connection %s\n", gtk_entry_get_text(this->name));
}

static gboolean can_export(private_nm_applet_gui_t *this)
{
	return FALSE;
}

static gboolean import_file (private_nm_applet_gui_t *this, const char *path)
{
	return FALSE;
}

static gboolean export(private_nm_applet_gui_t *this, GSList *properties,
					   GSList *routes, const char *connection_name)
{
	return FALSE;
}

NetworkManagerVpnUI* nm_vpn_properties_factory(void)
{
	private_nm_applet_gui_t *this = g_new0(private_nm_applet_gui_t, 1);
	
	this->public.get_display_name = (const char *(*)(NetworkManagerVpnUI *))get_display_name;
    this->public.get_service_name = (const char *(*) (NetworkManagerVpnUI *))get_service_name;
    this->public.get_widget = (GtkWidget *(*) (NetworkManagerVpnUI *self, GSList *, GSList *, const char *))get_widget;
    this->public.get_connection_name = (char *(*) (NetworkManagerVpnUI *))get_connection_name;
    this->public.get_properties = (GSList *(*) (NetworkManagerVpnUI *))get_properties;
    this->public.get_routes = (GSList *(*) (NetworkManagerVpnUI *))get_routes;
    this->public.set_validity_changed_callback = (void (*) (NetworkManagerVpnUI *, NetworkManagerVpnUIDialogValidityCallback, gpointer))set_validity_changed_callback;
    this->public.is_valid = (gboolean (*) (NetworkManagerVpnUI *))is_valid;
    this->public.get_confirmation_details = (void (*)(NetworkManagerVpnUI *, gchar **))get_confirmation_details;
    this->public.can_export = (gboolean (*) (NetworkManagerVpnUI *))can_export;
    this->public.import_file = (gboolean (*) (NetworkManagerVpnUI *, const char *))import_file;
    this->public.export = (gboolean (*) (NetworkManagerVpnUI *, GSList *, GSList *, const char *))export;
    this->public.data = NULL;
    
    this->callback = NULL;
    this->xml = glade_xml_new("/home/martin/strongswan/trunk/src/charon/plugins/dbus/nm_applet_gui.xml", NULL, NULL);
	
	if (this->xml != NULL)
	{
    	this->widget = glade_xml_get_widget(this->xml, "main");
    	this->name = GTK_ENTRY(glade_xml_get_widget(this->xml, "name"));
    	this->gateway = GTK_ENTRY(glade_xml_get_widget(this->xml, "gateway"));
    	this->user = GTK_ENTRY(glade_xml_get_widget(this->xml, "user"));
    		
		if (this->widget && this->name && this->gateway && this->user)
		{
			return &this->public;
		}
	}
	g_free(this);
	return NULL;
}
