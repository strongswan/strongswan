/*
 * Copyright (C) 2008 Martin Willi
 * Hochschule fuer Technik Rapperswil
 * Copyright (C) 2004 Dan Williams 
 * Red Hat, Inc.
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

#include <string.h>
#include <glib/gi18n.h>
#include <gtk/gtk.h>
#include <gnome-keyring.h>
#include <libgnomeui/libgnomeui.h>
#include <gconf/gconf-client.h>
#include <nm-vpn-plugin.h>
#include <nm-setting-vpn.h>
#include <nm-setting-connection.h>

#define NM_DBUS_SERVICE_STRONGSWAN	"org.freedesktop.NetworkManager.strongswan"

/**
 * lookup a password in the keyring
 */
static char *lookup_password(char *name, char *service)
{
	GList *list;
	GList *iter;
	char *pass = NULL;

	if (gnome_keyring_find_network_password_sync(g_get_user_name(), NULL, name,
			NULL, service, NULL, 0, &list) != GNOME_KEYRING_RESULT_OK)
	{
		return NULL;
	}

	for (iter = list; iter; iter = iter->next)
	{
		GnomeKeyringNetworkPasswordData *data = iter->data;
		
		if (strcmp(data->object, "password") == 0 && data->password)
		{
			pass = g_strdup(data->password);
			break;
		}
	}
	gnome_keyring_network_password_list_free(list);
	return pass;
}

/**
 * get the connection type
 */
static char* get_connection_type(char *uuid)
{
	GConfClient *client = NULL;
	GSList *list;
	GSList *iter;
	char *key, *str, *path, *found = NULL, *method = NULL;

	client = gconf_client_get_default();

	list = gconf_client_all_dirs(client, "/system/networking/connections", NULL);
	g_return_val_if_fail(list, NULL);

	for (iter = list; iter; iter = iter->next)
	{
		path = (char *) iter->data;

		key = g_strdup_printf("%s/%s/%s", path,
							  NM_SETTING_CONNECTION_SETTING_NAME,
							  NM_SETTING_CONNECTION_UUID);
		str = gconf_client_get_string(client, key, NULL);
		g_free (key);

		if (str && !strcmp(str, uuid))
		{
			found = g_strdup(path);
		}
		g_free (str);
		if (found)
		{
			break;
		}
	}
	g_slist_foreach(list, (GFunc)g_free, NULL);
	g_slist_free(list);
	
	if (found)
	{
		key = g_strdup_printf ("%s/%s/%s", found,
			                   NM_SETTING_VPN_SETTING_NAME, "method");
		method = gconf_client_get_string(client, key, NULL);
		g_free(found);
		g_free(key);
	}
	g_object_unref(client);
	return method;
}

int main (int argc, char *argv[])
{
	gboolean retry = FALSE;
	gchar *name = NULL, *uuid = NULL, *service = NULL, *keyring = NULL, *pass;
	GOptionContext *context;
	GnomeProgram *program = NULL;
	char buf, *agent, *type;
	guint32 itemid;
	GtkWidget *dialog;
	GOptionEntry entries[] = {
		{ "reprompt", 'r', 0, G_OPTION_ARG_NONE, &retry, "Reprompt for passwords", NULL},
		{ "uuid", 'u', 0, G_OPTION_ARG_STRING, &uuid, "UUID of VPN connection", NULL},
		{ "name", 'n', 0, G_OPTION_ARG_STRING, &name, "Name of VPN connection", NULL},
		{ "service", 's', 0, G_OPTION_ARG_STRING, &service, "VPN service type", NULL},
		{ NULL }
	};

	bindtextdomain(GETTEXT_PACKAGE, NULL);
	bind_textdomain_codeset(GETTEXT_PACKAGE, "UTF-8");
	textdomain(GETTEXT_PACKAGE);

	context = g_option_context_new ("- strongswan auth dialog");
	g_option_context_add_main_entries (context, entries, GETTEXT_PACKAGE);

	program = gnome_program_init ("nm-strongswan-auth-dialog", VERSION,
								LIBGNOMEUI_MODULE,
								argc, argv,
								GNOME_PARAM_GOPTION_CONTEXT, context,
								GNOME_PARAM_NONE);
	
	if (uuid == NULL || name == NULL || service == NULL)
	{
		fprintf (stderr, "Have to supply UUID, name, and service\n");
		g_object_unref (program);
		return 1;
	}
	
	if (strcmp(service, NM_DBUS_SERVICE_STRONGSWAN) != 0)
	{
		fprintf(stderr, "This dialog only works with the '%s' service\n",
				NM_DBUS_SERVICE_STRONGSWAN);
		g_object_unref (program);
		return 1;
	}
	
	type = get_connection_type(uuid);
	if (!type)
	{
		fprintf(stderr, "Connection lookup failed\n");
		g_object_unref (program);
		return 1;
	}
	if (!strcmp(type, "eap") || !strcmp(type, "key"))
	{
		pass = lookup_password(name, service);
		if (!pass || retry)
		{
			if (!strcmp(type, "eap"))
			{
				dialog = gnome_password_dialog_new(_("VPN password required"),
							_("EAP password required to establish VPN connection:"),
							NULL, NULL, TRUE);
			}
			else
			{
				dialog = gnome_password_dialog_new(_("VPN password required"),
							_("Private key decryption password required to establish VPN connection:"),
							NULL, NULL, TRUE);
			}
			gnome_password_dialog_set_show_remember(GNOME_PASSWORD_DIALOG(dialog), TRUE);
			gnome_password_dialog_set_show_username(GNOME_PASSWORD_DIALOG(dialog), FALSE);
			if (pass)
			{
				gnome_password_dialog_set_password(GNOME_PASSWORD_DIALOG(dialog), pass);
			}
			if (!gnome_password_dialog_run_and_block(GNOME_PASSWORD_DIALOG(dialog)))
			{
				g_object_unref (program);
				return 1;
			}

			pass = gnome_password_dialog_get_password(GNOME_PASSWORD_DIALOG(dialog));
			switch (gnome_password_dialog_get_remember(GNOME_PASSWORD_DIALOG(dialog)))
			{
				case GNOME_PASSWORD_DIALOG_REMEMBER_NOTHING:
					break;
				case GNOME_PASSWORD_DIALOG_REMEMBER_SESSION:
					keyring = "session";
					/* FALL */
				case GNOME_PASSWORD_DIALOG_REMEMBER_FOREVER:
					if (gnome_keyring_set_network_password_sync(keyring,
							g_get_user_name(), NULL, name, "password", service, NULL, 0,
							pass, &itemid) != GNOME_KEYRING_RESULT_OK)
					{
						g_warning ("storing password in keyring failed");
					}
					break;
			}
		}
		printf("password\n%s\n", pass);
	}
	else
	{
		agent = getenv("SSH_AUTH_SOCK");
		if (agent)
		{
			printf("agent\n%s\n", agent);
		}
		else
		{
			dialog = gtk_message_dialog_new(NULL, 0, GTK_MESSAGE_ERROR,
						  GTK_BUTTONS_OK, 
						  _("Configuration uses ssh-agent for authentication, "
						  "but ssh-agent is not running!"));
			gtk_dialog_run (GTK_DIALOG (dialog));
			gtk_widget_destroy (dialog);
			return 1;
		}
	}
	printf("\n\n");
	/* flush output, wait for input */
	fflush(stdout);
	if (fread(&buf, 1, sizeof(buf), stdin));
	g_object_unref(program);
	return 0;
}

