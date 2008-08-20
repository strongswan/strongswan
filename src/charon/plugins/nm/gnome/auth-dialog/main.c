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
 *
 * $Id$
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <string.h>
#include <glib/gi18n.h>
#include <gtk/gtk.h>
#include <gnome-keyring.h>
#include <libgnomeui/libgnomeui.h>

#define NM_DBUS_SERVICE_STRONGSWAN    "org.freedesktop.NetworkManager.strongswan"

static char *lookup(char *name, char *service)
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

int main (int argc, char *argv[])
{
	static gboolean retry = FALSE;
	static gchar *name = NULL, *id = NULL, *service = NULL, *keyring = NULL, *pass;
	GOptionContext *context;
	GnomeProgram *program = NULL;
	int exit_status = 1;
	char buf;
	guint32 itemid;
	GtkWidget *dialog;
	GOptionEntry entries[] = {
		{ "reprompt", 'r', 0, G_OPTION_ARG_NONE, &retry, "Reprompt for passwords", NULL},
		{ "id", 'i', 0, G_OPTION_ARG_STRING, &id, "ID of VPN connection", NULL},
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
	
	if (id == NULL || name == NULL || service == NULL)
	{
		fprintf (stderr, "Have to supply ID, name, and service\n");
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
	
	pass = lookup(name, service);
	if (!pass || retry)
	{
		dialog = gnome_password_dialog_new(_("VPN password required"),
							_("Password required to establish VPN connection:"),
							NULL, NULL, TRUE);
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
	printf("\n\n");
	/* flush output, wait for input */
	fflush(stdout);
	fread(&buf, 1, sizeof(buf), stdin);
	g_object_unref(program);
	return 0;
}

