/*
 * Copyright (C) 2008-2011 Martin Willi
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
#include <libsecret/secret.h>
#include <libgnomeui/libgnomeui.h>

#include <NetworkManager.h>
#include <nm-vpn-service-plugin.h>

#define NM_DBUS_SERVICE_STRONGSWAN	"org.freedesktop.NetworkManager.strongswan"

/**
 * Wait for quit input
 */
static void wait_for_quit (void)
{
	GString *str;
	char c;
	ssize_t n;
	time_t start;

	str = g_string_sized_new (10);
	start = time (NULL);
	do {
		errno = 0;
		n = read (0, &c, 1);
		if (n == 0 || (n < 0 && errno == EAGAIN))
			g_usleep (G_USEC_PER_SEC / 10);
		else if (n == 1) {
			g_string_append_c (str, c);
			if (strstr (str->str, "QUIT") || (str->len > 10))
				break;
		} else
			break;
	} while (time (NULL) < start + 20);
	g_string_free (str, TRUE);
}

/**
 * get the connection type
 */
static char* get_connection_type(char *uuid)
{
	GHashTable *data = NULL, *secrets = NULL;
	char *method;

	if (!nm_vpn_service_plugin_read_vpn_details (0, &data, &secrets)) {
		fprintf (stderr, "Failed to read data and secrets from stdin.\n");
		return NULL;
	}

	method = g_hash_table_lookup (data, "method");
	if (method)
		method = g_strdup(method);

	if (data)
		g_hash_table_unref (data);
	if (secrets)
		g_hash_table_unref (secrets);

	return method;
}

int main (int argc, char *argv[])
{
	gboolean retry = FALSE, allow_interaction = FALSE;
	gchar *name = NULL, *uuid = NULL, *service = NULL, *keyring = NULL, *pass;
	GOptionContext *context;
	char *agent, *type;
	guint32 minlen = 0;
	GtkWidget *dialog;
	GOptionEntry entries[] = {
		{ "reprompt", 'r', 0, G_OPTION_ARG_NONE, &retry, "Reprompt for passwords", NULL},
		{ "uuid", 'u', 0, G_OPTION_ARG_STRING, &uuid, "UUID of VPN connection", NULL},
		{ "name", 'n', 0, G_OPTION_ARG_STRING, &name, "Name of VPN connection", NULL},
		{ "service", 's', 0, G_OPTION_ARG_STRING, &service, "VPN service type", NULL},
		{ "allow-interaction", 'i', 0, G_OPTION_ARG_NONE, &allow_interaction, "Allow user interaction", NULL},
		{ NULL }
	};

	bindtextdomain(GETTEXT_PACKAGE, NULL);
	bind_textdomain_codeset(GETTEXT_PACKAGE, "UTF-8");
	textdomain(GETTEXT_PACKAGE);

	gtk_init (&argc, &argv);

	context = g_option_context_new ("- strongswan auth dialog");
	g_option_context_add_main_entries (context, entries, GETTEXT_PACKAGE);
	g_option_context_parse (context, &argc, &argv, NULL);
	g_option_context_free (context);

	if (uuid == NULL || name == NULL || service == NULL)
	{
		fprintf (stderr, "Have to supply UUID, name, and service\n");
		return 1;
	}

	if (strcmp(service, NM_DBUS_SERVICE_STRONGSWAN) != 0)
	{
		fprintf(stderr, "This dialog only works with the '%s' service\n",
				NM_DBUS_SERVICE_STRONGSWAN);
		return 1;
	}

	type = get_connection_type(uuid);
	if (!type)
	{
		fprintf(stderr, "Connection lookup failed\n");
		return 1;
	}
	if (!strcmp(type, "eap") || !strcmp(type, "key") || !strcmp(type, "psk") ||
		!strcmp(type, "smartcard"))
	{
		pass = secret_password_lookup_sync(SECRET_SCHEMA_COMPAT_NETWORK, NULL, NULL,
						   "user", g_get_user_name(),
						   "server", name,
						   "protocol", service,
						   NULL);

		if ((!pass || retry) && allow_interaction)
		{
			if (!strcmp(type, "eap"))
			{
				dialog = gnome_password_dialog_new(_("VPN password required"),
							_("EAP password required to establish VPN connection:"),
							NULL, NULL, TRUE);
				gnome_password_dialog_set_show_remember(GNOME_PASSWORD_DIALOG(dialog), TRUE);
			}
			else if (!strcmp(type, "key"))
			{
				dialog = gnome_password_dialog_new(_("VPN password required"),
							_("Private key decryption password required to establish VPN connection:"),
							NULL, NULL, TRUE);
				gnome_password_dialog_set_show_remember(GNOME_PASSWORD_DIALOG(dialog), TRUE);
			}
			else if (!strcmp(type, "psk"))
			{
				dialog = gnome_password_dialog_new(_("VPN password required"),
							_("Pre-shared key required to establish VPN connection (min. 20 characters):"),
							NULL, NULL, TRUE);
				gnome_password_dialog_set_show_remember(GNOME_PASSWORD_DIALOG(dialog), TRUE);
				minlen = 20;
			}
			else /* smartcard */
			{
				dialog = gnome_password_dialog_new(_("VPN password required"),
							_("Smartcard PIN required to establish VPN connection:"),
							NULL, NULL, TRUE);
				gnome_password_dialog_set_show_remember(GNOME_PASSWORD_DIALOG(dialog), FALSE);
			}
			gnome_password_dialog_set_show_username(GNOME_PASSWORD_DIALOG(dialog), FALSE);
			if (pass)
			{
				gnome_password_dialog_set_password(GNOME_PASSWORD_DIALOG(dialog), pass);
			}

too_short_retry:
			if (!gnome_password_dialog_run_and_block(GNOME_PASSWORD_DIALOG(dialog)))
			{
				return 1;
			}

			pass = gnome_password_dialog_get_password(GNOME_PASSWORD_DIALOG(dialog));
			if (minlen && strlen(pass) < minlen)
			{
				goto too_short_retry;
			}
			switch (gnome_password_dialog_get_remember(GNOME_PASSWORD_DIALOG(dialog)))
			{
				case GNOME_PASSWORD_DIALOG_REMEMBER_NOTHING:
					break;
				case GNOME_PASSWORD_DIALOG_REMEMBER_SESSION:
					keyring = SECRET_COLLECTION_SESSION;
					/* FALL */
				case GNOME_PASSWORD_DIALOG_REMEMBER_FOREVER:
					if (!secret_password_store_sync(SECRET_SCHEMA_COMPAT_NETWORK,
								keyring, "", pass, NULL, NULL,
								"user", g_get_user_name(),
								"server", name,
								"protocol", service,
								NULL))
					{
						g_warning ("storing password in keyring failed");
					}
					break;
			}
		}
		if (pass)
		{
			printf("password\n%s\n", pass);
			g_free(pass);
		}
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
			if (allow_interaction)
			{
				dialog = gtk_message_dialog_new(NULL, 0, GTK_MESSAGE_ERROR,
							  GTK_BUTTONS_OK,
							  _("Configuration uses ssh-agent for authentication, "
							  "but ssh-agent is not running!"));
				gtk_dialog_run (GTK_DIALOG (dialog));
				gtk_widget_destroy (dialog);
			}
		}
	}
	printf("\n\n");
	/* flush output, wait for input */
	fflush(stdout);
	wait_for_quit ();
	return 0;
}
