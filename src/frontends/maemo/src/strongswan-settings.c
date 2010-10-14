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

#include <hildon-cp-plugin/hildon-cp-plugin-interface.h>
#include <gtk/gtk.h>
#include <hildon/hildon.h>
#include <hildon/hildon-file-chooser-dialog.h>

#include <string.h>

#include "strongswan-connections.h"

enum {
	RESPONSE_NEW = 1,
	RESPONSE_EDIT,
	RESPONSE_DELETE
};

struct {
	GtkWidget *dialog;
	GtkWidget *list;
	StrongswanConnections *conns;
} ListDialog = { 0, };

/**
 * Callback if no certificate should be selected
 */
void no_certificate(HildonButton *button, gpointer user_data)
{
	gtk_dialog_response (GTK_DIALOG (user_data), GTK_RESPONSE_REJECT);
}

/**
 * Callback to select a certificate
 */
void select_cert(HildonButton *button, gpointer user_data)
{
	GtkWidget *selector = hildon_file_chooser_dialog_new (GTK_WINDOW (user_data), GTK_FILE_CHOOSER_ACTION_OPEN);
	GtkWidget *nocert = hildon_button_new (HILDON_SIZE_FINGER_HEIGHT |
										   HILDON_SIZE_AUTO_WIDTH,
										   HILDON_BUTTON_ARRANGEMENT_VERTICAL);
	hildon_button_set_text (HILDON_BUTTON (nocert),
							"No certificate",
							"Use system-wide CA certificates");
	hildon_button_set_alignment (HILDON_BUTTON (nocert), 0, 0.5, 1, 1);
	g_signal_connect (nocert, "clicked", G_CALLBACK (no_certificate), selector);
	hildon_file_chooser_dialog_add_extra (HILDON_FILE_CHOOSER_DIALOG (selector),
										  nocert);
	gtk_widget_show_all (selector);

	switch (gtk_dialog_run (GTK_DIALOG (selector)))
	{
		case GTK_RESPONSE_OK:
		{
			gchar *file = gtk_file_chooser_get_filename (GTK_FILE_CHOOSER (selector));
			hildon_button_set_value (button, file);
			g_free(file);
			break;
		}
		case GTK_RESPONSE_REJECT:
		{
			hildon_button_set_value (button, "None");
			break;
		}
		default:
			break;
	}
	gtk_widget_destroy (selector);
}

/**
 * Shows a dialog to edit the given connection (or create a new one,
 * if conn is NULL)
 */
static void
edit_connection (gpointer *parent, StrongswanConnection *conn)
{
	GtkWidget *dialog;
	dialog = gtk_dialog_new_with_buttons (
							conn ? "Edit Connection" : "New Connection",
							GTK_WINDOW (parent),
							GTK_DIALOG_MODAL | GTK_DIALOG_NO_SEPARATOR,
							GTK_STOCK_CANCEL,
							GTK_RESPONSE_CANCEL,
							GTK_STOCK_SAVE,
							GTK_RESPONSE_OK,
							NULL);
	GtkWidget *vbox = GTK_DIALOG (dialog)->vbox;
	GtkSizeGroup *group = gtk_size_group_new (GTK_SIZE_GROUP_HORIZONTAL);

	GtkWidget *name = hildon_entry_new (HILDON_SIZE_AUTO);
	hildon_gtk_entry_set_placeholder_text (GTK_ENTRY (name), "Connection Name");
	hildon_gtk_entry_set_input_mode (GTK_ENTRY (name),
									 HILDON_GTK_INPUT_MODE_AUTOCAP |
									 HILDON_GTK_INPUT_MODE_ALPHA |
									 HILDON_GTK_INPUT_MODE_NUMERIC);
	GtkWidget *ncap = hildon_caption_new (group,
										  "Name",
										  name,
										  NULL,
										  HILDON_CAPTION_OPTIONAL);
	gtk_box_pack_start (GTK_BOX (vbox), ncap, TRUE, TRUE, 0);

	GtkWidget *host = hildon_entry_new (HILDON_SIZE_AUTO);
	hildon_gtk_entry_set_placeholder_text (GTK_ENTRY (host), "Hostname / IP");
	hildon_gtk_entry_set_input_mode (GTK_ENTRY (host),
									 HILDON_GTK_INPUT_MODE_FULL);
	GtkWidget *hcap = hildon_caption_new (group,
										  "Host",
										  host,
										  NULL,
										  HILDON_CAPTION_OPTIONAL);
	gtk_box_pack_start (GTK_BOX (vbox), hcap, TRUE, TRUE, 0);

	GtkWidget *cert = hildon_button_new (HILDON_SIZE_FINGER_HEIGHT |
										 HILDON_SIZE_AUTO_WIDTH,
										 HILDON_BUTTON_ARRANGEMENT_VERTICAL);
	hildon_button_set_text (HILDON_BUTTON (cert),
							"Host or CA Certificate",
							"None");
	hildon_button_set_alignment (HILDON_BUTTON (cert), 0, 0.5, 1, 1);
	g_signal_connect (cert, "clicked", G_CALLBACK (select_cert), dialog);
	GtkWidget *ccap = hildon_caption_new (group,
										  "Certificate",
										  cert,
										  NULL,
										  HILDON_CAPTION_OPTIONAL);
	gtk_box_pack_start (GTK_BOX (vbox), ccap, TRUE, TRUE, 0);

	GtkWidget *user = hildon_entry_new (HILDON_SIZE_AUTO);
	hildon_gtk_entry_set_placeholder_text (GTK_ENTRY (user), "Username");
	hildon_gtk_entry_set_input_mode (GTK_ENTRY (user),
									 HILDON_GTK_INPUT_MODE_FULL);
	GtkWidget *ucap = hildon_caption_new (group,
										  "Username",
										  user,
										  NULL,
										  HILDON_CAPTION_OPTIONAL);
	gtk_box_pack_start (GTK_BOX (vbox), ucap, TRUE, TRUE, 0);

	if (conn)
	{
		gchar *c_name, *c_host, *c_cert, *c_user;
		g_object_get (conn,
					  "name", &c_name,
					  "host", &c_host,
					  "cert", &c_cert,
					  "user", &c_user,
					  NULL);
		gtk_entry_set_text (GTK_ENTRY (name), c_name);
		gtk_entry_set_text (GTK_ENTRY (host), c_host);
		hildon_button_set_value (HILDON_BUTTON (cert),
								 c_cert ? c_cert : "None");
		gtk_entry_set_text (GTK_ENTRY (user), c_user);
		g_free (c_name);
		g_free (c_host);
		g_free (c_cert);
		g_free (c_user);
	}

	gtk_widget_show_all (dialog);

	gint retval = gtk_dialog_run (GTK_DIALOG (dialog));
	if (retval == GTK_RESPONSE_OK)
	{
		const gchar *c_name, *c_cert;
		c_name = gtk_entry_get_text (GTK_ENTRY (name));
		if (!conn)
		{
			conn = strongswan_connection_new (c_name);
		}
		c_cert = hildon_button_get_value (HILDON_BUTTON (cert));
		c_cert = strcmp (c_cert, "None") ? c_cert : NULL;
		g_object_set (conn,
					  "name", c_name,
					  "host", gtk_entry_get_text (GTK_ENTRY (host)),
					  "cert", c_cert,
					  "user", gtk_entry_get_text (GTK_ENTRY (user)),
					  NULL);
		strongswan_connections_save_connection (ListDialog.conns, conn);
	}
	gtk_widget_destroy (dialog);
}

/**
 * Creates a dialog showing a list of all connections
 */
static void
create_list_dialog (gpointer *parent)
{
	GtkWidget *dialog = gtk_dialog_new_with_buttons (
							"strongSwan Connections",
							GTK_WINDOW (parent),
							GTK_DIALOG_MODAL | GTK_DIALOG_NO_SEPARATOR,
							GTK_STOCK_NEW,
							RESPONSE_NEW,
							GTK_STOCK_EDIT,
							RESPONSE_EDIT,
							GTK_STOCK_DELETE,
							RESPONSE_DELETE,
							GTK_STOCK_CLOSE,
							GTK_RESPONSE_OK,
							NULL);
	ListDialog.dialog = dialog;
	GtkWidget *vbox = GTK_DIALOG (dialog)->vbox;

	ListDialog.conns = strongswan_connections_new ();

	GtkTreeModel *model = strongswan_connections_get_model (ListDialog.conns);
	ListDialog.list = gtk_tree_view_new_with_model (model);
	g_object_unref (model);

	GtkTreeSelection *selection;
	selection = gtk_tree_view_get_selection (GTK_TREE_VIEW (ListDialog.list));
	gtk_tree_selection_set_mode (selection, GTK_SELECTION_BROWSE);

	GtkTreeViewColumn *column = gtk_tree_view_column_new ();
	strongswan_connections_setup_column_renderers (ListDialog.conns,
												   GTK_CELL_LAYOUT (column));
	gtk_tree_view_append_column (GTK_TREE_VIEW (ListDialog.list), column);

	gtk_box_pack_start (GTK_BOX (vbox),
						ListDialog.list,
						TRUE,
						TRUE,
						HILDON_MARGIN_DEFAULT);
	gtk_widget_show_all (dialog);
	gtk_widget_hide (dialog);
}

/**
 * Get the name fo the selected connection in the list (or NULL).
 * The name has to be freed.
 */
static gchar *
get_selected (void)
{
	GtkTreeView *tree = GTK_TREE_VIEW(ListDialog.list);
	GtkTreeSelection *selection;
	GtkTreeModel *model;
	GtkTreeIter iter;
	gchar *name = NULL;

	selection = gtk_tree_view_get_selection (tree);
	model = gtk_tree_view_get_model (tree);
	if (gtk_tree_selection_get_selected (selection, &model, &iter))
	{
		gtk_tree_model_get(model, &iter, 0, &name, -1);
	}
	return name;
}

/**
 * main callback for control panel plugins
 */
osso_return_t execute(osso_context_t *osso, gpointer data,
					  gboolean user_activated)
{
	gint response;

	create_list_dialog (data);

	if (!user_activated)
	{
		/* load state */
	}

	do
	{
		gchar *selected;
		response = gtk_dialog_run (GTK_DIALOG (ListDialog.dialog));
		switch (response)
		{
			case RESPONSE_NEW:
			{
				edit_connection (data, NULL);
				break;
			}
			case RESPONSE_EDIT:
			{
				StrongswanConnection *conn;
				selected = get_selected ();
				conn = strongswan_connections_get_connection (ListDialog.conns,
															  selected);
				if (conn)
				{
					edit_connection (data, conn);
				}
				else
				{
					hildon_banner_show_information (NULL, NULL,
												"Select a connection first");
				}
				g_free (selected);
				break;
			}
			case RESPONSE_DELETE:
			{
				GtkWidget *confirm;
				gint retval;
				gchar *msg;
				selected = get_selected ();
				if (!selected)
				{
					hildon_banner_show_information (NULL, NULL,
												"Select a connection first");
					break;
				}
				msg = g_strdup_printf ("Delete connection?\n%s", selected);
				confirm = hildon_note_new_confirmation (data, msg);
				retval = gtk_dialog_run (GTK_DIALOG (confirm));
				if (retval == GTK_RESPONSE_OK)
				{
					strongswan_connections_remove_connection (ListDialog.conns,
															  selected);
				}
				gtk_widget_destroy (confirm);
				g_free (msg);
				g_free (selected);
				break;
			}
			default:
				break;
		}
	}
	while (response > 0);

	gtk_widget_destroy (ListDialog.dialog);
	g_object_unref (ListDialog.conns);
	return OSSO_OK;
}

/**
 * callback called in case state has to be saved
 */
osso_return_t save_state(osso_context_t *osso, gpointer data)
{
	/* save state */
	return OSSO_OK;
}

