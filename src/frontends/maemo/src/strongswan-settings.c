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
				break;
			}
			case RESPONSE_EDIT:
			{
				break;
			}
			case RESPONSE_DELETE:
			{
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

