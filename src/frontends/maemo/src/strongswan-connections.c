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

#include <glib.h>
#include <libgnomevfs/gnome-vfs.h>

#include "strongswan-connections.h"

/* connections are stored in ~/.config/strongswan/connections */
#define CONFIG_DIR_NAME "strongswan"
#define CONFIG_FILE_NAME "connections"

#define STRONGSWAN_CONNECTIONS_GET_PRIVATE(object) \
	(G_TYPE_INSTANCE_GET_PRIVATE ((object), STRONGSWAN_TYPE_CONNECTIONS, StrongswanConnectionsPrivate))

struct _StrongswanConnectionsPrivate
{
	GKeyFile *key_file;
	gchar *path;
	GnomeVFSMonitorHandle *monitor;
	GHashTable *connections;
};

G_DEFINE_TYPE (StrongswanConnections, strongswan_connections, G_TYPE_OBJECT);

static void
strongswan_connections_load_connections (StrongswanConnections *connections)
{
	StrongswanConnectionsPrivate *priv = connections->priv;
	gchar **groups;
	guint i;

	g_hash_table_remove_all (priv->connections);
	groups = g_key_file_get_groups (priv->key_file, NULL);
	for (i = 0; groups[i]; i++)
	{
		StrongswanConnection *conn;
		conn = strongswan_connection_new_from_key_file(priv->key_file,
													   groups[i]);
		if (conn != NULL)
		{
			g_hash_table_insert (priv->connections,
								 g_strdup(groups[i]),
								 conn);
		}
	}
	g_strfreev (groups);
}

static void
strongswan_connections_load_config (StrongswanConnections *connections)
{
	StrongswanConnectionsPrivate *priv = connections->priv;
	GError *error = NULL;

	if (priv->key_file)
	{
		g_key_file_free (priv->key_file);
	}

	priv->key_file = g_key_file_new ();
	if (!g_key_file_load_from_file (priv->key_file,
									priv->path,
									G_KEY_FILE_KEEP_COMMENTS,
									&error))
	{
		if (g_error_matches (error,
							  G_KEY_FILE_ERROR,
							  G_KEY_FILE_ERROR_PARSE))
		{
			g_debug ("Failed to parse config file '%s', treated as empty: %s",
					 priv->path, error->message);
			g_error_free (error);
		}
		else
		{
			g_debug ("Could not read config file '%s': %s",
					 priv->path, error->message);
			g_error_free (error);
		}
	}

	strongswan_connections_load_connections (connections);
}

static void
strongswan_connections_file_changed (GnomeVFSMonitorHandle		*handle,
									 const gchar				*monitor_uri,
									 const gchar				*info_uri,
									 GnomeVFSMonitorEventType	 event_type,
									 StrongswanConnections		*connections)
{
	strongswan_connections_load_config (connections);
}


static void
strongswan_connections_init (StrongswanConnections *connections)
{
	StrongswanConnectionsPrivate *priv;
	connections->priv = STRONGSWAN_CONNECTIONS_GET_PRIVATE (connections);
	priv = connections->priv;

	priv->path = g_build_filename (g_get_user_config_dir (),
								   CONFIG_DIR_NAME,
								   CONFIG_FILE_NAME,
								   NULL);

	priv->connections = g_hash_table_new_full (g_str_hash,
											   g_str_equal,
											   g_free,
											   g_object_unref);

}

static void
strongswan_connections_constructed (GObject *object)
{
	StrongswanConnectionsPrivate *priv;
	GnomeVFSResult result;

	if (G_OBJECT_CLASS (strongswan_connections_parent_class)->constructed)
	{
		G_OBJECT_CLASS (strongswan_connections_parent_class)->constructed (object);
	}

	g_return_if_fail (STRONGSWAN_IS_CONNECTIONS (object));
	priv = STRONGSWAN_CONNECTIONS (object)->priv;

	result = gnome_vfs_monitor_add (&priv->monitor,
									priv->path,
									GNOME_VFS_MONITOR_FILE,
									(GnomeVFSMonitorCallback) strongswan_connections_file_changed,
									object);
	if (result != GNOME_VFS_OK)
	{
		g_warning ("Could not monitor '%s': %s",
				   priv->path,
				   gnome_vfs_result_to_string (result));
	}

	strongswan_connections_load_config (STRONGSWAN_CONNECTIONS (object));
}

static void
strongswan_connections_dispose (GObject *object)
{
	StrongswanConnectionsPrivate *priv;

	g_return_if_fail (STRONGSWAN_IS_CONNECTIONS (object));
	priv = STRONGSWAN_CONNECTIONS (object)->priv;

	G_OBJECT_CLASS (strongswan_connections_parent_class)->dispose (object);
}

static void
strongswan_connections_finalize (GObject *object)
{
	StrongswanConnectionsPrivate *priv;

	g_return_if_fail (STRONGSWAN_IS_CONNECTIONS (object));
	priv = STRONGSWAN_CONNECTIONS (object)->priv;

	priv->path = (g_free (priv->path), NULL);
	priv->monitor = (gnome_vfs_monitor_cancel (priv->monitor), NULL);
	priv->key_file = (g_key_file_free (priv->key_file), NULL);
	priv->connections = (g_hash_table_destroy (priv->connections), NULL);

	G_OBJECT_CLASS (strongswan_connections_parent_class)->finalize (object);
}

static void
strongswan_connections_class_init (StrongswanConnectionsClass *klass)
{
	GObjectClass *object_class = G_OBJECT_CLASS (klass);

	object_class->constructed = strongswan_connections_constructed;
	object_class->dispose = strongswan_connections_dispose;
	object_class->finalize = strongswan_connections_finalize;

	g_type_class_add_private (klass, sizeof (StrongswanConnectionsPrivate));
}

StrongswanConnections *
strongswan_connections_new (void)
{
	StrongswanConnections *connections;
	connections = g_object_new (STRONGSWAN_TYPE_CONNECTIONS,
								NULL);
	return connections;
}

StrongswanConnection *
strongswan_connections_get_connection (StrongswanConnections *self,
									   const gchar *name)
{
	StrongswanConnectionsPrivate *priv = self->priv;
	g_return_val_if_fail (name != NULL, NULL);
	return g_hash_table_lookup (priv->connections, name);
}

static void
strongswan_connections_save_connections (StrongswanConnections *self)
{
	StrongswanConnectionsPrivate *priv = self->priv;
	gchar *data;
	gsize size;
	GError *error = NULL;

	data = g_key_file_to_data (priv->key_file, &size, NULL);
	if (!g_file_set_contents (priv->path, data, size, &error))
	{
		g_warning ("Failed to save connections to '%s': %s",
				   priv->path, error->message);
		g_error_free (error);
	}
	g_free (data);
}

void
strongswan_connections_save_connection (StrongswanConnections *self,
										StrongswanConnection *conn)
{
	StrongswanConnectionsPrivate *priv = self->priv;

	strongswan_connection_save_to_key_file (priv->key_file, conn);

	strongswan_connections_save_connections (self);
}

void
strongswan_connections_remove_connection (StrongswanConnections *self,
										  const gchar *name)
{
	StrongswanConnectionsPrivate *priv = self->priv;

	g_key_file_remove_group (priv->key_file, name, NULL);

	strongswan_connections_save_connections (self);
}

