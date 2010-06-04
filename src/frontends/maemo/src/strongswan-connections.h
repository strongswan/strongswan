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

#ifndef __STRONGSWAN_CONNECTIONS_H__
#define __STRONGSWAN_CONNECTIONS_H__

#include <gtk/gtk.h>

#include "strongswan-connection.h"

G_BEGIN_DECLS

#define STRONGSWAN_TYPE_CONNECTIONS				(strongswan_connections_get_type ())
#define STRONGSWAN_CONNECTIONS(obj)				(G_TYPE_CHECK_INSTANCE_CAST ((obj), STRONGSWAN_TYPE_CONNECTIONS, StrongswanConnections))
#define STRONGSWAN_CONNECTIONS_CLASS(klass)		(G_TYPE_CHECK_CLASS_CAST ((klass),  STRONGSWAN_TYPE_CONNECTIONS, StrongswanConnectionsClass))
#define STRONGSWAN_IS_CONNECTIONS(obj)			(G_TYPE_CHECK_INSTANCE_TYPE ((obj), STRONGSWAN_TYPE_CONNECTIONS))
#define STRONGSWAN_IS_CONNECTIONS_CLASS(klass)	(G_TYPE_CHECK_CLASS_TYPE ((klass),  STRONGSWAN_TYPE_CONNECTIONS))
#define STRONGSWAN_CONNECTIONS_GET_CLASS(obj)	(G_TYPE_INSTANCE_GET_CLASS ((obj),  STRONGSWAN_TYPE_CONNECTIONS, StrongswanConnectionsClass))

typedef struct _StrongswanConnections			StrongswanConnections;
typedef struct _StrongswanConnectionsClass		StrongswanConnectionsClass;
typedef struct _StrongswanConnectionsPrivate	StrongswanConnectionsPrivate;

struct _StrongswanConnections
{
	GObject gobject;

	StrongswanConnectionsPrivate *priv;
};

struct _StrongswanConnectionsClass
{
	GObjectClass parent_class;
};

GType strongswan_connections_get_type (void);

StrongswanConnections *strongswan_connections_new (void);

GtkTreeModel *strongswan_connections_get_model (StrongswanConnections *connections);
void strongswan_connections_setup_column_renderers (StrongswanConnections *connections, GtkCellLayout *layout);

StrongswanConnection *strongswan_connections_get_connection (StrongswanConnections *self, const gchar *name);
void strongswan_connections_save_connection (StrongswanConnections *self, StrongswanConnection *conn);
void strongswan_connections_remove_connection (StrongswanConnections *self, const gchar *name);

#ifdef USE_DYNAMIC_TYPES
void strongswan_connections_register (GTypeModule *type_module);
#endif

G_END_DECLS

#endif /* __STRONGSWAN_CONNECTIONS_H__ */
