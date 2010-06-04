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

#ifndef __STRONGSWAN_CONNECTION_H__
#define __STRONGSWAN_CONNECTION_H__

#include <glib.h>
#include <glib-object.h>

G_BEGIN_DECLS

#define STRONGSWAN_TYPE_CONNECTION				(strongswan_connection_get_type ())
#define STRONGSWAN_CONNECTION(obj)				(G_TYPE_CHECK_INSTANCE_CAST ((obj), STRONGSWAN_TYPE_CONNECTION, StrongswanConnection))
#define STRONGSWAN_CONNECTION_CLASS(klass)		(G_TYPE_CHECK_CLASS_CAST ((klass),  STRONGSWAN_TYPE_CONNECTION, StrongswanConnectionClass))
#define STRONGSWAN_IS_CONNECTION(obj)			(G_TYPE_CHECK_INSTANCE_TYPE ((obj), STRONGSWAN_TYPE_CONNECTION))
#define STRONGSWAN_IS_CONNECTION_CLASS(klass)	(G_TYPE_CHECK_CLASS_TYPE ((klass),  STRONGSWAN_TYPE_CONNECTION))
#define STRONGSWAN_CONNECTION_GET_CLASS(obj)	(G_TYPE_INSTANCE_GET_CLASS ((obj),  STRONGSWAN_TYPE_CONNECTION, StrongswanConnectionClass))

typedef struct _StrongswanConnection			StrongswanConnection;
typedef struct _StrongswanConnectionClass		StrongswanConnectionClass;
typedef struct _StrongswanConnectionPrivate		StrongswanConnectionPrivate;

struct _StrongswanConnection
{
	GObject gobject;

	StrongswanConnectionPrivate *priv;
};

struct _StrongswanConnectionClass
{
	GObjectClass parent_class;
};

GType strongswan_connection_get_type (void);

StrongswanConnection *strongswan_connection_new (const gchar *name);

StrongswanConnection *strongswan_connection_new_from_key_file(GKeyFile *key_file, const gchar *name);
void strongswan_connection_save_to_key_file (GKeyFile *key_file, StrongswanConnection *connection);

#ifdef USE_DYNAMIC_TYPES
void strongswan_connection_register (GTypeModule *type_module);
#endif

G_END_DECLS

#endif /* __STRONGSWAN_CONNECTION_H__ */
