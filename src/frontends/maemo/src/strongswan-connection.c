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

#include <string.h>

#include "strongswan-connection.h"

#define STRONGSWAN_CONNECTION_GET_PRIVATE(object) \
	(G_TYPE_INSTANCE_GET_PRIVATE ((object), \
								  STRONGSWAN_TYPE_CONNECTION, \
								  StrongswanConnectionPrivate))

struct _StrongswanConnectionPrivate
{
	gchar *orig_name;
	gchar *name;
	gchar *host;
	gchar *cert;
	gchar *user;
};

enum
{
	PROP_0,
	PROP_NAME,
	PROP_HOST,
	PROP_CERT,
	PROP_USER,
};

#ifndef USE_DYNAMIC_TYPES
G_DEFINE_TYPE (StrongswanConnection, strongswan_connection, G_TYPE_OBJECT);
#else
G_DEFINE_DYNAMIC_TYPE (StrongswanConnection, strongswan_connection, G_TYPE_OBJECT);
void strongswan_connection_register (GTypeModule *type_module)
{
	strongswan_connection_register_type (type_module);
}
#endif

static void
strongswan_connection_get_property (GObject		*object,
									guint		 prop_id,
									GValue		*value,
									GParamSpec	*pspec)
{
	StrongswanConnectionPrivate *priv = STRONGSWAN_CONNECTION (object)->priv;
	switch (prop_id)
	{
		case PROP_NAME:
			g_value_set_string (value, priv->name);
			break;
		case PROP_HOST:
			g_value_set_string (value, priv->host);
			break;
		case PROP_CERT:
			g_value_set_string (value, priv->cert);
			break;
		case PROP_USER:
			g_value_set_string (value, priv->user);
			break;
		default:
			G_OBJECT_WARN_INVALID_PROPERTY_ID (object, prop_id, pspec);
			break;
	}
}

static void
strongswan_connection_set_property (GObject			*object,
									guint			 prop_id,
									const GValue	*value,
									GParamSpec		*pspec)
{
	StrongswanConnectionPrivate *priv = STRONGSWAN_CONNECTION (object)->priv;
	switch (prop_id)
	{
		case PROP_NAME:
			g_free (priv->name);
			priv->name = g_value_dup_string (value);
		case PROP_HOST:
			g_free (priv->host);
			priv->host = g_value_dup_string (value);
			break;
		case PROP_CERT:
			g_free (priv->cert);
			priv->cert = g_value_dup_string (value);
			break;
		case PROP_USER:
			g_free (priv->user);
			priv->user = g_value_dup_string (value);
			break;
		default:
			G_OBJECT_WARN_INVALID_PROPERTY_ID (object, prop_id, pspec);
			break;
	}
}

static void
strongswan_connection_init (StrongswanConnection *connection)
{
	connection->priv = STRONGSWAN_CONNECTION_GET_PRIVATE (connection);
}

static void
strongswan_connection_dispose (GObject *object)
{
	G_OBJECT_CLASS (strongswan_connection_parent_class)->dispose (object);
}

static void
strongswan_connection_finalize (GObject *object)
{
	StrongswanConnectionPrivate *priv = STRONGSWAN_CONNECTION (object)->priv;
	g_free (priv->orig_name);
	g_free (priv->name);
	g_free (priv->host);
	g_free (priv->cert);
	g_free (priv->user);
	G_OBJECT_CLASS (strongswan_connection_parent_class)->finalize (object);
}

static void
strongswan_connection_class_init (StrongswanConnectionClass *klass)
{
	GObjectClass *object_class = G_OBJECT_CLASS (klass);

	object_class->get_property = strongswan_connection_get_property;
	object_class->set_property = strongswan_connection_set_property;
	object_class->dispose = strongswan_connection_dispose;
	object_class->finalize = strongswan_connection_finalize;

	g_object_class_install_property (object_class, PROP_NAME,
			g_param_spec_string ("name", "Connection name",
								 "The unique name of a connection",
								 NULL,
								 G_PARAM_READWRITE | G_PARAM_STATIC_STRINGS));

	g_object_class_install_property (object_class, PROP_HOST,
			g_param_spec_string ("host", "Hostname or IP address",
								 "The hostname or IP address of the Gateway",
								 NULL,
								 G_PARAM_READWRITE | G_PARAM_STATIC_STRINGS));

	g_object_class_install_property (object_class, PROP_CERT,
			g_param_spec_string ("cert", "Gateway or CA certificate",
								 "The certificate of the gateway or the CA",
								 NULL,
								 G_PARAM_READWRITE | G_PARAM_STATIC_STRINGS));

	g_object_class_install_property (object_class, PROP_USER,
			g_param_spec_string ("user", "Username",
								 "The username for EAP authentication",
								 NULL,
								 G_PARAM_READWRITE | G_PARAM_STATIC_STRINGS));

	g_type_class_add_private (klass, sizeof (StrongswanConnectionPrivate));
}

#ifdef USE_DYNAMIC_TYPES
static void
strongswan_connection_class_finalize (StrongswanConnectionClass *klass)
{
}
#endif

static inline gchar *
get_string_from_key_file (GKeyFile *key_file,
						  const gchar *name,
						  const gchar *key)
{
	GError *error = NULL;
	gchar *value;
	value = g_key_file_get_string (key_file, name, key, &error);
	if (error)
	{
		g_warning ("Failed to read %s/%s from key file: %s",
				   name, key, error->message);
		g_error_free (error);
	}
	return value;
}

static void
strongswan_connection_update_from_key_file (GKeyFile *key_file,
											StrongswanConnection *connection)
{
	StrongswanConnectionPrivate *priv = connection->priv;
	gchar *name = priv->name;

	priv->orig_name = g_strdup (name);
	priv->host = get_string_from_key_file (key_file, name, "host");
	priv->cert = get_string_from_key_file (key_file, name, "cert");
	priv->user = get_string_from_key_file (key_file, name, "user");
}

StrongswanConnection *
strongswan_connection_new (const gchar *name)
{
	StrongswanConnection *conn;
	conn = g_object_new (STRONGSWAN_TYPE_CONNECTION,
						 "name", name,
						 NULL);
	g_return_val_if_fail (conn->priv != NULL, NULL);
	return conn;
}

StrongswanConnection *
strongswan_connection_new_from_key_file (GKeyFile *key_file,
										 const gchar *name)
{
	StrongswanConnection *conn = strongswan_connection_new (name);
	g_return_val_if_fail (conn != NULL, NULL);
	strongswan_connection_update_from_key_file (key_file, conn);
	return conn;
}

void
strongswan_connection_save_to_key_file (GKeyFile *key_file,
										StrongswanConnection *connection)
{
	StrongswanConnectionPrivate *priv = connection->priv;
	gchar *name = priv->name;

	if (priv->orig_name && strcmp (name, priv->orig_name))
	{
		g_key_file_remove_group (key_file, priv->orig_name, NULL);
		g_free (priv->orig_name);
		priv->orig_name = g_strdup (name);
	}

	if (priv->host)
	{
		g_key_file_set_string (key_file, name, "host", priv->host);
	}
	if (priv->cert)
	{
		g_key_file_set_string (key_file, name, "cert", priv->cert);
	}
	else
	{
		g_key_file_remove_key (key_file, name, "cert", NULL);
	}
	if (priv->user)
	{
		g_key_file_set_string (key_file, name, "user", priv->user);
	}
}

