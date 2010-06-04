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
	gchar *name;
	gchar *host;
	gchar *cert;
	gchar *user;
	gchar *pass;
};

enum
{
	PROP_0,
	PROP_NAME,
	PROP_HOST,
	PROP_CERT,
	PROP_USER,
	PROP_PASS,
};

G_DEFINE_TYPE (StrongswanConnection, strongswan_connection, G_TYPE_OBJECT);

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
		case PROP_PASS:
			g_value_set_string (value, priv->pass);
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
		case PROP_PASS:
			g_free (priv->pass);
			priv->pass = g_value_dup_string (value);
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
strongswan_connection_constructed (GObject *object)
{
	if (G_OBJECT_CLASS (strongswan_connection_parent_class)->constructed)
	{
		G_OBJECT_CLASS (strongswan_connection_parent_class)->constructed (object);
	}
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
	g_free (priv->name);
	g_free (priv->host);
	g_free (priv->cert);
	g_free (priv->user);
	g_free (priv->pass);
	G_OBJECT_CLASS (strongswan_connection_parent_class)->finalize (object);
}

static void
strongswan_connection_class_init (StrongswanConnectionClass *klass)
{
	GObjectClass *object_class = G_OBJECT_CLASS (klass);

	object_class->constructed = strongswan_connection_constructed;
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

	g_object_class_install_property (object_class, PROP_PASS,
			g_param_spec_string ("pass", "Password",
								 "The password for EAP authentication",
								 NULL,
								 G_PARAM_READWRITE | G_PARAM_STATIC_STRINGS));

	g_type_class_add_private (klass, sizeof (StrongswanConnectionPrivate));
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

