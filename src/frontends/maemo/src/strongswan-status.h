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

#ifndef __STRONGSWAN_STATUS_H__
#define __STRONGSWAN_STATUS_H__

#include <libhildondesktop/libhildondesktop.h>

G_BEGIN_DECLS

#define STRONGSWAN_TYPE_STATUS				(strongswan_status_get_type ())
#define STRONGSWAN_STATUS(obj)				(G_TYPE_CHECK_INSTANCE_CAST ((obj), STRONGSWAN_TYPE_STATUS, StrongswanStatus))
#define STRONGSWAN_STATUS_CLASS(klass)		(G_TYPE_CHECK_CLASS_CAST ((klass),  STRONGSWAN_TYPE_STATUS, StrongswanStatusClass))
#define STRONGSWAN_IS_STATUS(obj)			(G_TYPE_CHECK_INSTANCE_TYPE ((obj), STRONGSWAN_TYPE_STATUS))
#define STRONGSWAN_IS_STATUS_CLASS(klass)	(G_TYPE_CHECK_CLASS_TYPE ((klass),  STRONGSWAN_TYPE_STATUS))
#define STRONGSWAN_STATUS_GET_CLASS(obj)	(G_TYPE_INSTANCE_GET_CLASS ((obj),  STRONGSWAN_TYPE_STATUSS, StrongswanStatusClass))

typedef struct _StrongswanStatus			StrongswanStatus;
typedef struct _StrongswanStatusClass		StrongswanStatusClass;
typedef struct _StrongswanStatusPrivate		StrongswanStatusPrivate;

struct _StrongswanStatus
{
	HDStatusMenuItem parent;

	StrongswanStatusPrivate *priv;
};

struct _StrongswanStatusClass
{
	HDStatusMenuItemClass parent;
};

GType strongswan_status_get_type (void);

G_END_DECLS

#endif /* __STRONGSWAN_STATUS_H__ */

