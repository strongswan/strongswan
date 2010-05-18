/*
 * Copyright (C) 2010 Andreas Steffen
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

/**
 * @defgroup xauth_default_provider xauth_default_provider
 * @{ @ingroup xauth
 */

#ifndef XAUTH_DEFAULT_PROVIDER_H_
#define XAUTH_DEFAULT_PROVIDER_H_

#include <xauth/xauth_provider.h>


/**
 * Create an xauth_default_provider instance.
 */
xauth_provider_t *xauth_default_provider_create();

#endif /** XAUTH_DEFAULT_PROVIDER_H_ @}*/

