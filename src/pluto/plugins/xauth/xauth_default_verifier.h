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
 * @defgroup xauth_default_verifier xauth_default_verifier
 * @{ @ingroup xauth
 */

#ifndef XAUTH_DEFAULT_VERIFIER_H_
#define XAUTH_DEFAULT_VERIFIER_H_

#include <xauth/xauth_verifier.h>


/**
 * Create an xauth_default_verifier instance.
 */
xauth_verifier_t *xauth_default_verifier_create();

#endif /** XAUTH_DEFAULT_VERIFIER_H_ @}*/

