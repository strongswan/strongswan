/*
 * Copyright (C) 2009 Martin Willi
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
 * @defgroup pki pki
 *
 * @addtogroup pki
 * @{
 */

#ifndef PKI_H_
#define PKI_H_

#include "command.h"

#include <library.h>
#include <credentials/keys/private_key.h>

/**
 * Convert a form string to a encoding type
 */
bool get_form(char *form, cred_encoding_type_t *enc, credential_type_t type);

#endif /** PKI_H_ @}*/
