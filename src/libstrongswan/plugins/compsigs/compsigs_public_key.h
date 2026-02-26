/*
 * Copyright (C) 2026 Tobias Brunner
 *
 * Copyright (C) secunet Security Networks AG
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
 * @defgroup compsigs_public_key compsigs_public_key
 * @{ @ingroup compsigs_p
 */

#ifndef COMPSIGS_PUBLIC_KEY_H_
#define COMPSIGS_PUBLIC_KEY_H_

#include <credentials/builder.h>
#include <credentials/keys/public_key.h>

/**
 * Load a compsite public key.
 *
 * FIXME: Accepts a BUILD_BLOB or BUILD_BLOB_ASN1_DER argument.
 *
 * @param type		key type, must be one of the composite key types
 * @param args		builder_part_t argument list
 * @return 			loaded key, NULL on failure
 */
public_key_t *compsigs_public_key_load(key_type_t type, va_list args);

#endif /** COMPSIGS_PUBLIC_KEY_H_ @}*/
