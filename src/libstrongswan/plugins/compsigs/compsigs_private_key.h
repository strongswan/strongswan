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
 * @defgroup compsigs_private_key compsigs_private_key
 * @{ @ingroup compsigs_p
 */

#ifndef COMPSIGS_PRIVATE_KEY_H_
#define COMPSIGS_PRIVATE_KEY_H_

#include <credentials/builder.h>
#include <credentials/keys/private_key.h>

/**
 * Generate a composite private key.
 *
 * @param type		key type, must be one of the composite key types
 * @param args		builder_part_t argument list
 * @return 			generated key, NULL on failure
 */
private_key_t *compsigs_private_key_gen(key_type_t type, va_list args);

/**
 * Load a composite private key.
 *
 * FIXME: Accepts a BUILD_BLOB or BUILD_BLOB_ASN1_DER argument.
 *
 * @param type		key type, must be one of the composite key types
 * @param args		builder_part_t argument list
 * @return 			loaded key, NULL on failure
 */
private_key_t *compsigs_private_key_load(key_type_t type, va_list args);

#endif /** COMPSIGS_PRIVATE_KEY_H_ @}*/
