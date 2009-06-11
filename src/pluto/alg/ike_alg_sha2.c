/* IKE SHA-2 hash algorithm description
 * Copyright (C) JuanJo Ciarlante <jjo-ipsec@mendoza.gov.ar>
 * Copyright (C) 2009 Andreas Steffen
 *
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

#include <crypto/hashers/hasher.h>

#include "ike_alg.h"

struct hash_desc hash_desc_sha2_256 = {
	algo_type: IKE_ALG_HASH,
	algo_id:   OAKLEY_SHA2_256,
	algo_next: NULL,
	hash_digest_size: HASH_SIZE_SHA256,
};

struct hash_desc hash_desc_sha2_384 = {
	algo_type: IKE_ALG_HASH,
	algo_id:   OAKLEY_SHA2_384,
	algo_next: NULL,
	hash_digest_size: HASH_SIZE_SHA384,
};

struct hash_desc hash_desc_sha2_512 = {
	algo_type: IKE_ALG_HASH,
	algo_id:   OAKLEY_SHA2_512,
	algo_next: NULL,
	hash_digest_size: HASH_SIZE_SHA512,
};

