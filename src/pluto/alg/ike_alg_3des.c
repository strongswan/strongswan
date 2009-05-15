/* IKE 3DES encryption algorithm description
 * Copyright (C) 1998-2001 D. Hugh Redelmeier
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

#include <crypto/crypters/crypter.h>

#include "ike_alg.h"

struct encrypt_desc encrypt_desc_3des =
{       
		algo_type:      IKE_ALG_ENCRYPT,
		algo_id:        OAKLEY_3DES_CBC, 
		algo_next:      NULL,

		enc_blocksize:	DES_BLOCK_SIZE, 
		keydeflen:		DES_BLOCK_SIZE * 3 * BITS_PER_BYTE,
		keyminlen:		DES_BLOCK_SIZE * 3 * BITS_PER_BYTE,
		keymaxlen:		DES_BLOCK_SIZE * 3 * BITS_PER_BYTE,
		enc_testvectors: NULL
};


