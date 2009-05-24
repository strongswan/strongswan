/* IKE AES encryption algorithm description
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

#include <crypto/crypters/crypter.h>

#include "ike_alg.h"

#define  AES_KEY_MIN_LEN	128
#define  AES_KEY_DEF_LEN	128
#define  AES_KEY_MAX_LEN	256

struct encrypt_desc encrypt_desc_aes =
{
	algo_type: 	     IKE_ALG_ENCRYPT,
	algo_id:   	     OAKLEY_AES_CBC,
	algo_next: 	     NULL, 

	enc_blocksize: 	 AES_BLOCK_SIZE,
	keyminlen: 		 AES_KEY_MIN_LEN,
	keydeflen: 		 AES_KEY_DEF_LEN,
	keymaxlen: 		 AES_KEY_MAX_LEN,
	enc_testvectors: NULL
};

