/* IKE Diffie-Hellman group description
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

#include <crypto/diffie_hellman.h>

#include "ike_alg.h"

struct dh_desc unset_group = {
	algo_type:      IKE_ALG_DH_GROUP,
	algo_id:        MODP_NONE, 
	algo_next:      NULL,

	modulus_size:	0
};

struct dh_desc dh_desc_modp_1024 = {       
	algo_type:      IKE_ALG_DH_GROUP,
	algo_id:        MODP_1024_BIT, 
	algo_next:      NULL,

	modulus_size:	1024 / BITS_PER_BYTE
};

struct dh_desc dh_desc_modp_1536 = {       
	algo_type:      IKE_ALG_DH_GROUP,
	algo_id:        MODP_1536_BIT, 
	algo_next:      NULL,

	modulus_size:	1536 / BITS_PER_BYTE
};

struct dh_desc dh_desc_modp_2048 = {       
	algo_type:      IKE_ALG_DH_GROUP,
	algo_id:        MODP_2048_BIT, 
	algo_next:      NULL,

	modulus_size:	2048 / BITS_PER_BYTE
};

struct dh_desc dh_desc_modp_3072 = {       
	algo_type:      IKE_ALG_DH_GROUP,
	algo_id:        MODP_3072_BIT, 
	algo_next:      NULL,

	modulus_size:	3072 / BITS_PER_BYTE
};

struct dh_desc dh_desc_modp_4096 = {       
	algo_type:      IKE_ALG_DH_GROUP,
	algo_id:        MODP_4096_BIT, 
	algo_next:      NULL,

	modulus_size:	4096 / BITS_PER_BYTE
};

struct dh_desc dh_desc_modp_6144 = {       
	algo_type:      IKE_ALG_DH_GROUP,
	algo_id:        MODP_6144_BIT, 
	algo_next:      NULL,

	modulus_size:	6144 / BITS_PER_BYTE
};

struct dh_desc dh_desc_modp_8192 = {       
	algo_type:      IKE_ALG_DH_GROUP,
	algo_id:        MODP_8192_BIT, 
	algo_next:      NULL,

	modulus_size:	8192 / BITS_PER_BYTE
};

struct dh_desc dh_desc_ecp_256 = {       
	algo_type:      IKE_ALG_DH_GROUP,
	algo_id:        ECP_256_BIT, 
	algo_next:      NULL,

	modulus_size:	256 / BITS_PER_BYTE
};

struct dh_desc dh_desc_ecp_384 = {       
	algo_type:      IKE_ALG_DH_GROUP,
	algo_id:        ECP_384_BIT, 
	algo_next:      NULL,

	modulus_size:	384 / BITS_PER_BYTE
};

struct dh_desc dh_desc_ecp_521 = {       
	algo_type:      IKE_ALG_DH_GROUP,
	algo_id:        ECP_521_BIT, 
	algo_next:      NULL,

	modulus_size:	528 / BITS_PER_BYTE
};

struct dh_desc dh_desc_ecp_192 = {       
	algo_type:      IKE_ALG_DH_GROUP,
	algo_id:        ECP_192_BIT, 
	algo_next:      NULL,

	modulus_size:	192 / BITS_PER_BYTE
};

struct dh_desc dh_desc_ecp_224 = {       
	algo_type:      IKE_ALG_DH_GROUP,
	algo_id:        ECP_224_BIT, 
	algo_next:      NULL,

	modulus_size:	224 / BITS_PER_BYTE
};

