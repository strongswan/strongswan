/*
 * Copyright (C) 2012 Tobias Brunner
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
 * @defgroup hmac_signer hmac_signer
 * @{ @ingroup hmac
 */

#ifndef HMAC_SIGNER_H_
#define HMAC_SIGNER_H_

typedef struct hmac_signer_t hmac_signer_t;

#include <crypto/hmacs/hmac.h>
#include <crypto/signers/signer.h>

/**
 * Creates an implementation of the signer_t interface using the provided hmac_t
 * implementation and truncation length.
 *
 * @note len will be set to hmac_t.get_mac_size() if it is greater than that.
 *
 * @param hmac		hmac_t implementation
 * @param len		length of resulting signature
 * @return			hmac_signer_t
 */
signer_t *hmac_signer_create(hmac_t *hmac, size_t len);

#endif /** HMAC_SIGNER_H_ @}*/
