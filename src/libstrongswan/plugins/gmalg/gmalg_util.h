/*
 * Copyright (C) 2008 Tobias Brunner
 * HSR Hochschule fuer Technik Rapperswil
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
 * @defgroup gmalg_util gmalg_util
 * @{ @ingroup gmalg_p
 */

#ifndef GMALG_UTIL_H_
#define GMALG_UTIL_H_

#include <library.h>
#include <gmalg.h>

extern u_char id_default[16];

/**
 * Described in header.
 */
bool gmalg_d2i_ec_pubkey(ECCrefPublicKey *pubkey, chunk_t data);

/**
 * Described in header.
 */
bool gmalg_i2d_ec_pubkey(ECCrefPublicKey *pubkey, chunk_t *data);

/**
 * Described in header.
 */
bool gmalg_d2i_ec_prikey(ECCrefPrivateKey *prikey, ECCrefPublicKey *pubkey, chunk_t data);

/**
 * Described in header.
 */
bool gmalg_i2d_EC_prikey(ECCrefPrivateKey *prikey, ECCrefPublicKey *pubkey,  chunk_t *data);

#endif /** GMALG_UTIL_H_ @}*/
