/*
 * Copyright (C) 2013 Tobias Brunner
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
 * @defgroup openssl_ec_util openssl_ec_util
 * @{ @ingroup openssl_p
 */

#ifndef OPENSSL_EC_UTIL_H_
#define OPENSSL_EC_UTIL_H_

#include <openssl/ec.h>
#include <crypto/ec_params.h>

/**
 * Returns the length in bytes of a field element
 */
#define EC_FIELD_ELEMENT_LEN(group) ((EC_GROUP_get_degree(group) + 7) / 8)

/**
 * Create an EC_GROUP object for the given curve.
 *
 * @param curve		curve
 * @return			allocated EC_GROUP object or NULL
 */
EC_GROUP *openssl_ec_group_for_curve(ec_curve_t curve);

/**
 * Clear lookup table to map from ec_curve_t to OpenSSL NID
 */
void openssl_ec_lookup_table_cleanup();

#endif /** OPENSSL_EC_UTIL_H_ @}*/
