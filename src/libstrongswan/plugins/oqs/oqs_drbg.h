/*
 * Copyright (C) 2019 Andreas Steffen
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
 * @defgroup oqs_p oqs
 * @ingroup plugins
 *
 * @defgroup oqs_drbg oqs_drbg
 * @{ @ingroup oqs_p
 */

#ifndef OQS_DRBG_H_
#define OQS_DRBG_H_

#include <library.h>

/**
 * Initializes the local DRBG
 */
void oqs_drbg_init(void);

/**
 * De-Initializes the local DRBG
 */
void oqs_drbg_deinit(void);

/**
 * Global random function used by liboqs
 *
 * @param buffer	buffer where requested random bytes are written to
 * @param size		number of requested random bytes
 */
void oqs_drbg_rand(uint8_t *buffer, size_t size);

/**
 * Sets the current DRBG used by liboqs
 *
 * @param drbg		DRBG to be used
 */
void oqs_drbg_set(drbg_t *drbg);

#endif /** OQS_DRBG_H_ @}*/
