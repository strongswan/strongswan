/**
 * @file library.h
 * 
 * @brief Global library header.
 * 
 */

/*
 * Copyright (C) 2006 Martin Willi
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

#ifndef LIBRARY_H_
#define LIBRARY_H_

/**
 * @defgroup libstrongswan libstrongswan
 *
 * libstrongswan: library with various crypto related things.
 */

/**
 * @defgroup asn1 asn1
 *
 * ASN1 definitions, parser and generator functions.
 *
 * @ingroup libstrongswan
 */

/**
 * @defgroup crypto crypto
 *
 * Crypto algorithms of different kind.
 *
 * @ingroup libstrongswan
 */

/**
 * @defgroup crypters crypters
 *
 * Symmetric encryption algorithms, used for
 * encryption and decryption.
 *
 * @ingroup crypto
 */

/**
 * @defgroup hashers hashers
 *
 * Hashing algorithms, such as MD5 or SHA1
 *
 * @ingroup crypto
 */

/**
 * @defgroup prfs prfs
 *
 * Pseudo random functions, used to generate 
 * pseude random byte sequences.
 *
 * @ingroup crypto
 */

/**
 * @defgroup rsa rsa
 *
 * RSA private/public key algorithm.
 *
 * @ingroup crypto
 */

/**
 * @defgroup signers signers
 *
 * Symmetric signing algorithms, 
 * used to ensure message integrity.
 * 
 * @ingroup crypto
 */
 
/**
 * @defgroup utils utils
 * 
 * Generic helper classes.
 * 
 * @ingroup libstrongswan
 */


#endif /* LIBRARY_H_ */
