/**
 * @file library.h
 *
 * @brief Helper functions and definitions.
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
 * libstrongswan: library with various cryptographic, X.509 trust chain and
 * identity management functions.
 */

/**
 * @defgroup asn1 asn1
 *
 * ASN.1 definitions, parser and generator functions.
 *
 * @ingroup libstrongswan
 */

/**
 * @defgroup crypto crypto
 *
 * Various cryptographic algorithms.
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

#include <gmp.h>
#include <sys/types.h>
#include <stdlib.h>
#include <stddef.h>
#include <printf.h>

#include <enum.h>

/**
 * Number of bits in a byte
 */
#define BITS_PER_BYTE 8

/**
 * Default length for various auxiliary text buffers
 */
#define BUF_LEN 512

/**
 * Macro compares two strings for equality
 */
#define streq(x,y) (strcmp(x, y) == 0)

/**
 * Macro compares two binary blobs for equality
 */
#define memeq(x,y,len) (memcmp(x, y, len) == 0)

/**
 * Macro gives back larger of two values.
 */
#define max(x,y) ((x) > (y) ? (x):(y))

/**
 * Macro gives back smaller of two values.
 */
#define min(x,y) ((x) < (y) ? (x):(y))

/**
 * Call destructor of a object if object != NULL
 */
#define DESTROY_IF(obj) if (obj) obj->destroy(obj)

/**
 * Debug macro to follow control flow
 */
#define POS printf("%s, line %d\n", __FILE__, __LINE__)

/**
 * Macro to allocate a sized type.
 */
#define malloc_thing(thing) ((thing*)malloc(sizeof(thing)))

/**
 * Assign a function as a class method
 */
#define ASSIGN(method, function) (method = (typeof(method))function)

/**
 * time_t not defined
 */
#define UNDEFINED_TIME 0

/**
 * General purpose boolean type.
 */
typedef int bool;
#define FALSE 0
#define TRUE  1

typedef enum status_t status_t;

/**
 * Return values of function calls.
 */
enum status_t {
	/**
	 * Call succeeded.
	 */
	SUCCESS,
	
	/**
	 * Call failed.
	 */
	FAILED,
	
	/**
	 * Out of resources.
	 */
	OUT_OF_RES,
	
	/**
	 * The suggested operation is already done
	 */
	ALREADY_DONE,
	
	/**
	 * Not supported.
	 */
	NOT_SUPPORTED,
	
	/**
	 * One of the arguments is invalid.
	 */
	INVALID_ARG,
	
	/**
	 * Something could not be found.
	 */
	NOT_FOUND,
	
	/**
	 * Error while parsing.
	 */
	PARSE_ERROR,
	
	/**
	 * Error while verifying.
	 */
	VERIFY_ERROR,
	
	/**
	 * Object in invalid state.
	 */
	INVALID_STATE,
	
	/**
	 * Destroy object which called method belongs to.
	 */
	DESTROY_ME,
	
	/**
	 * Another call to the method is required.
	 */
	NEED_MORE,
};

/**
 * used by strict_crl_policy
 */
typedef enum {
	STRICT_NO,
	STRICT_YES,
	STRICT_IFURI
} strict_t;

/**
 * enum_names for type status_t.
 */
extern enum_name_t *status_names;

/**
 * deprecated pluto style return value:
 * error message, NULL for success
 */
typedef const char *err_t;

/**
 * Handle struct timeval like an own type.
 */
typedef struct timeval timeval_t;

/**
 * Handle struct timespec like an own type.
 */
typedef struct timespec timespec_t;

/**
 * Handle struct chunk_t like an own type.
 */
typedef struct sockaddr sockaddr_t;

/**
 * Clone a data to a newly allocated buffer
 */
void *clalloc(void *pointer, size_t size);

/**
 * Same as memcpy, but XORs src into dst instead of copy
 */
void memxor(u_int8_t dest[], u_int8_t src[], size_t n);

/**
 * Special type to count references
 */
typedef volatile u_int refcount_t;

/**
 * @brief Get a new reference.
 *
 * Increments the reference counter atomic.
 *
 * @param ref	pointer to ref counter
 */
void ref_get(refcount_t *ref);

/**
 * @brief Put back a unused reference.
 *
 * Decrements the reference counter atomic and 
 * says if more references available.
 *
 * @param ref	pointer to ref counter
 * @return		TRUE if no more references counted
 */
bool ref_put(refcount_t *ref);


#include <chunk.h>
#include <printf_hook.h>

#endif /* LIBRARY_H_ */
