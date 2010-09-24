/*
 * Copyright (C) 2010 Martin Willi
 * Copyright (C) 2010 revosec AG
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
 * @defgroup mem_cred mem_cred
 * @{ @ingroup sets
 */

#ifndef MEM_CRED_H_
#define MEM_CRED_H_

typedef struct mem_cred_t mem_cred_t;

#include <credentials/credential_set.h>

/**
 * Generic in-memory credential set.
 */
struct mem_cred_t {

	/**
	 * Implements credential_set_t.
	 */
	credential_set_t set;

	/**
	 * Add a certificate to the credential set.
	 *
	 * @param trusted		TRUE to serve certificate as trusted
	 * @param cert			certificate, reference gets owned by set
	 */
	void (*add_cert)(mem_cred_t *this, bool trusted, certificate_t *cert);

	/**
	 * Add a private key to the credential set.
	 *
	 * @param key			key, reference gets owned by set
	 */
	void (*add_key)(mem_cred_t *this, private_key_t *key);

	/**
	 * Add a shared key to the credential set.
	 *
	 * @param shared		shared key to add, gets owned by set
	 * @param ...			NULL terminated list of owners identification_t*
	 */
	void (*add_shared)(mem_cred_t *this, shared_key_t *shared, ...);

	/**
	 * Clear all credentials from the credential set.
	 */
	void (*clear)(mem_cred_t *this);

	/**
	 * Destroy a mem_cred_t.
	 */
	void (*destroy)(mem_cred_t *this);
};

/**
 * Create a mem_cred instance.
 */
mem_cred_t *mem_cred_create();

#endif /** MEM_CRED_H_ @}*/
