/*
 * Copyright (C) 2008 Martin Willi
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
 *
 * $Id$
 */

/**
 * @defgroup stroke_cred stroke_cred
 * @{ @ingroup stroke
 */

#ifndef STROKE_CRED_H_
#define STROKE_CRED_H_

#include <stroke_msg.h>
#include <credentials/credential_set.h>
#include <credentials/certificates/certificate.h>

typedef struct stroke_cred_t stroke_cred_t;

/**
 * Stroke in-memory credential storage.
 */
struct stroke_cred_t {

	/**
	 * Implements credential_set_t
	 */
	credential_set_t set;
	
	/**
	 * Reread secrets from config files.
	 *
	 * @param msg		stroke message
	 */
	void (*reread)(stroke_cred_t *this, stroke_msg_t *msg);
	
	/**
	 * Load a CA certificate, and serve it through the credential_set.
	 *
	 * @param filename		file to load CA cert from
	 * @return				reference to loaded certificate, or NULL
	 */
	certificate_t* (*load_ca)(stroke_cred_t *this, char *filename);
	
	/**
	 * Load a peer certificate and serve it rhrough the credential_set.
	 *
	 * @param filename		file to load peer cert from
	 * @return				reference to loaded certificate, or NULL
	 */
	certificate_t* (*load_peer)(stroke_cred_t *this, char *filename);
	
	/**
	 * Enable/Disable CRL caching to disk.
	 *
	 * @param enabled		TRUE to enable, FALSE to disable
	 */
	void (*cachecrl)(stroke_cred_t *this, bool enabled);
	
	/**
     * Destroy a stroke_cred instance.
     */
    void (*destroy)(stroke_cred_t *this);
};

/**
 * Create a stroke_cred instance.
 */
stroke_cred_t *stroke_cred_create();

#endif /** STROKE_CRED_H_ @}*/
