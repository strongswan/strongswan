/*
 * Copyright (C) 2007-2008 Martin Willi
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
 * @defgroup credential_manager credential_manager
 * @{ @ingroup ccredentials
 */

#ifndef CREDENTIAL_MANAGER_H_
#define CREDENTIAL_MANAGER_H_

#include <utils/identification.h>
#include <utils/enumerator.h>
#include <credentials/auth_info.h>
#include <credentials/credential_set.h>
#include <credentials/keys/private_key.h>
#include <credentials/keys/shared_key.h>
#include <credentials/certificates/certificate.h>

typedef struct credential_manager_t credential_manager_t;

/**
 * Manages credentials using credential_sets.
 *
 * The credential manager is the entry point of the credential framework. It
 * uses so called "sets" to access credentials in a modular fashion, these
 * are implemented through the credential_set_t interface. 
 * The manager additionally does trust chain verification and trust status
 * chaching. A set may call the managers methods if it needs credentials itself,
 * the manager uses recursive locking.
 * 
 * @verbatim

  +-------+        +----------------+
  |   A   |        |                |          +------------------+
  |   u   | -----> |                | ------>  |  +------------------+
  |   t   |        |   credential-  |          |  |  +------------------+
  |   h   | -----> |     manager    | ------>  +--|  |   credential-    | => IPC
  |   e   |        |                |             +--|       sets       |
  |   n   |   +--> |                | ------>        +------------------+
  |   t   |   |    |                |                        |
  |   i   |   |    |                |                        |
  |   c   |   |    +----------------+                        |
  |   a   |   |                                              |
  |   t   |   +----------------------------------------------+
  |   o   |                    may be recursive
  |   r   |
  +-------+
    
   @endverbatim                                       
 *
 * The credential manager uses rwlocks for performance reasons, credential
 * sets must be fully thread save.
 */
struct credential_manager_t {
	
	/**
	 * Create an enumerator over all certificates.
	 *
	 * @param cert		kind of certificate
	 * @param key		kind of key in certificate
	 * @param id		subject this certificate belongs to
	 * @param trusted	TRUE to list trusted certificates only
	 * @return			enumerator over the certificates
	 */
	enumerator_t *(*create_cert_enumerator)(credential_manager_t *this,
								certificate_type_t cert, key_type_t key,
								identification_t *id, bool trusted);
	/**
	 * Create an enumerator over all shared keys.
	 *
	 * The enumerator enumerates over:
	 *  shared_key_t*, id_match_t me, id_match_t other
	 * But must accepts values for the id_matches.
	 *
	 * @param type		kind of requested shared key
	 * @param first		first subject between key is shared
	 * @param second	second subject between key is shared
	 * @return			enumerator over shared keys
	 */
	enumerator_t *(*create_shared_enumerator)(credential_manager_t *this, 
								shared_key_type_t type,
								identification_t *first, identification_t *second);
	/**
	 * Create an enumerator over all Certificate Distribution Points.
	 *
	 * @param type		kind of certificate the point distributes
	 * @param id		identification of the distributed certificate
	 * @return			enumerator of CDPs as char*
	 */
	enumerator_t *(*create_cdp_enumerator)(credential_manager_t *this,
								certificate_type_t type, identification_t *id);
	/**
	 * Get a trusted or untrusted certificate.
	 *
	 * @param cert		kind of certificate
	 * @param key		kind of key in certificate
	 * @param id		subject this certificate belongs to
	 * @param trusted	TRUE to get a trusted certificate only
	 * @return			certificate, if found, NULL otherwise
	 */
	certificate_t *(*get_cert)(credential_manager_t *this,
							   certificate_type_t cert, key_type_t key,
							   identification_t *id, bool trusted);
	/**
	 * Get the best matching shared key for two IDs.
	 *
	 * @param type		kind of requested shared key
	 * @param me		own identity
	 * @param other		peers identity
	 * @param auth		auth_info helper 
	 * @return			shared_key_t, NULL if none found
	 */			   
	shared_key_t *(*get_shared)(credential_manager_t *this, shared_key_type_t type,
								identification_t *me, identification_t *other);
	/**
	 * Get a private key to create a signature.
	 *
	 * The get_private() method gets a secret private key identified by either
	 * the keyid itself or an id the key belongs to. 
	 * The auth parameter contains additional information, such as receipients
	 * trusted CA certs. Auth gets filled with subject and CA certificates
	 * needed to validate a created signature.
	 *
	 * @param type		type of the key to get
	 * @param id		identification the key belongs to
	 * @param auth		auth_info helper, including trusted CA certificates
	 * @return			private_key_t, NULL if none found
	 */
	private_key_t* (*get_private)(credential_manager_t *this, key_type_t type,
								  identification_t *id, auth_info_t *auth);
	
	/**
	 * Create an enumerator over trusted public keys.
	 *
	 * This method gets a an enumerator over trusted public keys to verify a
	 * signature created by id. The auth parameter contains additional 
	 * authentication infos, e.g. peer and intermediate certificates.
	 * The resulting enumerator enumerates over public_key_t *, auth_info_t *,
	 * where the auth info contains gained privileges for the authorization
	 * process.
	 *
	 * @param type		type of the key to get
	 * @param id		owner of the key, signer of the signature
	 * @param auth		authentication infos
	 * @return			enumerator
	 */
	enumerator_t* (*create_public_enumerator)(credential_manager_t *this,
					key_type_t type, identification_t *id, auth_info_t *auth);
	
	/**
	 * Cache a certificate by invoking cache_cert() on all registerd sets.
	 *
	 * @param cert		certificate to cache
	 */
	void (*cache_cert)(credential_manager_t *this, certificate_t *cert);
	
	/**
	 * Flush the certificate cache.
	 *
	 * Only the managers local cache is flushed, but not the sets cache filled
	 * by the cache_cert() method.
	 *
	 * @param type		type of certificate to flush, or CERT_ANY
	 */
	void (*flush_cache)(credential_manager_t *this, certificate_type_t type);
		
	/**
	 * Register a credential set to the manager.
	 *
	 * @param set		set to register
	 */
	void (*add_set)(credential_manager_t *this, credential_set_t *set);
	
	/**
	 * Unregister a credential set from the manager.
	 *
	 * @param set		set to unregister
	 */
	void (*remove_set)(credential_manager_t *this, credential_set_t *set);
	
	/**
     * Destroy a credential_manager instance.
     */
    void (*destroy)(credential_manager_t *this);
};

/**
 * Create a credential_manager instance.
 */
credential_manager_t *credential_manager_create();

#endif /** CREDENTIAL_MANAGER_H_ @}*/
