/*
 * Copyright (C) 2007 Martin Willi
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
 * @defgroup auth_info auth_info
 * @{ @ingroup ccredentials
 */

#ifndef AUTH_INFO_H_
#define AUTH_INFO_H_

#include <utils/enumerator.h>

typedef struct auth_info_t auth_info_t;
typedef enum auth_item_t auth_item_t;

/**
 * Authentication/Authorization process helper item.
 *
 * For the authentication process, further information may be needed. These
 * items are defined as auth_item_t and have a AUTHN prefix. 
 * The authentication process returns important data for the authorization 
 * process, these items are defined with a AUTHZ prefix.
 * Authentication uses AUTHN items and creates AUTHZ items during authentication,
 * authorization reads AUTHZ values to give out privileges.
 *
 *                +---+             +---------------------+
 *                | A |             | A                   |
 *                | u |             | u    +-----------+  |
 *                | t |             | t    |  Required |  |
 *                | h |             | h    | auth_info |  |
 *                | e |             | o    +-----------+  |
 *                | n |             | r           |       |
 * +-----------+  | t |             | i           |       |
 * | Provided  |  | i |             | z           V       |
 * | auth_info |--| c |-------------| a  ----> match? ----|------->
 * +-----------+  | a |             | t                   |
 *                | t |             | i                   |
 *                | i |             | o                   |
 *                | o |             | n                   |
 *                | n |             |                     |
 *                +---+             +---------------------+
 */
enum auth_item_t {

	/*
	 * items provided to authentication process
	 */
	
	/** CA certificate to use for authentication, value is certificate_t* */
	AUTHN_CA_CERT,
	/** Keyid of a CA certificate to use, value is identification_t* */
	AUTHN_CA_CERT_KEYID,
	/** subject DN of a CA certificate to use, value is identification_t* */
	AUTHN_CA_CERT_NAME,
	/** intermediate certificate, value is certificate_t* */
	AUTHN_IM_CERT,
	/** certificate for trustchain verification, value is certificate_t* */
	AUTHN_SUBJECT_CERT,
	
	/*
	 * item provided to authorization process
	 */
	
	/** subject has been authenticated by public key, value is public_key_t* */
	AUTHZ_PUBKEY,
	/** subject has ben authenticated using preshared secrets, value is shared_key_t* */ 
	AUTHZ_PSK,
	/** subject has been authenticated using EAP, value is eap_method_t */
	AUTHZ_EAP,
	/** certificate authority, value is certificate_t* */
	AUTHZ_CA_CERT,
	/** subject DN of a certificate authority, value is identification_t* */
	AUTHZ_CA_CERT_NAME,
	/** intermediate certificate in trustchain, value is certificate_t* */
	AUTHZ_IM_CERT,
	/** subject certificate, value is certificate_t* */
	AUTHZ_SUBJECT_CERT,
	/** result of a CRL validation, value is cert_validation_t */
	AUTHZ_CRL_VALIDATION,
	/** result of a OCSP validation, value is cert_validation_t */
	AUTHZ_OCSP_VALIDATION,
	/** subject is in attribute certificate group, value is identification_t* */
	AUTHZ_AC_GROUP,
};


/**
 * enum name for auth_item_t.
 */
extern enum_name_t *auth_item_names;

/**
 * The auth_info class contains auth_item_t's used for AA.
 *
 * A auth_info allows the separation of authentication and authorization. 
 */
struct auth_info_t {

	/**
	 * Add an item to the set.
	 *
	 * @param type		auth_info type
	 * @param value		associated value to auth_info type, if any
	 */
	void (*add_item)(auth_info_t *this, auth_item_t type, void *value);
	
	/**
	 * Get an item.
	 *
	 * @param type		auth_info type to get
	 * @param value		pointer to a pointer receiving item
	 * @return			bool if item has been found
	 */
	bool (*get_item)(auth_info_t *this, auth_item_t type, void **value);
	
	/**
	 * Create an enumerator over all items.
	 *
	 * @return			enumerator over (auth_item_t type, void *value)
	 */
	enumerator_t* (*create_item_enumerator)(auth_info_t *this);
	
	/**
	 * Check if this fulfills a set of required constraints.
	 *
	 * @param constraints	required authorization infos
	 * @return				TRUE if this complies with constraints
	 */
	bool (*complies)(auth_info_t *this, auth_info_t *constraints);
	
	/**
	 * Merge items from other into this.
  	 *
	 * Items do not get cloned, but moved from other to this.
	 *
	 * @param other		items to read for merge
	 */
	void (*merge)(auth_info_t *this, auth_info_t *other);
	
	/**
	 * Check two auth_infos for equality.
	 *
	 * @param other		other item to compaire against this
	 * @return			TRUE if auth infos identical
	 */
	bool (*equals)(auth_info_t *this, auth_info_t *other);
	
	/**
     * Destroy a auth_info instance with all associated values.
     */
    void (*destroy)(auth_info_t *this);
};

/**
 * Create a auth_info instance.
 */
auth_info_t *auth_info_create();

#endif /* AUTH_INFO_H_ @}*/
