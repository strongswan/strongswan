/**
 * @file ca.h
 * 
 * @brief Interface of ca_info_t.
 * 
 */

/*
 * Copyright (C) 2007 Andreas Steffen
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

#ifndef CA_H_
#define CA_H_

typedef struct ca_info_t ca_info_t;

#include <library.h>
#include <chunk.h>

#include <credential_store.h>

#include "x509.h"
#include "crl.h"

/**
 * @brief X.509 certification authority information record
 * 
 * @b Constructors:
 *  - ca_info_create()
 * 
 * @ingroup transforms
 */
struct ca_info_t {

	/**
	 * @brief Compare two ca info records
	 *
	 * Comparison is done via the keyid of the ca certificate
     *
	 * @param this			first ca info object
	 * @param that			second ca info objct
	 * @return				TRUE if a match is found
	 */
	bool (*equals) (const ca_info_t *this, const ca_info_t* that);

	/**
	 * @brief If the ca info record has the same name then release the name and URIs
	 * 
	 * @param this			ca info object
	 * @return				TRUE if a match is found
	 */
	bool (*equals_name_release_info) (ca_info_t *this, const char *name);

	/**
	 * @brief Checks if a certificate was issued by this ca
	 * 
	 * @param this			ca info object
	 * @param cert			certificate to be checked
	 * @return				TRUE if the issuing ca has been found
	 */
	bool (*is_cert_issuer) (ca_info_t *this, const x509_t *cert);

	/**
	 * @brief Checks if a crl was issued by this ca
	 * 
	 * @param this			ca info object
	 * @param crl			crl to be checked
	 * @return				TRUE if the issuing ca has been found
	 */
	bool (*is_crl_issuer) (ca_info_t *this, const crl_t *crl);

	/**
	 * @brief Merges info from a secondary ca info object
	 * 
	 * @param this			primary ca info object
	 * @param that			secondary ca info object
	 */
	void (*add_info) (ca_info_t *this, const ca_info_t *that);

	/**
	 * @brief Adds a new or replaces an obsoleted CRL
	 * 
	 * @param this			ca info object
	 * @param crl			crl to be added
	 */
	void (*add_crl) (ca_info_t *this, crl_t *crl);

	/**
	 * @brief Does the CA have a CRL?
	 * 
	 * @param this			ca info object
	 * @return				TRUE if crl is available
	 */
	bool (*has_crl) (ca_info_t *this);

	/**
	 * @brief Does the CA have OCSP certinfos?
	 * 
	 * @param this			ca info object
	 * @return				TRUE if there are any certinfos
	 */
	bool (*has_certinfos) (ca_info_t *this);

	/**
	 * @brief List the CRL onto the console
	 * 
	 * @param this			ca info object
	 * @param out			output stream
	 * @param utc			TRUE -  utc
							FALSE - local time
	 */
	void (*list_crl) (ca_info_t *this, FILE *out, bool utc);

	/**
	 * @brief List the OCSP certinfos onto the console
	 * 
	 * @param this			ca info object
	 * @param out			output stream
	 * @param utc			TRUE -  utc
							FALSE - local time
	 */
	void (*list_certinfos) (ca_info_t *this, FILE *out, bool utc);

	/**
	 * @brief Adds a CRL URI to a list
	 * 
	 * @param this			ca info object
	 * @param uri			crl uri to be added
	 */
	void (*add_crluri) (ca_info_t *this, chunk_t uri);

	/**
	 * @brief Adds a OCSP URI to a list
	 * 
	 * @param this			ca info object
	 * @param uri			ocsp uri to be added
	 */
	void (*add_ocspuri) (ca_info_t *this, chunk_t uri);

	/**
	 * @brief Get the ca certificate
	 * 
	 * @param this			ca info object
	 * @return				ca certificate
	 */
	x509_t* (*get_certificate) (ca_info_t *this);

	/**
	 * @brief Verify the status of a certificate by CRL
	 * 
	 * @param this			ca info object
	 * @param certinfo		detailed certificate status information
	 * @return				certificate status
	 */
	cert_status_t (*verify_by_crl) (ca_info_t* this, certinfo_t* certinfo);

	/**
	 * @brief Verify the status of a certificate by OCSP
	 * 
	 * @param this			ca info object
	 * @param certinfo		detailed certificate status information
	 * @param credentials	credential store needed for trust path verification
	 * @return				certificate status
	 */
	cert_status_t (*verify_by_ocsp) (ca_info_t* this, certinfo_t* certinfo, credential_store_t* credentials);

	/**
	 * @brief Purge the OCSP certinfos of a ca info record
	 * 
	 * @param this			ca info object
	 */
	void (*purge_ocsp) (ca_info_t *this);

	/**
	 * @brief Destroys a ca info record
	 * 
	 * @param this			ca info to destroy
	 */
	void (*destroy) (ca_info_t *this);
};

/**
 * @brief Create a ca info record
 * 
 * @param name 		name of the ca info record
 * @param cacert	path to the ca certificate
 * @return 			created ca_info_t, or NULL if invalid.
 * 
 * @ingroup transforms
 */
ca_info_t *ca_info_create(const char *name, x509_t *cacert);

#endif /* CA_H_ */
