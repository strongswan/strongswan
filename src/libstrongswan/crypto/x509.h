/**
 * @file x509.h
 * 
 * @brief Interface of x509_t.
 * 
 */

/*
 * Copyright (C) 2000 Andreas Hess, Patric Lichtsteiner, Roger Wegmann
 * Copyright (C) 2001 Marco Bertossa, Andreas Schleiss
 * Copyright (C) 2002 Mario Strasser
 * Copyright (C) 2000-2004 Andreas Steffen, Zuercher Hochschule Winterthur
 * Copyright (C) 2006 Martin Willi, Andreas Steffen
 *
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
 * RCSID $Id$
 */

#ifndef X509_H_
#define X509_H_

typedef struct x509_t x509_t;

#include <library.h>
#include <crypto/rsa/rsa_private_key.h>
#include <crypto/hashers/hasher.h>
#include <crypto/certinfo.h>
#include <crypto/ca.h>
#include <utils/identification.h>
#include <utils/iterator.h>
#include <utils/linked_list.h>

/* authority flags */

#define AUTH_NONE	0x00	/* no authorities */
#define AUTH_CA		0x01	/* certification authority */
#define AUTH_AA		0x02	/* authorization authority */
#define AUTH_OCSP	0x04	/* ocsp signing authority */

/**
 * @brief X.509 certificate.
 * 
 * @b Constructors:
 *  - x509_create()
 *  - x509_create_from_chunk()
 *  - x509_create_from_file()
 *
 * @ingroup crypto
 */
struct x509_t {

	/**
	 * @brief Set trusted public key life.
	 * 
	 * @param this				calling object
	 * @param until				time until public key is trusted
	 */
	void (*set_until) (x509_t *this, time_t until);

	/**
	 * @brief Get trusted public key life.
	 * 
	 * @param this				calling object
	 * @return					time until public key is trusted
	 */
	time_t (*get_until) (const x509_t *this);

	/**
	 * @brief Set the certificate status
	 * 
	 * @param this				calling object
	 * @param status			certificate status
	 */
	void (*set_status) (x509_t *this, cert_status_t status);

	/**
	 * @brief Get the certificate status
	 * 
	 * @param this				calling object
	 * @return					certificate status
	 */
	cert_status_t (*get_status) (const x509_t *this);

	/**
	 * @brief Add authority flags
	 * 
	 * @param this				calling object
	 * @param flag				flags to be added
	 */
	void (*add_authority_flags) (x509_t *this, u_int flags);

	/**
	 * @brief Get authority flags
	 * 
	 * @param this				calling object
	 * @return					authority flags
	 */
	u_int (*get_authority_flags) (x509_t *this);

	/**
	 * @brief Check a specific authority flag
	 * 
	 * @param this				calling object
	 * @param flag				flag to be checked
	 * @return					TRUE if flag is present
	 */
	bool (*has_authority_flag) (x509_t *this, u_int flag);

	/**
	 * @brief Get the DER-encoded X.509 certificate body
	 * 
	 * @param this				calling object
	 * @return					DER-encoded X.509 certificate
	 */
	chunk_t (*get_certificate) (const x509_t *this);

	/**
	 * @brief Get the RSA public key from the certificate.
	 * 
	 * @param this				calling object
	 * @return					public_key
	 */
	rsa_public_key_t *(*get_public_key) (const x509_t *this);

	/**
	 * @brief Get serial number from the certificate.
	 * 
	 * @param this				calling object
	 * @return					serialNumber
	 */
	chunk_t (*get_serialNumber) (const x509_t *this);
		
	/**
	 * @brief Get subjectKeyID from the certificate.
	 * 
	 * @param this				calling object
	 * @return					subjectKeyID
	 */
	chunk_t (*get_subjectKeyID) (const x509_t *this);

	/**
	 * @brief Get keyid from the certificate's public key.
	 * 
	 * @param this				calling object
	 * @return					keyid
	 */
	chunk_t (*get_keyid) (const x509_t *this);

	/**
	 * @brief Get the issuerDistinguishedName
	 * 
	 * The resulting ID is always a identification_t
	 * of type ID_DER_ASN1_DN.
	 * 
	 * @param this				calling object
	 * @return					issuers ID
	 */
	identification_t *(*get_issuer) (const x509_t *this);

	/**
	 * @brief Get the subjectDistinguishedName.
	 * 
	 * The resulting ID is always a identification_t
	 * of type ID_DER_ASN1_DN. 
	 * 
	 * @param this				calling object
	 * @return					subjects ID
	 */
	identification_t *(*get_subject) (const x509_t *this);

	/**
	 * @brief Set a link  ca info
	 * 
	 * @param this				calling object
	 * @param ca_info			link to the info record of the issuing ca
	 */
	void (*set_ca_info) (x509_t *this, ca_info_t *ca_info);

	/**
	 * @brief Get the .
	 * 
	 * The resulting ID is always a identification_t
	 * of type ID_DER_ASN1_DN. 
	 * 
	 * @param this				calling object
	 * @return					link to the info record of the issuing ca
	 *							or NULL if it does not [yet] exist
	 */
	ca_info_t *(*get_ca_info) (const x509_t *this);

	/**
	 * @brief Create an iterator for the crlDistributionPoints.
	 * 
	 * @param this				calling object
	 * @return					iterator for crlDistributionPoints
	 */
	iterator_t *(*create_crluri_iterator) (const x509_t *this);

	/**
	 * @brief Create an iterator for the ocspAccessLocations.
	 * 
	 * @param this				calling object
	 * @return					iterator for ocspAccessLocations
	 */
	iterator_t *(*create_ocspuri_iterator) (const x509_t *this);

	/**
	 * @brief Check if a certificate is trustworthy
	 * 
	 * @param this			calling object
	 * @param signer		signer's RSA public key
	 */
	bool (*verify) (const x509_t *this, const rsa_public_key_t *signer);

	/**
	 * @brief Compare two certificates.
	 * 
	 * Comparison is done via the certificates signature.
	 * 
	 * @param this			first cert for compare
	 * @param other			second cert for compare
	 * @return				TRUE if signature is equal
	 */
	bool (*equals) (const x509_t *this, const x509_t *that);

	/**
	 * @brief Checks if the certificate contains a subjectAltName equal to id.
	 * 
	 * @param this			certificate being examined
	 * @param id			id which is being compared to the subjectAltNames
	 * @return				TRUE if a match is found
	 */
	bool (*equals_subjectAltName) (const x509_t *this, identification_t *id);

	/**
	 * @brief Checks if the subject of the other cert is the issuer of this cert.
	 * 
	 * @param this			certificate
	 * @param issuer		potential issuer certificate
	 * @return				TRUE if issuer is found
	 */
	bool (*is_issuer) (const x509_t *this, const x509_t *issuer);

	/**
	 * @brief Checks the validity interval of the certificate
	 * 
	 * @param this			certificate being examined
	 * @param until			until = min(until, notAfter)
	 * @return				NULL if the certificate is valid
	 */
	err_t (*is_valid) (const x509_t *this, time_t *until);

	/**
	 * @brief Returns the CA basic constraints flag
	 * 
	 * @param this			certificate being examined
	 * @return				TRUE if the CA flag is set
	 */
	bool (*is_ca) (const x509_t *this);

	/**
	 * @brief Returns the OCSPSigner extended key usage flag
	 * 
	 * @param this			certificate being examined
	 * @return				TRUE if the OCSPSigner flag is set
	 */
	bool (*is_ocsp_signer) (const x509_t *this);

	/**
	 * @brief Checks if the certificate is self-signed (subject equals issuer)
	 * 
	 * @param this			certificate being examined
	 * @return				TRUE if self-signed
	 */
	bool (*is_self_signed) (const x509_t *this);
	
	/**
	 * @brief Log the certificate info to out.
	 *
	 * @param this			calling object
	 * @param out			stream to write to
	 * @param utc			TRUE for UTC times, FALSE for local time
	 */
	void (*list) (x509_t *this, FILE *out, bool utc);
	
	/**
	 * @brief Adds a list of subjectAltNames
	 * 
	 * @param this				calling object
	 * @param subjectAltNames	list of subjectAltNames to be added
	 */
	void (*add_subjectAltNames) (x509_t *this, linked_list_t *subjectAltNames);

	/**
	 * @brief Builds a DER-encoded signed X.509 certificate
	 * 
	 * @param this			calling object
	 * @param alg			hash algorithm used to compute the certificate digest
	 * @param private_key	RSA private key used to sign the certificate digest
	 */
	void (*build_encoding) (x509_t *this, hash_algorithm_t alg, rsa_private_key_t *private_key);

	/**
	 * @brief Destroys the certificate.
	 * 
	 * @param this			certificate to destroy
	 */
	void (*destroy) (x509_t *this);
};

/**
 * @brief Create a X.509 certificate from its components
 *
 * @param serialNumber	chunk containing the serialNumber
 * @param issuer		issuer distinguished name
 * @param notBefore		start date of validity
 * @param notAfter		end date of validity
 * @param subject		subject distinguished name
 *
 * @return				created x509_t certificate, or NULL if invalid.
 *
 * @ingroup crypto
 */
x509_t *x509_create(chunk_t serialNumber, identification_t *issuer,
					time_t notBefore, time_t notAfter,
					identification_t *subject);

/**
 * @brief Read a X.509 certificate from a DER encoded blob.
 *
 * @param chunk 	chunk containing DER encoded data
 * @return 			created x509_t certificate, or NULL if invalid.
 * 
 * @ingroup crypto
 */
x509_t *x509_create_from_chunk(chunk_t chunk, u_int level);

/**
 * @brief Read a X.509 certificate from a DER encoded file.
 * 
 * @param filename 	file containing DER encoded data
 * @param label		label describing kind of certificate
 * @return 			created x509_t certificate, or NULL if invalid.
 * 
 * @ingroup crypto
 */
x509_t *x509_create_from_file(const char *filename, const char *label);

/**
 * @brief Parses a DER encoded authorityKeyIdentifier
 * 
 * @param blob 					blob containing DER encoded data
 * @param level0 				indicates the current parsing level
 * @param authKeyID				assigns the authorityKeyIdentifier
 * @param authKeySerialNumber	assigns the authKeySerialNumber
 * 
 * @ingroup crypto
 */
void x509_parse_authorityKeyIdentifier(chunk_t blob, int level0, chunk_t *authKeyID, chunk_t *authKeySerialNumber);

/**
 * @brief Parses DER encoded generalNames
 * 
 * @param blob 			blob containing DER encoded data
 * @param level0 		indicates the current parsing level
 * @param implicit		implicit coding is used
 * @param list			list of decoded generalNames
 * 
 * @ingroup crypto
 */
void x509_parse_generalNames(chunk_t blob, int level0, bool implicit, linked_list_t *list);

/**
 * @brief Builds a DER encoded list of generalNames
 * 
 * @param list			list of generalNames to be encoded
 * @return				DER encoded list of generalNames
 * 
 * @ingroup crypto
 */
chunk_t x509_build_generalNames(linked_list_t *list);

/**
 * @brief Builds a DER encoded list of subjectAltNames
 * 
 * @param list			list of subjectAltNames to be encoded
 * @return				DER encoded list of subjectAltNames
 * 
 * @ingroup crypto
 */
chunk_t x509_build_subjectAltNames(linked_list_t *list);

#endif /* X509_H_ */
