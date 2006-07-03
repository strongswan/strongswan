/**
 * @file certinfo.h
 * 
 * @brief Interface of certinfo_t.
 * 
 */

/*
 * Copyright (C) 2006 Andreas Steffen
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

#ifndef CERTINFO_H_
#define CERTINFO_H_

#include <types.h>
#include <definitions.h>

/**
 * RFC 2560 OCSP - certificate status
 */
extern enum_names cert_status_names;

typedef enum {
	CERT_GOOD = 		0,
	CERT_REVOKED = 		1,
	CERT_UNKNOWN = 		2,
	CERT_UNDEFINED =	3,
	CERT_UNTRUSTED =	4  /* private use */
} cert_status_t;

/**
 * RFC 2459 CRL reason codes
 */

extern enum_names crl_reason_names;

typedef enum {
    REASON_UNSPECIFIED =			0,
    REASON_KEY_COMPROMISE = 		1,
    REASON_CA_COMPROMISE = 			2,
    REASON_AFFILIATION_CHANGED =	3,
    REASON_SUPERSEDED =				4,
    REASON_CESSATION_OF_OPERATON =	5,
    REASON_CERTIFICATE_HOLD =		6,
    REASON_REMOVE_FROM_CRL =		8
} crl_reason_t;

typedef struct certinfo_t certinfo_t;

/**
 * @brief X.509 certificate status information
 * 
 * 
 * @ingroup transforms
 */
struct certinfo_t {

	/**
	 * @brief Get serial number
	 * 
	 * 
	 * @param this				calling object
	 * @return					serialNumber
	 */
	chunk_t (*get_serialNumber) (const certinfo_t *this);

	/**
	 * @brief Set certificate status
	 * 
	 * 
	 * @param this				calling object
	 * @param status			status
	 */
	void (*set_status) (certinfo_t *this, cert_status_t status);

	/**
	 * @brief Get certificate status
	 * 
	 * 
	 * @param this				calling object
	 * @return					status
	 */
	cert_status_t (*get_status) (const certinfo_t *this);

	/**
	 * @brief Set nextUpdate
	 * 
	 * 
	 * @param this				calling object
	 * @return					nextUpdate
	 */
	void (*set_nextUpdate) (certinfo_t *this, time_t nextUpdate);

	/**
	 * @brief Get nextUpdate
	 * 
	 * 
	 * @param this				calling object
	 * @return					nextUpdate
	 */
	time_t (*get_nextUpdate) (const certinfo_t *this);

	/**
	 * @brief Set revocationTime
	 * 
	 * 
	 * @param this				calling object
	 * @param revocationTime	revocationTime
	 */
	void (*set_revocationTime) (certinfo_t *this, time_t revocationTime);

	/**
	 * @brief Get revocationTime
	 * 
	 * 
	 * @param this				calling object
	 * @return					revocationTime
	 */
	time_t (*get_revocationTime) (const certinfo_t *this);

	/**
	 * @brief Set revocationReason
	 * 
	 * 
	 * @param this				calling object
	 * @param reason			revocationReason
	 */
	void (*set_revocationReason) (certinfo_t *this, crl_reason_t reason);

	/**
	 * @brief Get revocationReason
	 * 
	 * 
	 * @param this				calling object
	 * @return					revocationReason
	 */
	const char *(*get_revocationReason) (const certinfo_t *this);

	/**
	 * @brief Destroys the certinfo_t object.
	 * 
	 * @param this			crl to destroy
	 */
	void (*destroy) (certinfo_t *this);

};

/**
 * @brief Create a certinfo_t object.
 * 
 * @param serial 	chunk serial number of the certificate
 * @return 			created certinfo_t object
 * 
 * @ingroup transforms
 */
certinfo_t *certinfo_create(chunk_t serial);

#endif /* CERTINFO_H_ */
