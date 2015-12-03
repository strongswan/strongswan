/*
 * Copyright (C) 2015 Andreas Steffen
 * HSR Hochschule fuer Technik Rapperswil
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
 * @defgroup vici_cert_info vici_cert_info
 * @{ @ingroup vici
 */

#ifndef VICI_CERT_INFO_H_
#define VICI_CERT_INFO_H_

typedef struct vici_cert_info_t vici_cert_info_t;

#include <credentials/certificates/certificate.h>
#include <credentials/certificates/x509.h>

/**
 * Information on vici certificate types
 */
struct vici_cert_info_t {

	/**
	 * Certificate type string used in vici messages
	 */
	char *type_str;

	/**
	 * Caption describing the certificate type
	 */
	char *caption;

	/**
	 * Base certificate type
	 */
	certificate_type_t type;

	/**
	 * X.509 flag
	 */
	x509_flag_t flag;

};

/**
 * Retrieve information on a given certificate type
 *
 * @param type_str		Vici certificate type string
 * @return				Information record or NULL if not found
 */
vici_cert_info_t* vici_cert_info_retrieve(char *type_str);

#endif /** VICI_CERT_INFO_H_ @}*/
