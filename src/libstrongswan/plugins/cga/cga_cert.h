/*
 * Copyright (C) 2015 Martin Willi
 * Copyright (C) 2015 revosec AG
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
 * @defgroup cga_cert cga_cert
 * @{ @ingroup cga_p
 */

#ifndef CGA_CERT_H_
#define CGA_CERT_H_

typedef struct cga_cert_t cga_cert_t;

#include <credentials/builder.h>
#include <credentials/certificates/certificate.h>

/**
 * IPv6 CGA parameters implemented as certificate_t
 */
struct cga_cert_t {

	/**
	 * Implements the certificate_t interface
	 */
	certificate_t interface;
};

/**
 * Load IPv6 CGA parameters as a certificate.
 *
 * This function takes a BUILD_BLOB builder part.
 *
 * @param type		certificate type, CERT_CGA_PARAMS only
 * @param args		builder_part_t argument list
 * @return			CGA parameters as certificate, NULL on failure
 */
cga_cert_t *cga_cert_load(certificate_type_t type, va_list args);

/**
 * Generate new IPv6 CGA parameters from a public key.
 *
 * This function takes a BUILD_PUBLIC_KEY with the public key, a
 * BUILD_CGA_PREFIX defining the subnet prefix, and optionally a BUILD_CGA_SEC,
 * the security parameter Sec.
 *
 * @param type		certificate type, CERT_CGA_PARAMS only
 * @param args		builder_part_t argument list
 * @return			CGA parameters as certificate, NULL on failure
 */
cga_cert_t *cga_cert_gen(certificate_type_t type, va_list args);

#endif /** CGA_CERT_H_ @}*/
