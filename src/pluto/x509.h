/* Support of X.509 certificates
 * Copyright (C) 2000 Andreas Hess, Patric Lichtsteiner, Roger Wegmann
 * Copyright (C) 2001 Marco Bertossa, Andreas Schleiss
 * Copyright (C) 2002 Mario Strasser
 * Copyright (C) 2000-2009 Andreas Steffen, Hochschule fuer Technik Rapperswil
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

#ifndef _X509_H
#define _X509_H

#include <utils/identification.h>
#include <utils/linked_list.h>
#include <credentials/keys/private_key.h>
#include <credentials/certificates/x509.h>

#include "constants.h"
#include "certs.h"

extern bool same_keyid(chunk_t a, chunk_t b);
extern bool x509_check_signature(chunk_t tbs, chunk_t sig, int algorithm,
								 certificate_t *issuer_cert);
extern chunk_t x509_build_signature(chunk_t tbs, int algorithm,
									private_key_t *key, bool bit_string);
extern bool verify_x509cert(cert_t *cert, bool strict, time_t *until);
extern void store_x509certs(linked_list_t *certs, bool strict);
extern void list_x509cert_chain(const char *caption, cert_t* cert,
								x509_flag_t flags, bool utc);
extern void list_x509_end_certs(bool utc);

#endif /* _X509_H */
