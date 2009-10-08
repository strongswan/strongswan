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
#include <credentials/keys/public_key.h>
#include <credentials/keys/private_key.h>
#include <credentials/certificates/x509.h>

#include "constants.h"
#include "id.h"

/* access structure for an X.509v3 certificate */

typedef struct x509cert x509cert_t;

struct x509cert {
	certificate_t  *cert;
	x509cert_t     *next;
	int             count;
	bool            smartcard;
};

/* used for initialization */
extern const x509cert_t empty_x509cert;

extern bool same_keyid(chunk_t a, chunk_t b);
extern bool same_dn(chunk_t a, chunk_t b);
extern bool match_dn(chunk_t a, chunk_t b, int *wildcards);
extern int dn_count_wildcards(chunk_t dn);
extern int dntoa(char *dst, size_t dstlen, chunk_t dn);
extern err_t atodn(char *src, chunk_t *dn);
extern void select_x509cert_id(x509cert_t *cert, struct id *end_id);
extern void parse_authorityKeyIdentifier(chunk_t blob, int level0,
										 chunk_t *authKeyID,
										 chunk_t *authKeySerialNumber);
extern bool x509_check_signature(chunk_t tbs, chunk_t sig, int algorithm,
								 certificate_t *issuer_cert);
extern chunk_t x509_build_signature(chunk_t tbs, int algorithm,
									private_key_t *key, bool bit_string);
extern bool verify_x509cert(const x509cert_t *cert, bool strict, time_t *until);
extern x509cert_t* add_x509cert(x509cert_t *cert);
extern x509cert_t* get_x509cert(identification_t *issuer, chunk_t keyid, x509cert_t* chain);
extern void share_x509cert(x509cert_t *cert);
extern void release_x509cert(x509cert_t *cert);
extern void free_x509cert(x509cert_t *cert);
extern void store_x509certs(x509cert_t **firstcert, bool strict);
extern void list_x509cert_chain(const char *caption, x509cert_t* cert,
								x509_flag_t flags, bool utc);
extern void list_x509_end_certs(bool utc);

#endif /* _X509_H */
