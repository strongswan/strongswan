/* Certificate support for IKE authentication
 * Copyright (C) 2002-2009 Andreas Steffen
 *
 * HSR - Hochschule fuer Technik Rapperswil
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

#ifndef _CERTS_H
#define _CERTS_H

#include <credentials/keys/private_key.h>

#include "x509.h"
#include "pgpcert.h"

/* path definitions for private keys, end certs,
 * cacerts, attribute certs and crls
 */
#define PRIVATE_KEY_PATH  IPSEC_CONFDIR "/ipsec.d/private"
#define HOST_CERT_PATH    IPSEC_CONFDIR "/ipsec.d/certs"
#define CA_CERT_PATH      IPSEC_CONFDIR "/ipsec.d/cacerts"
#define A_CERT_PATH       IPSEC_CONFDIR "/ipsec.d/acerts"
#define AA_CERT_PATH      IPSEC_CONFDIR "/ipsec.d/aacerts"
#define OCSP_CERT_PATH    IPSEC_CONFDIR "/ipsec.d/ocspcerts"
#define CRL_PATH          IPSEC_CONFDIR "/ipsec.d/crls"
#define REQ_PATH          IPSEC_CONFDIR "/ipsec.d/reqs"

/* advance warning of imminent expiry of
 * cacerts, public keys, and crls
 */
#define CA_CERT_WARNING_INTERVAL        30 /* days */
#define OCSP_CERT_WARNING_INTERVAL      30 /* days */
#define PUBKEY_WARNING_INTERVAL          7 /* days */
#define CRL_WARNING_INTERVAL             7 /* days */
#define ACERT_WARNING_INTERVAL           1 /* day */

/* certificate access structure
 * currently X.509 and OpenPGP certificates are supported
 */
typedef struct {
	u_char type;
	union {
		x509cert_t *x509;
		pgpcert_t  *pgp;
	} u;
} cert_t;

/* used for initialization */
extern const cert_t empty_cert;

/*  do not send certificate requests
 *  flag set in plutomain.c and used in ipsec_doi.c
 */
extern bool no_cr_send;

extern private_key_t* load_private_key(char* filename, prompt_pass_t *pass,
									   key_type_t type);
extern chunk_t get_mycert(cert_t cert);
extern bool load_coded_file(char *filename, prompt_pass_t *pass,
							const char *type, chunk_t *blob, bool *pgp);
extern bool load_cert(char *filename, const char *label, cert_t *cert);
extern bool load_host_cert(char *filename, cert_t *cert);
extern bool load_ca_cert(char *filename, cert_t *cert);
extern bool same_cert(const cert_t *a, const cert_t *b);
extern void share_cert(cert_t cert);
extern void release_cert(cert_t cert);
extern void list_certs(bool utc);

#endif /* _CERTS_H */


