/* Support of X.509 certificate revocation lists (CRLs)
 * Copyright (C) 2000-2004 Andreas Steffen, Zuercher Hochschule Winterthur
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

#include "constants.h"

#include <utils/linked_list.h>
#include <credentials/certificates/certificate.h>
#include <credentials/certificates/crl.h>

/* storage structure for an X.509 CRL */

typedef struct x509crl x509crl_t;

struct x509crl {
	certificate_t *crl;
	x509crl_t     *next;
	linked_list_t *distributionPoints;
	chunk_t        signature;
};

/* apply a strict CRL policy
 * flag set in plutomain.c and used in ipsec_doi.c and rcv_whack.c
 */
extern bool strict_crl_policy;

/*
 * cache the retrieved CRLs by storing them locally as a file
 */
extern bool cache_crls;

/*
 * check periodically for expired crls
 */
extern long crl_check_interval;
extern void load_crls(void);
extern void check_crls(void);
extern bool insert_crl(x509crl_t *crl, char *crl_uri, bool cache_crl);
extern cert_status_t verify_by_crl(const x509cert_t *cert, time_t *until,
								   time_t *revocationDate,
								   crl_reason_t *revocationReason);
extern void list_crls(bool utc, bool strict);
extern void free_crls(void);
extern void free_crl(x509crl_t *crl);
