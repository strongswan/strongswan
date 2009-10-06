/* Support of OpenPGP certificates
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

#ifndef _PGPCERT_H
#define _PGPCERT_H

#include <crypto/hashers/hasher.h>
#include <credentials/keys/private_key.h>
#include <credentials/keys/public_key.h>

/*
 * Length of PGP V3 fingerprint
 */
#define PGP_FINGERPRINT_SIZE    HASH_SIZE_MD5

typedef char fingerprint_t[PGP_FINGERPRINT_SIZE];

/* access structure for an OpenPGP certificate */

typedef struct pgpcert pgpcert_t;

struct pgpcert {
	pgpcert_t        *next;
	int              version;
	int              count;
	chunk_t          certificate;
	time_t           created;
	time_t           until;
	public_key_t     *public_key;
	identification_t *fingerprint;
};

extern const pgpcert_t pgpcert_empty;
extern bool parse_pgp(chunk_t blob, pgpcert_t *cert);
extern void share_pgpcert(pgpcert_t *cert);
extern void select_pgpcert_id(pgpcert_t *cert, struct id *end_id);
extern pgpcert_t* add_pgpcert(pgpcert_t *cert);
extern void list_pgp_end_certs(bool utc);
extern void release_pgpcert(pgpcert_t *cert);
extern void free_pgpcert(pgpcert_t *cert);

#endif /* _PGPCERT_H */
