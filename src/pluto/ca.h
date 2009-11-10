/* Certification Authority (CA) support for IKE authentication
 * Copyright (C) 2002-2004 Andreas Steffen, Zuercher Hochschule Winterthur
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

#ifndef _CA_H
#define _CA_H

#include <utils/linked_list.h>
#include <utils/identification.h>

#include "certs.h"
#include "whack.h"

/* CA info structures */

typedef struct ca_info ca_info_t;

struct ca_info {
	ca_info_t        *next;
	char             *name;
	identification_t *authName;
	chunk_t           authKeyID;
	char             *ldaphost;
	char             *ldapbase;
	char             *ocspuri;
	linked_list_t    *crluris;
	bool              strictcrlpolicy;
};

extern bool trusted_ca(identification_t *a, identification_t *b, int *pathlen);
extern bool match_requested_ca(linked_list_t *requested_ca,
							   identification_t *our_ca, int *our_pathlen);
extern cert_t* get_authcert(identification_t *subject, chunk_t keyid,
								x509_flag_t auth_flags);
extern void load_authcerts(char *type, char *path, x509_flag_t auth_flags);
extern cert_t* add_authcert(cert_t *cert, x509_flag_t auth_flags);
extern void free_authcerts(void);
extern void list_authcerts(const char *caption, x509_flag_t auth_flags, bool utc);
extern bool trust_authcert_candidate(const cert_t *cert, const cert_t *alt_chain);
extern ca_info_t* get_ca_info(identification_t *name, chunk_t keyid);
extern bool find_ca_info_by_name(const char *name, bool delete);
extern void add_ca_info(const whack_message_t *msg);
extern void delete_ca_info(const char *name);
extern void free_ca_infos(void);
extern void list_ca_infos(bool utc);

#endif /* _CA_H */

