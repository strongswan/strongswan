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
 *
 * RCSID $Id$
 */

#ifndef _CA_H
#define _CA_H

#include "x509.h"
#include "whack.h"

#define MAX_CA_PATH_LEN		7

/* authority flags */

#define AUTH_NONE	0x00	/* no authorities */
#define AUTH_CA		0x01	/* certification authority */
#define AUTH_AA		0x02	/* authorization authority */
#define AUTH_OCSP	0x04	/* ocsp signing authority */

/* CA info structures */

typedef struct ca_info ca_info_t;

struct ca_info {
    ca_info_t       *next;
    char	    *name;
    time_t	    installed;
    chunk_t	    authName;
    chunk_t	    authKeyID;
    chunk_t	    authKeySerialNumber;
    char	    *ldaphost;
    char	    *ldapbase;
    char	    *ocspuri;
    generalName_t   *crluri;
    bool	    strictcrlpolicy;
};

extern bool trusted_ca(chunk_t a, chunk_t b, int *pathlen);
extern bool match_requested_ca(generalName_t *requested_ca
    , chunk_t our_ca, int *our_pathlen);
extern x509cert_t* get_authcert(chunk_t subject, chunk_t serial, chunk_t keyid
    , u_char auth_flags);
extern void load_authcerts(const char *type, const char *path
    , u_char auth_flags);
extern x509cert_t* add_authcert(x509cert_t *cert, u_char auth_flags);
extern void free_authcerts(void);
extern void list_authcerts(const char *caption, u_char auth_flags, bool utc);
extern bool trust_authcert_candidate(const x509cert_t *cert
    , const x509cert_t *alt_chain);
extern ca_info_t* get_ca_info(chunk_t name, chunk_t serial, chunk_t keyid);
extern bool find_ca_info_by_name(const char *name, bool delete);
extern void add_ca_info(const whack_message_t *msg);
extern void delete_ca_info(const char *name);
extern void free_ca_infos(void);
extern void list_ca_infos(bool utc);

#endif /* _CA_H */

