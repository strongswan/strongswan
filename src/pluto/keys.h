/* mechanisms for preshared keys (public, private, and preshared secrets)
 * Copyright (C) 1998-2002  D. Hugh Redelmeier.
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
 * RCSID $Id: keys.h,v 1.7 2006/01/26 20:10:34 as Exp $
 */

#ifndef _KEYS_H
#define _KEYS_H

#include <gmp.h>    /* GNU Multi-Precision library */

#include "pkcs1.h"
#include "certs.h"

#ifndef SHARED_SECRETS_FILE
# define SHARED_SECRETS_FILE  IPSEC_CONFDIR "/ipsec.secrets"
#endif

const char *shared_secrets_file;

extern void load_preshared_secrets(int whackfd);
extern void free_preshared_secrets(void);

struct state;	/* forward declaration */

enum PrivateKeyKind {
    PPK_PSK,
 /* PPK_DSS, */	/* not implemented */
    PPK_RSA,
    PPK_PIN
};

extern const chunk_t *get_preshared_secret(const struct connection *c);
extern err_t unpack_RSA_public_key(RSA_public_key_t *rsa, const chunk_t *pubkey);
extern const RSA_private_key_t *get_RSA_private_key(const struct connection *c);
extern const RSA_private_key_t *get_x509_private_key(const x509cert_t *cert);

/* public key machinery  */

typedef struct pubkey pubkey_t;

struct pubkey {
    struct id id;
    unsigned refcnt;	/* reference counted! */
    enum dns_auth_level dns_auth_level;
    char *dns_sig;
    time_t installed_time
	, last_tried_time
	, last_worked_time
	, until_time;
    chunk_t issuer;
    chunk_t serial;
    enum pubkey_alg alg;
    union {
	RSA_public_key_t rsa;
    } u;
};

typedef struct pubkey_list pubkey_list_t;

struct pubkey_list {
    pubkey_t *key;
    pubkey_list_t *next;
};

extern pubkey_list_t *pubkeys;	/* keys from ipsec.conf or from certs */

extern pubkey_t *public_key_from_rsa(const RSA_public_key_t *k);
extern pubkey_list_t *free_public_keyentry(pubkey_list_t *p);
extern void free_public_keys(pubkey_list_t **keys);
extern void free_remembered_public_keys(void);
extern void delete_public_keys(const struct id *id, enum pubkey_alg alg
    , chunk_t issuer, chunk_t serial);

extern pubkey_t *reference_key(pubkey_t *pk);
extern void unreference_key(pubkey_t **pkp);


extern err_t add_public_key(const struct id *id
    , enum dns_auth_level dns_auth_level
    , enum pubkey_alg alg
    , const chunk_t *key
    , pubkey_list_t **head);

extern bool has_private_key(cert_t cert);
extern void add_x509_public_key(x509cert_t *cert, time_t until
    , enum dns_auth_level dns_auth_level);
extern void add_pgp_public_key(pgpcert_t *cert, time_t until
    , enum dns_auth_level dns_auth_level);
extern void remove_x509_public_key(const x509cert_t *cert);
extern void list_public_keys(bool utc);

struct gw_info;	/* forward declaration of tag (defined in dnskey.h) */
extern void transfer_to_public_keys(struct gw_info *gateways_from_dns
#ifdef USE_KEYRR
    , pubkey_list_t **keys
#endif /* USE_KEYRR */
    );
    
#endif /* _KEYS_H */
