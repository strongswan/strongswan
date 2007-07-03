/* Support of smartcards and cryptotokens
 * Copyright (C) 2003 Christoph Gysin, Simon Zwahlen
 * Copyright (C) 2004 David Buechi, Michael Meier
 * Zuercher Hochschule Winterthur
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
 * RCSID $Id: smartcard.h,v 1.14 2005/11/06 22:55:41 as Exp $
 */

#ifndef _SMARTCARD_H
#define _SMARTCARD_H

#include "certs.h"

#define SCX_TOKEN		  "%smartcard"
#define SCX_CERT_CACHE_INTERVAL	  60 /* seconds */
#define SCX_MAX_PIN_TRIALS	  3

/* smartcard operations */

typedef enum {
    SC_OP_NONE =    0,
    SC_OP_ENCRYPT = 1,
    SC_OP_DECRYPT = 2,
    SC_OP_SIGN =    3,
} sc_op_t;

/* smartcard record */

typedef struct smartcard smartcard_t;

struct smartcard {
    smartcard_t  *next;
    time_t	  last_load;
    cert_t	  last_cert;
    int		  count;
    int		  number;
    unsigned long slot;
    char	  *id;
    char	 *label;
    chunk_t	  pin;
    bool	  pinpad;
    bool	  valid;
    bool	  session_opened;
    bool	  logged_in;
    bool	  any_slot;
    long	  session;
};

extern const smartcard_t empty_sc;

/*  keep a PKCS#11 login during the lifetime of pluto
 *  flag set in plutomain.c and used in ipsec_doi.c and ocsp.c
 */
extern bool pkcs11_keep_state;

/* allow other applications access to pluto's PKCS#11 interface
 * via whack. Could be used e.g. for disk encryption
 */
extern bool pkcs11_proxy;

extern smartcard_t* scx_parse_number_slot_id(const char *number_slot_id);
extern void scx_init(const char *module, const char *init_args);
extern void scx_finalize(void);
extern bool scx_establish_context(smartcard_t *sc);
extern bool scx_login(smartcard_t *sc);
extern bool scx_on_smartcard(const char *filename);
extern bool scx_load_cert(const char *filename, smartcard_t **scp
    , cert_t *cert, bool *cached);
extern bool scx_verify_pin(smartcard_t *sc);
extern void scx_share(smartcard_t *sc);
extern bool scx_sign_hash(smartcard_t *sc, const u_char *in, size_t inlen
    , u_char *out, size_t outlen);
extern bool scx_encrypt(smartcard_t *sc, const u_char *in, size_t inlen
    , u_char *out, size_t *outlen);
extern bool scx_decrypt(smartcard_t *sc, const u_char *in, size_t inlen
    , u_char *out, size_t *outlen);
extern bool scx_op_via_whack(const char* msg, int inbase, int outbase
    , sc_op_t op, const char *keyid, int whackfd);
extern bool scx_get_pin(smartcard_t *sc, int whackfd);
extern size_t scx_get_keylength(smartcard_t *sc);
extern smartcard_t* scx_add(smartcard_t *sc);
extern smartcard_t* scx_get(x509cert_t *cert);
extern void scx_release(smartcard_t *sc);
extern void scx_release_context(smartcard_t *sc);
extern void scx_free_pin(chunk_t *pin);
extern void scx_free(smartcard_t *sc);
extern void scx_list(bool utc);
extern char *scx_print_slot(smartcard_t *sc, const char *whitespace);

#endif /* _SMARTCARD_H */
