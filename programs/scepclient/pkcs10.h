/**
 * @file pkcs10.h
 * @brief Functions to build PKCS#10 Request's
 * 
 * Contains functions to build DER encoded pkcs#10 certificate requests
 */
 
/*
 * Copyright (C) 2005 Jan Hutter, Martin Willi
 * Hochschule fuer Technik Rapperswil
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

#ifndef _PKCS10_H
#define _PKCS10_H

#include "../pluto/defs.h"
#include "../pluto/pkcs1.h"
#include "../pluto/x509.h"

typedef struct pkcs10_struct pkcs10_t;

/**
 * @brief type representating a pkcs#10 request.
 *
 * A pkcs#10 request contains a distinguished name, an optional 
 * challenge password, a public key and optional subjectAltNames.
 * 
 * The RSA private key is needed to compute the signature of the given request
 */
struct pkcs10_struct {
    RSA_private_key_t *private_key;
    chunk_t            request;
    chunk_t            subject;
    chunk_t            challengePassword;
    generalName_t     *subjectAltNames;
};

extern const pkcs10_t empty_pkcs10;

extern void pkcs10_add_subjectAltName(generalName_t **subjectAltNames
    , generalNames_t kind, char *value);
extern pkcs10_t* pkcs10_build(RSA_private_key_t *key, chunk_t subject
    , chunk_t challengePassword, generalName_t *subjectAltNames
    , int signature_alg);
extern void pkcs10_free(pkcs10_t *pkcs10);

#endif /* _PKCS10_H */
