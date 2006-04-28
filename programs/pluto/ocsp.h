/* Support of the Online Certificate Status Protocol (OCSP) Support
 * Copyright (C) 2003 Christoph Gysin, Simon Zwahlen
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
 */

#include "constants.h"

/* constants */

#define OCSP_BASIC_RESPONSE_VERSION	1
#define OCSP_DEFAULT_VALID_TIME		120  /* validity of one-time response in seconds */
#define OCSP_WARNING_INTERVAL		2    /* days */

/* OCSP response status */

typedef enum {
    STATUS_SUCCESSFUL = 	0,
    STATUS_MALFORMEDREQUEST = 	1,
    STATUS_INTERNALERROR = 	2,
    STATUS_TRYLATER = 		3,
    STATUS_SIGREQUIRED = 	5,
    STATUS_UNAUTHORIZED= 	6
} response_status;

/* OCSP access structures */

typedef struct ocsp_certinfo ocsp_certinfo_t;

struct ocsp_certinfo {
    ocsp_certinfo_t  *next;
    int              trials;
    chunk_t          serialNumber;
    cert_status_t    status;
    bool             once;
    crl_reason_t     revocationReason;
    time_t           revocationTime;
    time_t           thisUpdate;
    time_t           nextUpdate;
};

typedef struct ocsp_location ocsp_location_t;

struct ocsp_location {
    ocsp_location_t  *next;
    chunk_t          issuer;
    chunk_t          authNameID;
    chunk_t          authKeyID;
    chunk_t	     authKeySerialNumber;
    chunk_t          uri;
    chunk_t          nonce;
    ocsp_certinfo_t  *certinfo;
};

extern ocsp_location_t* get_ocsp_location(const ocsp_location_t *loc
    , ocsp_location_t *chain);
extern ocsp_location_t* add_ocsp_location(const ocsp_location_t *loc
    , ocsp_location_t **chain);
extern void add_certinfo(ocsp_location_t *loc, ocsp_certinfo_t *info
    , ocsp_location_t **chain, bool request);
extern void check_ocsp(void);
extern cert_status_t verify_by_ocsp(const x509cert_t *cert, time_t *until
    , time_t *revocationTime, crl_reason_t *revocationReason);
extern bool ocsp_set_request_cert(char* path);
extern void ocsp_set_default_uri(char* uri);
extern void ocsp_cache_add_cert(const x509cert_t* cert);
extern chunk_t build_ocsp_request(ocsp_location_t* location);
extern void parse_ocsp(ocsp_location_t* location, chunk_t blob);
extern void list_ocsp_locations(ocsp_location_t *location, bool requests
    , bool utc, bool strict);
extern void list_ocsp_cache(bool utc, bool strict);
extern void free_ocsp_locations(ocsp_location_t **chain);
extern void free_ocsp_cache(void);
extern void free_ocsp(void);
extern void ocsp_purge_cache(void);
