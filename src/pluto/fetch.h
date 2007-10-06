/* Dynamic fetching of X.509 CRLs
 * Copyright (C) 2002 Stephane Laroche <stephane.laroche@colubris.com>
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

#include "x509.h"

#define FETCH_CMD_TIMEOUT	10	/* seconds */

struct ocsp_location;	/* forward declaration of ocsp_location defined in ocsp.h */

typedef enum {
    FETCH_GET =  1,
    FETCH_POST = 2
} fetch_request_t;

typedef struct fetch_req fetch_req_t;

struct fetch_req {
    fetch_req_t   *next;
    time_t        installed;
    int           trials;
    chunk_t       issuer;
    chunk_t       authKeyID;
    chunk_t	  authKeySerialNumber;
    generalName_t *distributionPoints;
};

#ifdef THREADS
extern void lock_crl_list(const char *who);
extern void unlock_crl_list(const char *who);
extern void lock_ocsp_cache(const char *who);
extern void unlock_ocsp_cache(const char *who);
extern void lock_ca_info_list(const char *who);
extern void unlock_ca_info_list(const char *who);
extern void lock_authcert_list(const char *who);
extern void unlock_authcert_list(const char *who);
extern void lock_certs_and_keys(const char *who);
extern void unlock_certs_and_keys(const char *who);
extern void wake_fetch_thread(const char *who);
#else
#define lock_crl_list(who)          /* do nothing */
#define unlock_crl_list(who)        /* do nothing */
#define lock_ocsp_cache(who)        /* do nothing */
#define unlock_ocsp_cache(who)      /* do nothing */
#define lock_ca_info_list(who)      /* do nothing */
#define unlock_ca_info_list(who)    /* do nothing */
#define lock_authcert_list(who)     /* do nothing */
#define unlock_authcert_list(who)   /* do nothing */
#define lock_certs_and_keys(who)    /* do nothing */
#define unlock_certs_and_keys(who)  /* do nothing */
#define wake_fetch_thread(who)      /* do nothing */
#endif
extern void init_fetch(void);
extern void free_crl_fetch(void);
extern void free_ocsp_fetch(void);
extern void add_distribution_points(const generalName_t *newPoints
    , generalName_t **distributionPoints);
extern fetch_req_t* build_crl_fetch_request(chunk_t issuer, chunk_t authKeySerialNumber
    , chunk_t authKeyID, const generalName_t *gn);
extern void add_crl_fetch_request(fetch_req_t *req);
extern void add_ocsp_fetch_request(struct ocsp_location *location, chunk_t serialNumber);
extern void list_distribution_points(const generalName_t *gn);
extern void list_crl_fetch_requests(bool utc);
extern void list_ocsp_fetch_requests(bool utc);
extern size_t write_buffer(void *ptr, size_t size, size_t nmemb, void *data);

