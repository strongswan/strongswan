/* Dynamic fetching of X.509 CRLs
 * Copyright (C) 2002 Stephane Laroche <stephane.laroche@colubris.com>
 * Copyright (C) 2002-2009 Andreas Steffen - Hochschule fuer Technik Rapperswil
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

#include <stdlib.h>
#include <errno.h>
#include <sys/time.h>
#include <time.h>
#include <string.h>

#ifdef THREADS
#include <pthread.h>
#endif

#include <freeswan.h>

#include <library.h>
#include <debug.h>
#include <asn1/asn1.h>
#include <credentials/certificates/certificate.h>

#include "constants.h"
#include "defs.h"
#include "log.h"
#include "id.h"
#include "x509.h"
#include "ca.h"
#include "whack.h"
#include "ocsp.h"
#include "crl.h"
#include "fetch.h"
#include "builder.h"

fetch_req_t empty_fetch_req = {
	NULL    , /* next */
		  0 , /* installed */
		  0 , /* trials */
  { NULL, 0}, /* issuer */
  { NULL, 0}, /* authKeyID */
  { NULL, 0}, /* authKeySerialNumber */
	NULL      /* distributionPoints */
};

/* chained list of crl fetch requests */
static fetch_req_t *crl_fetch_reqs  = NULL;

/* chained list of ocsp fetch requests */
static ocsp_location_t *ocsp_fetch_reqs = NULL;

#ifdef THREADS
static pthread_t thread;
static pthread_mutex_t certs_and_keys_mutex  = PTHREAD_MUTEX_INITIALIZER;
static pthread_mutex_t authcert_list_mutex   = PTHREAD_MUTEX_INITIALIZER;
static pthread_mutex_t crl_list_mutex        = PTHREAD_MUTEX_INITIALIZER;
static pthread_mutex_t ocsp_cache_mutex      = PTHREAD_MUTEX_INITIALIZER;
static pthread_mutex_t ca_info_list_mutex    = PTHREAD_MUTEX_INITIALIZER;
static pthread_mutex_t crl_fetch_list_mutex  = PTHREAD_MUTEX_INITIALIZER;
static pthread_mutex_t ocsp_fetch_list_mutex = PTHREAD_MUTEX_INITIALIZER;
static pthread_mutex_t fetch_wake_mutex      = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t  fetch_wake_cond       = PTHREAD_COND_INITIALIZER;

/**
 * lock access to my certs and keys
 */
void lock_certs_and_keys(const char *who)
{
	pthread_mutex_lock(&certs_and_keys_mutex);
	DBG(DBG_CONTROLMORE,
		DBG_log("certs and keys locked by '%s'", who)
	)
}

/**
 * Unlock access to my certs and keys
 */
void unlock_certs_and_keys(const char *who)
{
	DBG(DBG_CONTROLMORE,
		DBG_log("certs and keys unlocked by '%s'", who)
	)
	pthread_mutex_unlock(&certs_and_keys_mutex);
}

/**
 * Lock access to the chained authcert list
 */
void lock_authcert_list(const char *who)
{
	pthread_mutex_lock(&authcert_list_mutex);
	DBG(DBG_CONTROLMORE,
		DBG_log("authcert list locked by '%s'", who)
	)
}

/**
 * Unlock access to the chained authcert list
 */
void unlock_authcert_list(const char *who)
{
	DBG(DBG_CONTROLMORE,
		DBG_log("authcert list unlocked by '%s'", who)
	)
	pthread_mutex_unlock(&authcert_list_mutex);
}

/**
 * Lock access to the chained crl list
 */
void lock_crl_list(const char *who)
{
	pthread_mutex_lock(&crl_list_mutex);
	DBG(DBG_CONTROLMORE,
		DBG_log("crl list locked by '%s'", who)
	)
}

/**
 * Unlock access to the chained crl list
 */
void unlock_crl_list(const char *who)
{
	DBG(DBG_CONTROLMORE,
		DBG_log("crl list unlocked by '%s'", who)
	)
	pthread_mutex_unlock(&crl_list_mutex);
}

/**
 * Lock access to the ocsp cache
 */
extern void lock_ocsp_cache(const char *who)
{
	pthread_mutex_lock(&ocsp_cache_mutex);
	DBG(DBG_CONTROLMORE,
		DBG_log("ocsp cache locked by '%s'", who)
	)
}

/**
 * Unlock access to the ocsp cache
 */
extern void unlock_ocsp_cache(const char *who)
{
	DBG(DBG_CONTROLMORE,
		DBG_log("ocsp cache unlocked by '%s'", who)
	)
	pthread_mutex_unlock(&ocsp_cache_mutex);
}

/**
 * Lock access to the ca info list
 */
extern void lock_ca_info_list(const char *who)
{
	pthread_mutex_lock(&ca_info_list_mutex);
	DBG(DBG_CONTROLMORE,
		DBG_log("ca info list locked by '%s'", who)
	)
}

/**
 * Unlock access to the ca info list
 */
extern void unlock_ca_info_list(const char *who)
{
	DBG(DBG_CONTROLMORE,
		DBG_log("ca info list unlocked by '%s'", who)
	)
	pthread_mutex_unlock(&ca_info_list_mutex);
}

/**
 * Lock access to the chained crl fetch request list
 */
static void lock_crl_fetch_list(const char *who)
{
	pthread_mutex_lock(&crl_fetch_list_mutex);
	DBG(DBG_CONTROLMORE,
		DBG_log("crl fetch request list locked by '%s'", who)
	)
}

/**
 * Unlock access to the chained crl fetch request list
 */
static void unlock_crl_fetch_list(const char *who)
{
	DBG(DBG_CONTROLMORE,
		DBG_log("crl fetch request list unlocked by '%s'", who)
	)
	pthread_mutex_unlock(&crl_fetch_list_mutex);
}

/**
 * Lock access to the chained ocsp fetch request list
 */
static void lock_ocsp_fetch_list(const char *who)
{
	pthread_mutex_lock(&ocsp_fetch_list_mutex);
	DBG(DBG_CONTROLMORE,
		DBG_log("ocsp fetch request list locked by '%s'", who)
	)
}

/**
 * Unlock access to the chained ocsp fetch request list
 */
static void unlock_ocsp_fetch_list(const char *who)
{
	DBG(DBG_CONTROLMORE,
		DBG_log("ocsp fetch request list unlocked by '%s'", who)
	)
	pthread_mutex_unlock(&ocsp_fetch_list_mutex);
}

/**
 * Wakes up the sleeping fetch thread
 */
void wake_fetch_thread(const char *who)
{
	if (crl_check_interval > 0)
	{
		DBG(DBG_CONTROLMORE,
			DBG_log("fetch thread wake call by '%s'", who)
		)
		pthread_mutex_lock(&fetch_wake_mutex);
		pthread_cond_signal(&fetch_wake_cond);
		pthread_mutex_unlock(&fetch_wake_mutex);
	}
}
#else /* !THREADS */
#define lock_crl_fetch_list(who)    /* do nothing */
#define unlock_crl_fetch_list(who)  /* do nothing */
#define lock_ocsp_fetch_list(who)   /* do nothing */
#define unlock_ocsp_fetch_list(who) /* do nothing */
#endif /* !THREADS */

/**
 *  Free the dynamic memory used to store fetch requests
 */
static void free_fetch_request(fetch_req_t *req)
{
	free(req->issuer.ptr);
	free(req->authKeySerialNumber.ptr);
	free(req->authKeyID.ptr);
	free_generalNames(req->distributionPoints, TRUE);
	free(req);
}

#ifdef THREADS
/**
 * Fetch an ASN.1 blob coded in PEM or DER format from a URL
 */
x509crl_t* fetch_crl(char *url)
{
	x509crl_t *crl;
	chunk_t blob;

	DBG1("  fetching crl from '%s' ...", url);
	if (lib->fetcher->fetch(lib->fetcher, url, &blob, FETCH_END) != SUCCESS)
	{
		DBG1("crl fetching failed");
		return FALSE;
	}
	crl = lib->creds->create(lib->creds, CRED_CERTIFICATE, CERT_PLUTO_CRL,
							 BUILD_BLOB_PEM, blob, BUILD_END);
	free(blob.ptr);
	if (!crl)
	{
		DBG1("crl fetched successfully but data coded in unknown format");
	}
	return crl;
}

/**
 * Complete a distributionPoint URI with ca information
 */
static char* complete_uri(chunk_t distPoint, const char *ldaphost)
{
	char *uri;
	char *ptr  = distPoint.ptr;
	size_t len = distPoint.len;

	char *symbol = memchr(ptr, ':', len);

	if (symbol != NULL)
	{
		size_t type_len = symbol - ptr;
		
		if (type_len >= 4 && strncasecmp(ptr, "ldap", 4) == 0)
		{
			ptr = symbol + 1;
			len -= (type_len + 1);

			if (len > 2 && *ptr++ == '/' && *ptr++ == '/')
			{
				len -= 2;
				symbol = memchr(ptr, '/', len);
				
				if (symbol != NULL && symbol - ptr == 0 && ldaphost != NULL)
				{
					uri = malloc(distPoint.len + strlen(ldaphost) + 1);

					/* insert the ldaphost into the uri */
					sprintf(uri, "%.*s%s%.*s"
						, (int)(distPoint.len - len), distPoint.ptr
						, ldaphost
						, (int)len, symbol);
					return uri;
				}
			}
		}
	}
	
	/* default action:  copy distributionPoint without change */
	uri = malloc(distPoint.len + 1);
	sprintf(uri, "%.*s", (int)distPoint.len, distPoint.ptr);
	return uri;
}

/**
 * Try to fetch the crls defined by the fetch requests
 */
static void fetch_crls(bool cache_crls)
{
	fetch_req_t *req;
	fetch_req_t **reqp;

	lock_crl_fetch_list("fetch_crls");
	req  =  crl_fetch_reqs;
	reqp = &crl_fetch_reqs;

	while (req != NULL)
	{
		bool valid_crl = FALSE;
		generalName_t *gn = req->distributionPoints;
		const char *ldaphost;
		ca_info_t *ca;

		lock_ca_info_list("fetch_crls");

		ca = get_ca_info(req->issuer, req->authKeySerialNumber, req->authKeyID);
		ldaphost = (ca == NULL)? NULL : ca->ldaphost;

		while (gn != NULL)
		{
			char *uri = complete_uri(gn->name, ldaphost);
			x509crl_t *crl;
			
			crl = fetch_crl(uri);
			if (crl)
			{
				chunk_t crl_uri = chunk_clone(gn->name);

				if (insert_crl(crl, crl_uri, cache_crls))
				{
					DBG(DBG_CONTROL,
						DBG_log("we have a valid crl")
					)
					valid_crl = TRUE;
					free(uri);
					break;
				}
			}
			free(uri);
			gn = gn->next;
		}

		unlock_ca_info_list("fetch_crls");

		if (valid_crl)
		{
			/* delete fetch request */
			fetch_req_t *req_free = req;

			req   = req->next;
			*reqp = req;
			free_fetch_request(req_free);
		}
		else
		{
			/* try again next time */
			req->trials++;
			reqp = &req->next;
			req  =  req->next;
		}
	}
	unlock_crl_fetch_list("fetch_crls");
}

static void fetch_ocsp_status(ocsp_location_t* location)
{
	chunk_t request, response;
	char *uri;

	request = build_ocsp_request(location);
	response = chunk_empty;

	/* we need a null terminated string for curl */
	uri = malloc(location->uri.len + 1);
	memcpy(uri, location->uri.ptr, location->uri.len);
	*(uri + location->uri.len) = '\0';

	DBG1("  requesting ocsp status from '%s' ...", uri);
	if (lib->fetcher->fetch(lib->fetcher, uri, &response, 
							FETCH_REQUEST_DATA, request,
							FETCH_REQUEST_TYPE, "application/ocsp-request",
							FETCH_END) == SUCCESS)
	{
		parse_ocsp(location, response);
	}
	else
	{
		DBG1("ocsp request to %s failed", uri);
	}

	free(uri);
	free(request.ptr);
	chunk_free(&location->nonce);

	/* increment the trial counter of the unresolved fetch requests */
	{
		ocsp_certinfo_t *certinfo = location->certinfo;
		
		while (certinfo != NULL)
		{
			certinfo->trials++;
			certinfo = certinfo->next;
		}
	}
}

/**
 * Try to fetch the necessary ocsp information
 */
static void fetch_ocsp(void)
{
	ocsp_location_t *location;

	lock_ocsp_fetch_list("fetch_ocsp");
	location = ocsp_fetch_reqs;

	/* fetch the ocps status for all locations */
	while (location != NULL)
	{
		if (location->certinfo != NULL)
		{
			fetch_ocsp_status(location);
		}
		location = location->next;
	}

	unlock_ocsp_fetch_list("fetch_ocsp");
}

static void* fetch_thread(void *arg)
{
	struct timespec wait_interval;

	DBG(DBG_CONTROL,
		DBG_log("fetch thread started")
	)

	pthread_mutex_lock(&fetch_wake_mutex);

	while(1)
	{
		int status;

		wait_interval.tv_nsec = 0;
		wait_interval.tv_sec = time(NULL) + crl_check_interval;

		DBG(DBG_CONTROL,
			DBG_log("next regular crl check in %ld seconds", crl_check_interval)
		)
		status = pthread_cond_timedwait(&fetch_wake_cond, &fetch_wake_mutex
										, &wait_interval);

		if (status == ETIMEDOUT)
		{
			DBG(DBG_CONTROL,
				DBG_log(" ");
				DBG_log("*time to check crls and the ocsp cache")
			)
			check_ocsp();
			check_crls();
		}
		else
		{
			DBG(DBG_CONTROL,
				DBG_log("fetch thread was woken up")
			)
		}
		fetch_ocsp();
		fetch_crls(cache_crls);
	}
}
#endif /* THREADS*/

/**
 * Initializes curl and starts the fetching thread
 */
void init_fetch(void)
{
	if (crl_check_interval > 0)
	{
#ifdef THREADS
		int status = pthread_create( &thread, NULL, fetch_thread, NULL);

		if (status != 0)
		{
			plog("fetching thread could not be started, status = %d", status);
		}
#else   /* !THREADS */
		plog("warning: not compiled with pthread support");
#endif  /* !THREADS */
	}
}

void free_crl_fetch(void)
{
   lock_crl_fetch_list("free_crl_fetch");

	while (crl_fetch_reqs != NULL)
	{
		fetch_req_t *req = crl_fetch_reqs;
		crl_fetch_reqs = req->next;
		free_fetch_request(req);
	}

	unlock_crl_fetch_list("free_crl_fetch");
}

/**
 * Free the chained list of ocsp requests
 */
void free_ocsp_fetch(void)
{
	lock_ocsp_fetch_list("free_ocsp_fetch");
	free_ocsp_locations(&ocsp_fetch_reqs);
	unlock_ocsp_fetch_list("free_ocsp_fetch");
}


/**
 * Add additional distribution points
 */
void add_distribution_points(const generalName_t *newPoints ,generalName_t **distributionPoints)
{
	while (newPoints != NULL)
	{
		/* skip empty distribution point */
		if (newPoints->name.len > 0)
		{       
			bool add = TRUE;
			generalName_t *gn = *distributionPoints;

			while (gn != NULL)
			{
				if (gn->kind == newPoints->kind
				&& gn->name.len == newPoints->name.len
				&& memeq(gn->name.ptr, newPoints->name.ptr, gn->name.len))
				{
					/* skip if the distribution point is already present */
					add = FALSE;
					break;
				}
				gn = gn->next;
			}

			if (add)
			{
				/* clone additional distribution point */
				gn = clone_thing(*newPoints);
				gn->name = chunk_clone(newPoints->name);

				/* insert additional CRL distribution point */
				gn->next = *distributionPoints;
				*distributionPoints = gn;
			}
		}
		newPoints = newPoints->next;
	}
}

fetch_req_t* build_crl_fetch_request(chunk_t issuer, chunk_t authKeySerialNumber,
									 chunk_t authKeyID, const generalName_t *gn)
{
	fetch_req_t *req = malloc_thing(fetch_req_t);
	*req = empty_fetch_req;

	/* note current time */
	req->installed = time(NULL);

	/* clone fields */
	req->issuer = chunk_clone(issuer);
	req->authKeySerialNumber =  chunk_clone(authKeySerialNumber);
	req->authKeyID = chunk_clone(authKeyID);

	/* copy distribution points */
	add_distribution_points(gn, &req->distributionPoints);

	return req;
}

/**
 * Add a crl fetch request to the chained list
 */
void add_crl_fetch_request(fetch_req_t *req)
{
	fetch_req_t *r;

	lock_crl_fetch_list("add_crl_fetch_request");
	r = crl_fetch_reqs;

	while (r != NULL)
	{
		if ((req->authKeyID.ptr != NULL)? same_keyid(req->authKeyID, r->authKeyID)
				: (same_dn(req->issuer, r->issuer)
				&& same_serial(req->authKeySerialNumber, r->authKeySerialNumber)))
		{
			/* there is already a fetch request */
			DBG(DBG_CONTROL,
				DBG_log("crl fetch request already exists")
			)

			/* there might be new distribution points */
			add_distribution_points(req->distributionPoints, &r->distributionPoints);

			unlock_crl_fetch_list("add_crl_fetch_request");
			free_fetch_request(req);
			return;
		}
		r = r->next;
	}

	/* insert new fetch request at the head of the queue */
	req->next = crl_fetch_reqs;
	crl_fetch_reqs = req;

	DBG(DBG_CONTROL,
		DBG_log("crl fetch request added")
	)
	unlock_crl_fetch_list("add_crl_fetch_request");
}

/**
 * Add an ocsp fetch request to the chained list
 */
void add_ocsp_fetch_request(ocsp_location_t *location, chunk_t serialNumber)
{
	ocsp_certinfo_t certinfo;

	certinfo.serialNumber = serialNumber;

	lock_ocsp_fetch_list("add_ocsp_fetch_request");
	add_certinfo(location, &certinfo, &ocsp_fetch_reqs, TRUE);
	unlock_ocsp_fetch_list("add_ocsp_fetch_request");
}

/**
 * List all distribution points
 */
void list_distribution_points(const generalName_t *gn)
{
	bool first_gn = TRUE;

	while (gn != NULL)
	{
		whack_log(RC_COMMENT, "       %s '%.*s'", (first_gn)? "distPts: "
			:"         ", (int)gn->name.len, gn->name.ptr);
		first_gn = FALSE;
		gn = gn->next;
	}
}

/**
 *  List all fetch requests in the chained list
 */
void list_crl_fetch_requests(bool utc)
{
	fetch_req_t *req;

	lock_crl_fetch_list("list_crl_fetch_requests");
	req = crl_fetch_reqs;

	if (req != NULL)
	{
		whack_log(RC_COMMENT, " ");
		whack_log(RC_COMMENT, "List of CRL fetch requests:");
		whack_log(RC_COMMENT, " ");
	}

	while (req != NULL)
	{
		u_char buf[BUF_LEN];

		whack_log(RC_COMMENT, "%T, trials: %d"
			, &req->installed, utc, req->trials);
		dntoa(buf, BUF_LEN, req->issuer);
		whack_log(RC_COMMENT, "       issuer:   '%s'", buf);
		if (req->authKeyID.ptr != NULL)
		{
			datatot(req->authKeyID.ptr, req->authKeyID.len, ':'
				, buf, BUF_LEN);
			whack_log(RC_COMMENT, "       authkey:   %s", buf);
		}
		if (req->authKeySerialNumber.ptr != NULL)
		{
			datatot(req->authKeySerialNumber.ptr, req->authKeySerialNumber.len, ':'
				, buf, BUF_LEN);
			whack_log(RC_COMMENT, "       aserial:   %s", buf);
		}
		list_distribution_points(req->distributionPoints);
		req = req->next;
	}
	unlock_crl_fetch_list("list_crl_fetch_requests");
}

void list_ocsp_fetch_requests(bool utc)
{
	lock_ocsp_fetch_list("list_ocsp_fetch_requests");
	list_ocsp_locations(ocsp_fetch_reqs, TRUE, utc, FALSE);
	unlock_ocsp_fetch_list("list_ocsp_fetch_requests");

}
