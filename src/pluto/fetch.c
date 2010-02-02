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
#ifdef THREADS
#include <threading/thread.h>
#endif

#include "constants.h"
#include "defs.h"
#include "log.h"
#include "x509.h"
#include "ca.h"
#include "whack.h"
#include "ocsp.h"
#include "crl.h"
#include "fetch.h"
#include "builder.h"

fetch_req_t empty_fetch_req = {
	NULL    , /* next */
		  0 , /* trials */
    NULL    , /* issuer */
  { NULL, 0}, /* authKeyID */
	NULL      /* distributionPoints */
};

/* chained list of crl fetch requests */
static fetch_req_t *crl_fetch_reqs  = NULL;

/* chained list of ocsp fetch requests */
static ocsp_location_t *ocsp_fetch_reqs = NULL;

#ifdef THREADS
static thread_t *thread;
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
	req->distributionPoints->destroy_function(req->distributionPoints, free);
	DESTROY_IF(req->issuer);
	free(req->authKeyID.ptr);
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
static char* complete_uri(char *distPoint, const char *ldaphost)
{
	char *symbol = strchr(distPoint, ':');

	if (symbol)
	{
		int type_len = symbol - distPoint;

		if (type_len >= 4 && strncasecmp(distPoint, "ldap", 4) == 0)
		{
			char *ptr  = symbol + 1;
			int len = strlen(distPoint) - (type_len + 1);

			if (len > 2 && *ptr++ == '/' && *ptr++ == '/')
			{
				len -= 2;
				symbol = strchr(ptr, '/');

				if (symbol && symbol - ptr == 0 && ldaphost)
				{
					char uri[BUF_LEN];

					/* insert the ldaphost into the uri */
					snprintf(uri, BUF_LEN, "%.*s%s%.*s", strlen(distPoint)-len,
							 distPoint, ldaphost, len, symbol);
					return strdup(uri);
				}
			}
		}
	}

	/* default action:  copy distributionPoint without change */
	return strdup(distPoint);
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
		enumerator_t *enumerator;
		char *point;
		bool valid_crl = FALSE;
		const char *ldaphost;
		ca_info_t *ca;

		lock_ca_info_list("fetch_crls");

		ca = get_ca_info(req->issuer, req->authKeyID);
		ldaphost = (ca == NULL)? NULL : ca->ldaphost;

		enumerator = req->distributionPoints->create_enumerator(req->distributionPoints);
		while (enumerator->enumerate(enumerator, &point))
		{
			x509crl_t *crl;
			char *uri;

			uri = complete_uri(point, ldaphost);
			crl = fetch_crl(uri);
			free(uri);

			if (crl)
			{
				if (insert_crl(crl, point, cache_crls))
				{
					DBG(DBG_CONTROL,
						DBG_log("we have a valid crl")
					)
					valid_crl = TRUE;
					break;
				}
			}
		}
		enumerator->destroy(enumerator);
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
	chunk_t request = build_ocsp_request(location);
	chunk_t response = chunk_empty;

	DBG1("  requesting ocsp status from '%s' ...", location->uri);
	if (lib->fetcher->fetch(lib->fetcher, location->uri, &response,
							FETCH_REQUEST_DATA, request,
							FETCH_REQUEST_TYPE, "application/ocsp-request",
							FETCH_END) == SUCCESS)
	{
		parse_ocsp(location, response);
	}
	else
	{
		DBG1("ocsp request to %s failed", location->uri);
	}

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

	/* the fetching thread is only cancellable while waiting for new events */
	thread_cancelability(FALSE);

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

		thread_cancelability(TRUE);
		status = pthread_cond_timedwait(&fetch_wake_cond, &fetch_wake_mutex
										, &wait_interval);
		thread_cancelability(FALSE);

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
	return NULL;
}
#endif /* THREADS*/

/**
 * Initializes curl and starts the fetching thread
 */
void fetch_initialize(void)
{
	if (crl_check_interval > 0)
	{
#ifdef THREADS
		thread = thread_create((thread_main_t)fetch_thread, NULL);
		if (thread == NULL)
		{
			plog("fetching thread could not be started");
		}
#else   /* !THREADS */
		plog("warning: not compiled with pthread support");
#endif  /* !THREADS */
	}
}

/**
 * Terminates the fetching thread
 */
void fetch_finalize(void)
{
	if (crl_check_interval > 0)
	{
#ifdef THREADS
		if (thread)
		{
			thread->cancel(thread);
			thread->join(thread);
		}
#endif
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
 * Add an additional distribution point
 */
void add_distribution_point(linked_list_t *points, char *new_point)
{
	char *point;
	bool add = TRUE;
	enumerator_t *enumerator;

	if (new_point == NULL || *new_point == '\0')
	{
		return;
	}

	enumerator = points->create_enumerator(points);
	while (enumerator->enumerate(enumerator, &point))
	{
		if (streq(point, new_point))
		{
			add = FALSE;
			break;
		}
	}
	enumerator->destroy(enumerator);

	if (add)
	{
		points->insert_last(points, strdup(new_point));
	}
}

/**
 * Add additional distribution points
 */
void add_distribution_points(linked_list_t *points, linked_list_t *new_points)
{
	char *new_point;
	enumerator_t *enumerator;

	enumerator = new_points->create_enumerator(new_points);
	while (enumerator->enumerate(enumerator, &new_point))
	{
		bool add = TRUE;
		char *point;
		enumerator_t *enumerator;

		enumerator = points->create_enumerator(points);
		while (enumerator->enumerate(enumerator, &point))
		{
			if (streq(point, new_point))
			{
				add = FALSE;
				break;
			}
		}
		enumerator->destroy(enumerator);

		if (add)
		{
			points->insert_last(points, strdup(new_point));
		}
	}
	enumerator->destroy(enumerator);
}

fetch_req_t* build_crl_fetch_request(identification_t *issuer,
									 chunk_t authKeyID,
									 linked_list_t *distributionPoints)
{
	char *point;
	enumerator_t *enumerator;
	fetch_req_t *req = malloc_thing(fetch_req_t);

	memset(req, 0, sizeof(fetch_req_t));
	req->distributionPoints = linked_list_create();

	/* clone fields */
	req->issuer = issuer->clone(issuer);
	req->authKeyID = chunk_clone(authKeyID);

	/* copy distribution points */
	enumerator = distributionPoints->create_enumerator(distributionPoints);
	while (enumerator->enumerate(enumerator, &point))
	{
		req->distributionPoints->insert_last(req->distributionPoints,
											 strdup(point));
	}
	enumerator->destroy(enumerator);

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
		if (req->authKeyID.ptr ? same_keyid(req->authKeyID, r->authKeyID) :
			req->issuer->equals(req->issuer, r->issuer))
		{
			/* there is already a fetch request */
			DBG(DBG_CONTROL,
				DBG_log("crl fetch request already exists")
			)

			/* there might be new distribution points */
			add_distribution_points(r->distributionPoints,
									req->distributionPoints);

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
void list_distribution_points(linked_list_t *distributionPoints)
{
	char *point;
	bool first_point = TRUE;
	enumerator_t *enumerator;

	enumerator = distributionPoints->create_enumerator(distributionPoints);
	while (enumerator->enumerate(enumerator, &point))
	{
		whack_log(RC_COMMENT, "  %s '%s'",
				 (first_point)? "distPts: " : "         ", point);
		first_point = FALSE;
	}
	enumerator->destroy(enumerator);
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
		whack_log(RC_COMMENT, "List of CRL Fetch Requests:");
	}

	while (req != NULL)
	{
		whack_log(RC_COMMENT, " ");
		whack_log(RC_COMMENT, "  trials:    %d", req->trials);
		whack_log(RC_COMMENT, "  issuer:   \"%Y\"", req->issuer);
		if (req->authKeyID.ptr)
		{
			whack_log(RC_COMMENT, "  authkey:   %#B", &req->authKeyID);
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
