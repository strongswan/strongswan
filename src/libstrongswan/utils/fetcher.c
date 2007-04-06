/**
 * @file fetcher.c
 * 
 * @brief Implementation of fetcher_t.
 * 
 */

/*
 * Copyright (C) 2007 Andreas Steffen
 * Hochschule fuer Technik Rapperswil
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the
 * Free Software Foundation; either version 2 of the License, or (at your
 * option) any later version.  See <fetcher://www.fsf.org/copyleft/gpl.txt>.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
 * or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License
 * for more details.
 */

#ifdef LIBCURL
#include <curl/curl.h>
#endif /* LIBCURL */

#ifdef LIBLDAP
#include <ldap.h>
#endif /* LIBLDAP */

#include <library.h>
#include <debug.h>

#include "fetcher.h"

typedef struct private_fetcher_t private_fetcher_t;

/**
 * @brief Private Data of a fetcher_t object.
 */
struct private_fetcher_t {
	/**
	 * Public data
	 */
	fetcher_t public;

	/**
	 * URI of the information source
	 */
	const char *uri;

#ifdef LIBCURL
	/**
	 * we use libcurl from http://curl.haxx.se/ as a fetcher
	 */
	CURL* curl;
#endif /* LIBCURL */
	
#ifdef LIBLDAP
	/**
	 * we use libldap from http://www.openssl.org/ as a fetcher
	 */
	LDAP *ldap;
	LDAPURLDesc *lurl;
#endif /* LIBLDAP */
};

/**
 * writes data into a dynamically resizeable chunk_t
 * needed for libcurl responses
 */
static size_t curl_write_buffer(void *ptr, size_t size, size_t nmemb, void *data)
{
    size_t realsize = size * nmemb;
    chunk_t *mem = (chunk_t*)data;

    mem->ptr = (u_char *)realloc(mem->ptr, mem->len + realsize);
    if (mem->ptr) {
	memcpy(&(mem->ptr[mem->len]), ptr, realsize);
	mem->len += realsize;
    }
    return realsize;
}

/**
 * Implements fetcher_t.get for http[s] and file URIs
 */
static chunk_t curl_get(private_fetcher_t *this)
{
	chunk_t response = chunk_empty;

#ifdef LIBCURL
	if (this->curl)
	{
		CURLcode res;
		chunk_t curl_response = chunk_empty;
		char curl_error_buffer[CURL_ERROR_SIZE];

		curl_easy_setopt(this->curl, CURLOPT_URL, this->uri);
		curl_easy_setopt(this->curl, CURLOPT_WRITEFUNCTION, curl_write_buffer);
		curl_easy_setopt(this->curl, CURLOPT_WRITEDATA, (void *)&curl_response);
		curl_easy_setopt(this->curl, CURLOPT_ERRORBUFFER, &curl_error_buffer);
		curl_easy_setopt(this->curl, CURLOPT_FAILONERROR, TRUE);
		curl_easy_setopt(this->curl, CURLOPT_CONNECTTIMEOUT, FETCHER_TIMEOUT);
		curl_easy_setopt(this->curl, CURLOPT_NOSIGNAL, TRUE);

		DBG1("sending curl request to '%s'...", this->uri);
		res = curl_easy_perform(this->curl);

		if (res == CURLE_OK)
		{
	    	DBG1("received valid curl response");
			response = chunk_clone(curl_response);
		}
		else
		{
	    	DBG1("curl request to '%s' failed: %s",
				  this->uri, curl_error_buffer);
		}
		curl_free(curl_response.ptr);
	}
#else
	DBG1("warning: libcurl fetching not compiled in");
#endif  /* LIBCURL */
	return response;
}

/**
 * Implements fetcher_t.post.
 */
static chunk_t http_post(private_fetcher_t *this, const char *request_type, chunk_t request)
{
	chunk_t response = chunk_empty;

#ifdef LIBCURL
	if (this->curl)
	{
		CURLcode res;
		struct curl_slist *headers = NULL;
		chunk_t curl_response = chunk_empty;
		char curl_error_buffer[CURL_ERROR_SIZE];
		char content_type[BUF_LEN];

		/* set content type header */
		snprintf(content_type, BUF_LEN, "Content-Type: %s", request_type);
		headers = curl_slist_append(headers, content_type);

		/* set options */
		curl_easy_setopt(this->curl, CURLOPT_HTTPHEADER, headers);
		curl_easy_setopt(this->curl, CURLOPT_URL, this->uri);
		curl_easy_setopt(this->curl, CURLOPT_WRITEFUNCTION, curl_write_buffer);
		curl_easy_setopt(this->curl, CURLOPT_WRITEDATA, (void *)&curl_response);
		curl_easy_setopt(this->curl, CURLOPT_POSTFIELDS, request.ptr);
		curl_easy_setopt(this->curl, CURLOPT_POSTFIELDSIZE, request.len);
		curl_easy_setopt(this->curl, CURLOPT_ERRORBUFFER, &curl_error_buffer);
		curl_easy_setopt(this->curl, CURLOPT_FAILONERROR, TRUE);
		curl_easy_setopt(this->curl, CURLOPT_CONNECTTIMEOUT, FETCHER_TIMEOUT);
		curl_easy_setopt(this->curl, CURLOPT_NOSIGNAL, TRUE);

		DBG1("sending http post request to '%s'...", this->uri);
		res = curl_easy_perform(this->curl);

		if (res == CURLE_OK)
		{
	    	DBG1("received valid http response");
			response = chunk_clone(curl_response);
		}
		else
		{
	    	DBG1("http post request to '%s' using libcurl failed: %s",
				  this->uri, curl_error_buffer);
		}
		curl_slist_free_all(headers);
		curl_free(curl_response.ptr);
	}
#else
	DBG1("warning: libcurl fetching not compiled in");
#endif  /* LIBCURL */
	return response;
}

#ifdef LIBLDAP
/**
 * parses the result returned by an ldap query
 */
static chunk_t ldap_parse(LDAP *ldap, LDAPMessage *result)
{
	chunk_t response = chunk_empty;

	LDAPMessage *entry = ldap_first_entry(ldap, result);
	if (entry != NULL)
	{
		BerElement *ber = NULL;
		char *attr;

		attr = ldap_first_attribute(ldap, entry, &ber);

		if (attr != NULL)
		{
			struct berval **values = ldap_get_values_len(ldap, entry, attr);

			if (values != NULL)
			{
				if (values[0] != NULL)
				{
					response.len = values[0]->bv_len;
					response.ptr = malloc(response.len);
					memcpy(response.ptr, values[0]->bv_val, response.len);
					if (values[1] != NULL)
					{
						DBG1("ldap: more than one value was fetched from LDAP URL");
					}
				}
				else
				{
					DBG1("ldap: no values in attribute");
				}
				ldap_value_free_len(values);
			}
			else
			{
				DBG1("ldap: %s", ldap_err2string(ldap_result2error(ldap, entry, 0)));
			}
			ldap_memfree(attr);
		}
		else
		{
			DBG1("ldap: %s", ldap_err2string(ldap_result2error(ldap, entry, 0)));
		}
		ber_free(ber, 0);
	}
	else
	{
		DBG1("ldap: %s", ldap_err2string(ldap_result2error(ldap, result, 0)));
	}
	return response;
}
#endif  /* LIBLDAP */

/**
 * fetches a binary blob from an ldap url
 */
static chunk_t ldap_get(private_fetcher_t *this)
{
	chunk_t response = chunk_empty;

#ifdef LIBLDAP
	if (this->ldap)
	{
		int rc;
		int ldap_version = LDAP_VERSION3;

		struct timeval timeout;

		timeout.tv_sec  = FETCHER_TIMEOUT;
		timeout.tv_usec = 0;

		ldap_set_option(this->ldap, LDAP_OPT_PROTOCOL_VERSION, &ldap_version);
		ldap_set_option(this->ldap, LDAP_OPT_NETWORK_TIMEOUT, &timeout);

		DBG1("sending ldap request to '%s'...", this->uri);

		rc = ldap_simple_bind_s(this->ldap, NULL, NULL);
		if (rc == LDAP_SUCCESS)
		{
			LDAPMessage *result;

			timeout.tv_sec = FETCHER_TIMEOUT;
			timeout.tv_usec = 0;

			rc = ldap_search_st(this->ldap, this->lurl->lud_dn,
											this->lurl->lud_scope,
											this->lurl->lud_filter,
											this->lurl->lud_attrs,
											0, &timeout, &result);

			if (rc == LDAP_SUCCESS)
			{
				response = ldap_parse(this->ldap, result);
				if (response.ptr)
				{
	    			DBG1("received valid ldap response");
				}
				ldap_msgfree(result);
			}
			else
			{
				DBG1("ldap: %s", ldap_err2string(rc));
			}
		}
		else
		{
			DBG1("ldap: %s", ldap_err2string(rc));
		}
		ldap_unbind_s(this->ldap);
	}
#else   /* !LIBLDAP */
	DBG1("warning: libldap fetching not compiled in");
#endif  /* !LIBLDAP */
    return response;
}

/**
 * Implements fetcher_t.destroy
 */
static void destroy(private_fetcher_t *this)
{
#ifdef LIBCURL
	if (this->curl)
	{
		curl_easy_cleanup(this->curl);
	}
#endif /* LIBCURL */

#ifdef LIBLDAP
	if (this->lurl)
	{
		ldap_free_urldesc(this->lurl);
	}
#endif /* LIBLDAP */

	free(this);
}

/*
 * Described in header.
 */
fetcher_t *fetcher_create(const char *uri)
{
	private_fetcher_t *this = malloc_thing(private_fetcher_t);
	
	/* initialize */
	this->uri = uri;

#ifdef LIBCURL
	this->curl = NULL;
#endif /* LIBCURL */

#ifdef LIBLDAP
		this->lurl = NULL;
		this->ldap = NULL;
#endif /* LIBLDAP */

	if (strlen(uri) >= 4 && strncasecmp(uri, "ldap", 4) == 0)
	{
#ifdef LIBLDAP
		int rc = ldap_url_parse(uri, &this->lurl);

		if (rc == LDAP_SUCCESS)
		{
			this->ldap = ldap_init(this->lurl->lud_host,
								   this->lurl->lud_port);
		}
		else
		{
			DBG1("ldap: %s", ldap_err2string(rc));
			this->ldap = NULL;
		}
#endif /* LIBLDAP */
		this->public.get = (chunk_t (*) (fetcher_t*))ldap_get;
	}
	else
	{
#ifdef LIBCURL
		this->curl = curl_easy_init();
		if (this->curl == NULL)
		{
			DBG1("curl_easy_init_failed()");
		}
#endif /* LIBCURL */
		this->public.get = (chunk_t (*) (fetcher_t*))curl_get;
	}

	/* public functions */
	this->public.post = (chunk_t (*) (fetcher_t*,const char*,chunk_t))http_post;
	this->public.destroy = (void (*) (fetcher_t*))destroy;

	return &this->public;
}

/**
 * Described in header.
 */
void fetcher_initialize(void)
{
#ifdef LIBCURL
	CURLcode res;

	/* initialize libcurl */
	DBG1("initializing libcurl");
	res = curl_global_init(CURL_GLOBAL_NOTHING);
	if (res != CURLE_OK)
	{
		DBG1("libcurl could not be initialized: %s", curl_easy_strerror(res));
    }
#endif /* LIBCURL */
}

/**
 * Described in header.
 */
void fetcher_finalize(void)
{
#ifdef LIBCURL
	/* finalize libcurl */
	DBG1("finalizing libcurl");
	curl_global_cleanup();
#endif /* LIBCURL */
}

