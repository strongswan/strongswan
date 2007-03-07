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
#endif

#include <library.h>
#include <debug.h>

#include "fetcher.h"

typedef struct private_fetcher_t private_fetcher_t;

/**
 * @brief Private Data of a h object.
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
	
};

/**
 * writes data into a dynamically resizeable chunk_t
 * needed for libcurl responses
 */
size_t curl_write_buffer(void *ptr, size_t size, size_t nmemb, void *data)
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
 * Implements fetcher_t.get
 */
static chunk_t get(private_fetcher_t *this, const char *uri)
{
	return chunk_empty;
}

/**
 * Implements fetcher_t.post
 */
static chunk_t post(private_fetcher_t *this, const char *request_type, chunk_t request)
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

		DBG2("sending http post request to '%s'", this->uri);
		res = curl_easy_perform(this->curl);

		if (res == CURLE_OK)
		{
	    	DBG2("received valid http response");
			response = chunk_clone(curl_response);
		}
		else
		{
	    	DBG1("http post request to '%s' using libcurl failed: %s",
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
 * Implements fetcher_t.destroy
 */
static void destroy(private_fetcher_t *this)
{
	curl_easy_cleanup(this->curl);
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
    this->curl = curl_easy_init();
	if (this->curl == NULL)
	{
		DBG1("curl_easy_init_failed()");
	}
#endif /* LIBCURL */

	/* public functions */
	this->public.get = (chunk_t (*) (fetcher_t*,const char*))get;
	this->public.post = (chunk_t (*) (fetcher_t*,const char*,chunk_t))post;
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

	/* init libcurl */
	DBG1("initializing libcurl");
	res = curl_global_init(CURL_GLOBAL_NOTHING);
	if (res != CURLE_OK)
	{
		DBG1("libcurl could not be initialized: %s", curl_easy_strerror(res));
    }
#endif /* LIBCURL */
}
