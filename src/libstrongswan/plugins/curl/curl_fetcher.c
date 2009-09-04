/*
 * Copyright (C) 2008 Martin Willi
 * Copyright (C) 2007 Andreas Steffen
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

#include <curl/curl.h>

#include <library.h>
#include <debug.h>

#include "curl_fetcher.h"

#define DEFAULT_TIMEOUT 10

typedef struct private_curl_fetcher_t private_curl_fetcher_t;

/**
 * private data of a curl_fetcher_t object.
 */
struct private_curl_fetcher_t {
	/**
	 * Public data
	 */
	curl_fetcher_t public;

	/**
	 * CURL handle
	 */
	CURL* curl;

	/**
     * Optional HTTP headers
	 */
	struct curl_slist *headers;
};

/**
 * writes data into a dynamically resizeable chunk_t
 */
static size_t append(void *ptr, size_t size, size_t nmemb, chunk_t *data)
{
	size_t realsize = size * nmemb;

	data->ptr = (u_char*)realloc(data->ptr, data->len + realsize);
	if (data->ptr)
	{
		memcpy(&data->ptr[data->len], ptr, realsize);
		data->len += realsize;
	}
	return realsize;
}

/**
 * Implements fetcher_t.fetch.
 */
static status_t fetch(private_curl_fetcher_t *this, char *uri, chunk_t *result)
{
	char error[CURL_ERROR_SIZE];
	status_t status;

	*result = chunk_empty;

	if (curl_easy_setopt(this->curl, CURLOPT_URL, uri) != CURLE_OK)
	{	/* URL type not supported by curl */
		return NOT_SUPPORTED;
	}
	curl_easy_setopt(this->curl, CURLOPT_ERRORBUFFER, error);
	curl_easy_setopt(this->curl, CURLOPT_FAILONERROR, TRUE);
	curl_easy_setopt(this->curl, CURLOPT_NOSIGNAL, TRUE);
	curl_easy_setopt(this->curl, CURLOPT_CONNECTTIMEOUT, DEFAULT_TIMEOUT);
	curl_easy_setopt(this->curl, CURLOPT_WRITEFUNCTION, (void*)append);
	curl_easy_setopt(this->curl, CURLOPT_WRITEDATA, (void*)result);
	if (this->headers)
	{
		curl_easy_setopt(this->curl, CURLOPT_HTTPHEADER, this->headers);
	}

	DBG2("  sending http request to '%s'...", uri);
	switch (curl_easy_perform(this->curl))
	{
		case CURLE_UNSUPPORTED_PROTOCOL:
			status = NOT_SUPPORTED;
			break;
		case CURLE_OK:
			status = SUCCESS;
			break;
		default:
			DBG1("libcurl http request failed: %s", error);
			status = FAILED;
			break;
	}
	return status;
}

/**
 * Implementation of fetcher_t.set_option.
 */
static bool set_option(private_curl_fetcher_t *this, fetcher_option_t option, ...)
{
	va_list args;

	va_start(args, option);
	switch (option)
	{
		case FETCH_REQUEST_DATA:
		{
			chunk_t data = va_arg(args, chunk_t);

			curl_easy_setopt(this->curl, CURLOPT_POSTFIELDS, (char*)data.ptr);
			curl_easy_setopt(this->curl, CURLOPT_POSTFIELDSIZE, data.len);
			return TRUE;
		}
		case FETCH_REQUEST_TYPE:
		{
			char header[BUF_LEN];
			char *request_type = va_arg(args, char*);

			snprintf(header, BUF_LEN, "Content-Type: %s", request_type);
			this->headers = curl_slist_append(this->headers, header);
			return TRUE;
		}
		case FETCH_REQUEST_HEADER:
		{
			char *header = va_arg(args, char*);

			this->headers = curl_slist_append(this->headers, header);
			return TRUE;
		}
		case FETCH_HTTP_VERSION_1_0:
		{
			curl_easy_setopt(this->curl, CURLOPT_HTTP_VERSION,
							 CURL_HTTP_VERSION_1_0);
			return TRUE;
		}
		case FETCH_TIMEOUT:
		{
			curl_easy_setopt(this->curl, CURLOPT_CONNECTTIMEOUT,
							 va_arg(args, u_int));
			return TRUE;
		}
		default:
			return FALSE;
	}
}

/**
 * Implements fetcher_t.destroy
 */
static void destroy(private_curl_fetcher_t *this)
{
	curl_slist_free_all(this->headers);
	curl_easy_cleanup(this->curl);
	free(this);
}

/*
 * Described in header.
 */
curl_fetcher_t *curl_fetcher_create()
{
	private_curl_fetcher_t *this = malloc_thing(private_curl_fetcher_t);

	this->curl = curl_easy_init();
	if (this->curl == NULL)
	{
		free(this);
		return NULL;
	}
	this->headers = NULL;

	this->public.interface.fetch = (status_t(*)(fetcher_t*,char*,chunk_t*))fetch;
	this->public.interface.set_option = (bool(*)(fetcher_t*, fetcher_option_t option, ...))set_option;
	this->public.interface.destroy = (void (*)(fetcher_t*))destroy;

	return &this->public;
}

