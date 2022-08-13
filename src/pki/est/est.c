/*
 * Copyright (C) 2022 Andreas Steffen, strongSec GmbH
 *
 * Copyright (C) secunet Security Networks AG
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

#define _GNU_SOURCE
#include <stdio.h>

#include "est.h"

#define HTTP_CODE_OK         200

static const char *operations[] = {
	"cacerts",
	"simpleenroll",
	"simplereenroll",
	"fullcmc",
	"serverkeygen",
	"csrattrs"
};

static const char *request_types[] = {
	"",
	"application/pkcs10",
	"application/pkcs10",
	"application/pkcs7-mime",
	"application/pkcs10",
	""
};

/**
 * Send an EST request via HTTPS and wait for a response
 */
bool est_https_request(const char *url, est_op_t op, bool http_post,
					   chunk_t data, chunk_t *response, u_int *http_code)
{
	host_t *srcip = NULL;
	char *complete_url = NULL;
	status_t status;

	uint32_t http_timeout = lib->settings->get_time(lib->settings,
										"%s.est.http_timeout", 30, lib->ns);

	char *http_bind = lib->settings->get_str(lib->settings,
										"%s.est.http_bind", NULL, lib->ns);

	/* initialize response */
	*response = chunk_empty;
	*http_code = 0;

	/* construct complete EST URL */
	if (asprintf(&complete_url, "%s/.well-known/est/%s", url, operations[op]) == -1)
	{
		DBG1(DBG_APP, "could not allocate complete_url string");
		return FALSE;
	}
	DBG2(DBG_APP, "sending EST request to '%s'", url);

	if (http_bind)
	{
		srcip = host_create_from_string(http_bind, 0);
	}

	if (http_post)
	{
		status = lib->fetcher->fetch(lib->fetcher, complete_url, response,
									 FETCH_TIMEOUT, http_timeout,
									 FETCH_REQUEST_DATA, data,
									 FETCH_REQUEST_TYPE, request_types[op],
									 FETCH_REQUEST_HEADER, "Expect:",
									 FETCH_SOURCEIP, srcip,
									 FETCH_RESPONSE_CODE, http_code,
									 FETCH_END);
	}
	else /* HTTP_GET */
	{
		status = lib->fetcher->fetch(lib->fetcher, complete_url, response,
									 FETCH_TIMEOUT, http_timeout,
									 FETCH_SOURCEIP, srcip,
									 FETCH_RESPONSE_CODE, http_code,
									 FETCH_END);
	}
	DESTROY_IF(srcip);
	free(complete_url);

	if (status != SUCCESS)
	{
		return FALSE;
	}

	if (*http_code == HTTP_CODE_OK)
	{
		chunk_t base64_response = *response;

		*response = chunk_from_base64(base64_response, NULL);
		chunk_free(&base64_response);
	}

	return TRUE;
}

