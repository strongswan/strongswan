/*
 * Copyright (C) 2025 Martin Willi
 * Copyright (C) 2015-2018 Tobias Brunner
 * Copyright (C) 2009-2022 Andreas Steffen
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

#include "revocation_fetcher.h"

#include <utils/debug.h>
#include <credentials/certificates/crl.h>
#include <credentials/certificates/ocsp_request.h>
#include <credentials/certificates/ocsp_response.h>

typedef struct private_revocation_fetcher_t private_revocation_fetcher_t;

/**
 * Private data of an revocation_fetcher_t object.
 */
struct private_revocation_fetcher_t {

	/**
	 * Public revocation_fetcher_t interface.
	 */
	revocation_fetcher_t public;
};

METHOD(revocation_fetcher_t, fetch_crl, certificate_t *,
	private_revocation_fetcher_t *this, char *url, u_int timeout)
{
	certificate_t *crl;
	chunk_t chunk = chunk_empty;

	DBG1(DBG_CFG, "  fetching crl from '%s' ...", url);
	if (lib->fetcher->fetch(lib->fetcher, url, &chunk,
							FETCH_TIMEOUT, timeout,
							FETCH_END) != SUCCESS)
	{
		DBG1(DBG_CFG, "crl fetching failed");
		chunk_free(&chunk);
		return NULL;
	}
	crl = lib->creds->create(lib->creds, CRED_CERTIFICATE, CERT_X509_CRL,
							 BUILD_BLOB_PEM, chunk, BUILD_END);
	chunk_free(&chunk);
	if (!crl)
	{
		DBG1(DBG_CFG, "crl fetched successfully but parsing failed");
		return NULL;
	}
	return crl;
}

METHOD(revocation_fetcher_t, fetch_ocsp, certificate_t*,
	private_revocation_fetcher_t *this, char *url,
    certificate_t *subject, certificate_t *issuer, u_int timeout)
{
	certificate_t *request, *response;
	ocsp_request_t *ocsp_request;
	ocsp_response_t *ocsp_response;
	chunk_t send, receive = chunk_empty;

	/* TODO: requestor name, signature */
	request = lib->creds->create(lib->creds,
						CRED_CERTIFICATE, CERT_X509_OCSP_REQUEST,
						BUILD_CA_CERT, issuer,
						BUILD_CERT, subject, BUILD_END);
	if (!request)
	{
		DBG1(DBG_CFG, "generating ocsp request failed");
		return NULL;
	}

	if (!request->get_encoding(request, CERT_ASN1_DER, &send))
	{
		DBG1(DBG_CFG, "encoding ocsp request failed");
		request->destroy(request);
		return NULL;
	}

	DBG1(DBG_CFG, "  requesting ocsp status from '%s' ...", url);
	if (lib->fetcher->fetch(lib->fetcher, url, &receive,
							FETCH_REQUEST_DATA, send,
							FETCH_REQUEST_TYPE, "application/ocsp-request",
							FETCH_TIMEOUT, timeout,
							FETCH_END) != SUCCESS)
	{
		DBG1(DBG_CFG, "ocsp request to %s failed", url);
		request->destroy(request);
		chunk_free(&receive);
		chunk_free(&send);
		return NULL;
	}
	chunk_free(&send);

	response = lib->creds->create(lib->creds,
								  CRED_CERTIFICATE, CERT_X509_OCSP_RESPONSE,
								  BUILD_BLOB_ASN1_DER, receive, BUILD_END);
	chunk_free(&receive);
	if (!response)
	{
		DBG1(DBG_CFG, "parsing ocsp response failed");
		request->destroy(request);
		return NULL;
	}
	ocsp_response = (ocsp_response_t*)response;
	if (ocsp_response->get_ocsp_status(ocsp_response) != OCSP_SUCCESSFUL)
	{
		response->destroy(response);
		request->destroy(request);
		return NULL;
	}
	ocsp_request = (ocsp_request_t*)request;
	if (ocsp_response->get_nonce(ocsp_response).len &&
		!chunk_equals_const(ocsp_request->get_nonce(ocsp_request),
							ocsp_response->get_nonce(ocsp_response)))
	{
		DBG1(DBG_CFG, "nonce in ocsp response doesn't match");
		request->destroy(request);
		return NULL;
	}
	request->destroy(request);
	return response;
}

METHOD(revocation_fetcher_t, destroy, void,
	private_revocation_fetcher_t *this)
{
	free(this);
}

/**
 * See header
 */
revocation_fetcher_t *revocation_fetcher_create()
{
	private_revocation_fetcher_t *this;

	INIT(this,
		.public = {
			.fetch_crl = _fetch_crl,
			.fetch_ocsp = _fetch_ocsp,
			.destroy = _destroy,
		},
	);

	return &this->public;
}
