/*
 * Copyright (C) 2008-2009 Martin Willi
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

#include "x509_plugin.h"

#include <library.h>
#include "x509_cert.h"
#include "x509_ac.h"
#include "x509_crl.h"
#include "x509_ocsp_request.h"
#include "x509_ocsp_response.h"
#include "x509_pkcs10.h"

typedef struct private_x509_plugin_t private_x509_plugin_t;

/**
 * private data of x509_plugin
 */
struct private_x509_plugin_t {

	/**
	 * public functions
	 */
	x509_plugin_t public;
};

METHOD(plugin_t, get_name, char*,
	private_x509_plugin_t *this)
{
	return "x509";
}

METHOD(plugin_t, destroy, void,
	private_x509_plugin_t *this)
{
	lib->creds->remove_builder(lib->creds,
							   (builder_function_t)x509_cert_gen);
	lib->creds->remove_builder(lib->creds,
							   (builder_function_t)x509_cert_load);
	lib->creds->remove_builder(lib->creds,
							   (builder_function_t)x509_ac_gen);
	lib->creds->remove_builder(lib->creds,
							   (builder_function_t)x509_ac_load);
	lib->creds->remove_builder(lib->creds,
							   (builder_function_t)x509_crl_load);
	lib->creds->remove_builder(lib->creds,
							   (builder_function_t)x509_crl_gen);
	lib->creds->remove_builder(lib->creds,
							   (builder_function_t)x509_ocsp_request_gen);
	lib->creds->remove_builder(lib->creds,
							   (builder_function_t)x509_ocsp_response_load);
	lib->creds->remove_builder(lib->creds,
							   (builder_function_t)x509_pkcs10_gen);
	lib->creds->remove_builder(lib->creds,
							   (builder_function_t)x509_pkcs10_load);
	free(this);
}

/*
 * see header file
 */
plugin_t *x509_plugin_create()
{
	private_x509_plugin_t *this;

	INIT(this,
		.public = {
			.plugin = {
				.get_name = _get_name,
				.reload = (void*)return_false,
				.destroy = _destroy,
			},
		},
	);

	lib->creds->add_builder(lib->creds, CRED_CERTIFICATE, CERT_X509, FALSE,
							(builder_function_t)x509_cert_gen);
	lib->creds->add_builder(lib->creds, CRED_CERTIFICATE, CERT_X509, TRUE,
							(builder_function_t)x509_cert_load);
	lib->creds->add_builder(lib->creds, CRED_CERTIFICATE, CERT_X509_AC, FALSE,
							(builder_function_t)x509_ac_gen);
	lib->creds->add_builder(lib->creds, CRED_CERTIFICATE, CERT_X509_AC, TRUE,
							(builder_function_t)x509_ac_load);
	lib->creds->add_builder(lib->creds, CRED_CERTIFICATE, CERT_X509_CRL, TRUE,
							(builder_function_t)x509_crl_load);
	lib->creds->add_builder(lib->creds, CRED_CERTIFICATE, CERT_X509_CRL, FALSE,
							(builder_function_t)x509_crl_gen);
	lib->creds->add_builder(lib->creds, CRED_CERTIFICATE, CERT_X509_OCSP_REQUEST, FALSE,
							(builder_function_t)x509_ocsp_request_gen);
	lib->creds->add_builder(lib->creds, CRED_CERTIFICATE, CERT_X509_OCSP_RESPONSE, TRUE,
							(builder_function_t)x509_ocsp_response_load);
	lib->creds->add_builder(lib->creds, CRED_CERTIFICATE, CERT_PKCS10_REQUEST, FALSE,
							(builder_function_t)x509_pkcs10_gen);
	lib->creds->add_builder(lib->creds, CRED_CERTIFICATE, CERT_PKCS10_REQUEST, TRUE,
							(builder_function_t)x509_pkcs10_load);

	return &this->public.plugin;
}

