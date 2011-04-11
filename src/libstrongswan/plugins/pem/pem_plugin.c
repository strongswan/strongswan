/*
 * Copyright (C) 2009 Martin Willi
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

#include "pem_plugin.h"

#include <library.h>

#include "pem_builder.h"
#include "pem_encoder.h"

typedef struct private_pem_plugin_t private_pem_plugin_t;

/**
 * private data of pem_plugin
 */
struct private_pem_plugin_t {

	/**
	 * public functions
	 */
	pem_plugin_t public;
};

METHOD(plugin_t, get_name, char*,
	private_pem_plugin_t *this)
{
	return "pem";
}

METHOD(plugin_t, destroy, void,
	private_pem_plugin_t *this)
{
	lib->creds->remove_builder(lib->creds,
							   (builder_function_t)pem_private_key_load);
	lib->creds->remove_builder(lib->creds,
							   (builder_function_t)pem_public_key_load);
	lib->creds->remove_builder(lib->creds,
							   (builder_function_t)pem_certificate_load);
	free(this);
}

/*
 * see header file
 */
plugin_t *pem_plugin_create()
{
	private_pem_plugin_t *this;

	INIT(this,
		.public = {
			.plugin = {
				.get_name = _get_name,
				.reload = (void*)return_false,
				.destroy = _destroy,
			},
		},
	);

	/* register private key PEM decoding builders */
	lib->creds->add_builder(lib->creds, CRED_PRIVATE_KEY, KEY_ANY, FALSE,
							(builder_function_t)pem_private_key_load);
	lib->creds->add_builder(lib->creds, CRED_PRIVATE_KEY, KEY_RSA, FALSE,
							(builder_function_t)pem_private_key_load);
	lib->creds->add_builder(lib->creds, CRED_PRIVATE_KEY, KEY_ECDSA, FALSE,
							(builder_function_t)pem_private_key_load);
	lib->creds->add_builder(lib->creds, CRED_PRIVATE_KEY, KEY_DSA, FALSE,
							(builder_function_t)pem_private_key_load);

	/* register public key PEM decoding builders */
	lib->creds->add_builder(lib->creds, CRED_PUBLIC_KEY, KEY_ANY, FALSE,
							(builder_function_t)pem_public_key_load);
	lib->creds->add_builder(lib->creds, CRED_PUBLIC_KEY, KEY_RSA, FALSE,
							(builder_function_t)pem_public_key_load);
	lib->creds->add_builder(lib->creds, CRED_PUBLIC_KEY, KEY_ECDSA, FALSE,
							(builder_function_t)pem_public_key_load);
	lib->creds->add_builder(lib->creds, CRED_PUBLIC_KEY, KEY_DSA, FALSE,
							(builder_function_t)pem_public_key_load);

	/* register certificate PEM decoding builders */
	lib->creds->add_builder(lib->creds, CRED_CERTIFICATE, CERT_ANY, FALSE,
							(builder_function_t)pem_certificate_load);
	lib->creds->add_builder(lib->creds, CRED_CERTIFICATE, CERT_X509, FALSE,
							(builder_function_t)pem_certificate_load);
	lib->creds->add_builder(lib->creds, CRED_CERTIFICATE, CERT_X509_CRL, FALSE,
							(builder_function_t)pem_certificate_load);
	lib->creds->add_builder(lib->creds, CRED_CERTIFICATE, CERT_X509_OCSP_REQUEST, FALSE,
							(builder_function_t)pem_certificate_load);
	lib->creds->add_builder(lib->creds, CRED_CERTIFICATE, CERT_X509_OCSP_RESPONSE, FALSE,
							(builder_function_t)pem_certificate_load);
	lib->creds->add_builder(lib->creds, CRED_CERTIFICATE, CERT_X509_AC, FALSE,
							(builder_function_t)pem_certificate_load);
	lib->creds->add_builder(lib->creds, CRED_CERTIFICATE, CERT_PKCS10_REQUEST, FALSE,
							(builder_function_t)pem_certificate_load);
	lib->creds->add_builder(lib->creds, CRED_CERTIFICATE, CERT_TRUSTED_PUBKEY, FALSE,
							(builder_function_t)pem_certificate_load);
	lib->creds->add_builder(lib->creds, CRED_CERTIFICATE, CERT_GPG, FALSE,
							(builder_function_t)pem_certificate_load);

	/* register pluto specific certificate formats */
	lib->creds->add_builder(lib->creds, CRED_CERTIFICATE, CERT_PLUTO_CERT, FALSE,
							(builder_function_t)pem_certificate_load);
	lib->creds->add_builder(lib->creds, CRED_CERTIFICATE, CERT_PLUTO_CRL, FALSE,
							(builder_function_t)pem_certificate_load);

	/* register PEM encoder */
	lib->encoding->add_encoder(lib->encoding, pem_encoder_encode);

	return &this->public.plugin;
}

