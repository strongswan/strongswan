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

/**
 * Implementation of pem_plugin_t.pemtroy
 */
static void destroy(private_pem_plugin_t *this)
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
	private_pem_plugin_t *this = malloc_thing(private_pem_plugin_t);

	this->public.plugin.destroy = (void(*)(plugin_t*))destroy;

	/* register private key PEM decoding builders */
	lib->creds->add_builder(lib->creds, CRED_PRIVATE_KEY, KEY_ANY,
							(builder_function_t)pem_private_key_load);
	lib->creds->add_builder(lib->creds, CRED_PRIVATE_KEY, KEY_RSA,
							(builder_function_t)pem_private_key_load);
	lib->creds->add_builder(lib->creds, CRED_PRIVATE_KEY, KEY_ECDSA,
							(builder_function_t)pem_private_key_load);
	lib->creds->add_builder(lib->creds, CRED_PRIVATE_KEY, KEY_DSA,
							(builder_function_t)pem_private_key_load);

	/* register public key PEM decoding builders */
	lib->creds->add_builder(lib->creds, CRED_PUBLIC_KEY, KEY_ANY,
							(builder_function_t)pem_public_key_load);
	lib->creds->add_builder(lib->creds, CRED_PUBLIC_KEY, KEY_RSA,
							(builder_function_t)pem_public_key_load);
	lib->creds->add_builder(lib->creds, CRED_PUBLIC_KEY, KEY_ECDSA,
							(builder_function_t)pem_public_key_load);
	lib->creds->add_builder(lib->creds, CRED_PUBLIC_KEY, KEY_DSA,
							(builder_function_t)pem_public_key_load);

	/* register certificate PEM decoding builders */
	lib->creds->add_builder(lib->creds, CRED_CERTIFICATE, CERT_ANY,
							(builder_function_t)pem_certificate_load);
	lib->creds->add_builder(lib->creds, CRED_CERTIFICATE, CERT_X509,
							(builder_function_t)pem_certificate_load);
	lib->creds->add_builder(lib->creds, CRED_CERTIFICATE, CERT_X509_CRL,
							(builder_function_t)pem_certificate_load);
	lib->creds->add_builder(lib->creds, CRED_CERTIFICATE, CERT_X509_OCSP_REQUEST,
							(builder_function_t)pem_certificate_load);
	lib->creds->add_builder(lib->creds, CRED_CERTIFICATE, CERT_X509_OCSP_RESPONSE,
							(builder_function_t)pem_certificate_load);
	lib->creds->add_builder(lib->creds, CRED_CERTIFICATE, CERT_X509_AC,
							(builder_function_t)pem_certificate_load);
	lib->creds->add_builder(lib->creds, CRED_CERTIFICATE, CERT_PKCS10_REQUEST,
							(builder_function_t)pem_certificate_load);
	lib->creds->add_builder(lib->creds, CRED_CERTIFICATE, CERT_TRUSTED_PUBKEY,
							(builder_function_t)pem_certificate_load);
	lib->creds->add_builder(lib->creds, CRED_CERTIFICATE, CERT_GPG,
							(builder_function_t)pem_certificate_load);

	/* register pluto specific certificate formats */
	lib->creds->add_builder(lib->creds, CRED_CERTIFICATE, CERT_PLUTO_CERT,
							(builder_function_t)pem_certificate_load);
	lib->creds->add_builder(lib->creds, CRED_CERTIFICATE, CERT_PLUTO_CRL,
							(builder_function_t)pem_certificate_load);

	/* register PEM encoder */
	lib->encoding->add_encoder(lib->encoding, pem_encoder_encode);

	return &this->public.plugin;
}

