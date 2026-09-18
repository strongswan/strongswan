/*
 * Copyright (C) 2026 Arthur SC Chan
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

#include <library.h>
#include <credentials/containers/container.h>
#include <credentials/containers/pkcs12.h>
#include <credentials/sets/mem_cred.h>
#include <credentials/keys/shared_key.h>
#include <utils/debug.h>

/* Passphrase for SafeBag PKCS#12 integrity/privacy mode */
static chunk_t fuzz_passphrase = chunk_from_chars('f','u','z','z');

static mem_cred_t *creds;

int LLVMFuzzerInitialize(int *argc, char ***argv)
{
	dbg_default_set_level(-1);
	library_init(NULL, "fuzz_pkcs12");
	if (!lib->plugins->load(lib->plugins, PLUGINS))
	{
		return 1;
	}

	creds = mem_cred_create();
	lib->credmgr->add_set(lib->credmgr, &creds->set);
	creds->add_shared(creds,
			shared_key_create(SHARED_PRIVATE_KEY_PASS,
							  chunk_clone(fuzz_passphrase)), NULL);
	return 0;
}

int LLVMFuzzerTestOneInput(const uint8_t *buf, size_t len)
{
	container_t *container;
	pkcs12_t *pkcs12;
	enumerator_t *enumerator;
	certificate_t *cert;
	private_key_t *key;
	chunk_t chunk;

	chunk = chunk_create((u_char*)buf, len);
	container = lib->creds->create(lib->creds, CRED_CONTAINER, CONTAINER_PKCS12,
								   BUILD_BLOB, chunk, BUILD_END);
	if (container)
	{
		container->get_type(container);

		pkcs12 = (pkcs12_t*)container;
		enumerator = pkcs12->create_cert_enumerator(pkcs12);
		while (enumerator->enumerate(enumerator, &cert)) { }
		enumerator->destroy(enumerator);

		enumerator = pkcs12->create_key_enumerator(pkcs12);
		while (enumerator->enumerate(enumerator, &key)) { }
		enumerator->destroy(enumerator);

		container->destroy(container);
	}
	return 0;
}
