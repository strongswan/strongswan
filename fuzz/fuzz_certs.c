/*
 * Copyright (C) 2017 Tobias Brunner
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
#include <utils/debug.h>

int LLVMFuzzerInitialize(int *argc, char ***argv)
{
	dbg_default_set_level(-1);
	library_init(NULL, "fuzz_certs");
	if (!lib->plugins->load(lib->plugins, PLUGINS))
	{
		fprintf(stderr, "failed to load plugins\n");
		exit(1);
	}
	atexit(library_deinit);
	return 0;
}

int LLVMFuzzerTestOneInput(const uint8_t *buf, size_t len)
{
	certificate_t *cert;
	chunk_t chunk;

	chunk = chunk_create((u_char*)buf, len);
	cert = lib->creds->create(lib->creds, CRED_CERTIFICATE, CERT_X509,
							  BUILD_BLOB, chunk, BUILD_END);
	DESTROY_IF(cert);
	return 0;
}
