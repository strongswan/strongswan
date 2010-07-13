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

#include "command.h"
#include "pki.h"

#include <debug.h>

/**
 * Convert a form string to a encoding type
 */
bool get_form(char *form, cred_encoding_type_t *enc, credential_type_t type)
{
	if (streq(form, "der"))
	{
		switch (type)
		{
			case CRED_CERTIFICATE:
				*enc = CERT_ASN1_DER;
				return TRUE;
			case CRED_PRIVATE_KEY:
				*enc = PRIVKEY_ASN1_DER;
				return TRUE;
			case CRED_PUBLIC_KEY:
				/* der encoded keys usually contain the complete
				 * SubjectPublicKeyInfo */
				*enc = PUBKEY_SPKI_ASN1_DER;
				return TRUE;
			default:
				return FALSE;
		}
	}
	else if (streq(form, "pem"))
	{
		switch (type)
		{
			case CRED_CERTIFICATE:
				*enc = CERT_PEM;
				return TRUE;
			case CRED_PRIVATE_KEY:
				*enc = PRIVKEY_PEM;
				return TRUE;
			case CRED_PUBLIC_KEY:
				*enc = PUBKEY_PEM;
				return TRUE;
			default:
				return FALSE;
		}
	}
	else if (streq(form, "pgp"))
	{
		switch (type)
		{
			case CRED_PRIVATE_KEY:
				*enc = PRIVKEY_PGP;
				return TRUE;
			case CRED_PUBLIC_KEY:
				*enc = PUBKEY_PGP;
				return TRUE;
			default:
				return FALSE;
		}
	}
	return FALSE;
}

/**
 * Convert a digest string to a hash algorithm
 */
hash_algorithm_t get_digest(char *name)
{
	if (streq(name, "md5"))
	{
		return HASH_MD5;
	}
	if (streq(name, "sha1"))
	{
		return HASH_SHA1;
	}
	if (streq(name, "sha224"))
	{
		return HASH_SHA224;
	}
	if (streq(name, "sha256"))
	{
		return HASH_SHA256;
	}
	if (streq(name, "sha384"))
	{
		return HASH_SHA384;
	}
	if (streq(name, "sha512"))
	{
		return HASH_SHA512;
	}
	return HASH_UNKNOWN;
}

/**
 * Library initialization and operation parsing
 */
int main(int argc, char *argv[])
{
	atexit(library_deinit);
	if (!library_init(NULL))
	{
		exit(SS_RC_LIBSTRONGSWAN_INTEGRITY);
	}
	if (lib->integrity &&
		!lib->integrity->check_file(lib->integrity, "pki", argv[0]))
	{
		fprintf(stderr, "integrity check of pki failed\n");
		exit(SS_RC_DAEMON_INTEGRITY);
	}
	if (!lib->plugins->load(lib->plugins, NULL,
			lib->settings->get_str(lib->settings, "pki.load", PLUGINS)))
	{
		exit(SS_RC_INITIALIZATION_FAILED);
	}
	return command_dispatch(argc, argv);
}

