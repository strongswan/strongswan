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

#include <unistd.h>

#include <utils/debug.h>
#include <credentials/sets/callback_cred.h>

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
	else if (streq(form, "dnskey"))
	{
		switch (type)
		{
			case CRED_PUBLIC_KEY:
				*enc = PUBKEY_DNSKEY;
				return TRUE;
			default:
				return FALSE;
		}
	}
	else if (streq(form, "sshkey"))
	{
		switch (type)
		{
			case CRED_PUBLIC_KEY:
				*enc = PUBKEY_SSHKEY;
				return TRUE;
			default:
				return FALSE;
		}
	}
	return FALSE;
}

/**
 * Callback credential set pki uses
 */
static callback_cred_t *cb_set;

/**
 * Callback function to receive credentials
 */
static shared_key_t* cb(void *data, shared_key_type_t type,
						identification_t *me, identification_t *other,
						id_match_t *match_me, id_match_t *match_other)
{
	char buf[64], *label, *secret;

	switch (type)
	{
		case SHARED_PIN:
			label = "Smartcard PIN";
			break;
		case SHARED_PRIVATE_KEY_PASS:
			label = "Private key passphrase";
			break;
		default:
			return NULL;
	}
	snprintf(buf, sizeof(buf), "%s: ", label);
	secret = getpass(buf);
	if (secret)
	{
		if (match_me)
		{
			*match_me = ID_MATCH_PERFECT;
		}
		if (match_other)
		{
			*match_other = ID_MATCH_NONE;
		}
		return shared_key_create(type,
							chunk_clone(chunk_create(secret, strlen(secret))));
	}
	return NULL;
}

/**
 * Register PIN/Passphrase callback function
 */
static void add_callback()
{
	cb_set = callback_cred_create_shared(cb, NULL);
	lib->credmgr->add_set(lib->credmgr, &cb_set->set);
}

/**
 * Unregister PIN/Passphrase callback function
 */
static void remove_callback()
{
	lib->credmgr->remove_set(lib->credmgr, &cb_set->set);
	cb_set->destroy(cb_set);
}

/**
 * Library initialization and operation parsing
 */
int main(int argc, char *argv[])
{
	atexit(library_deinit);
	if (!library_init(NULL, "pki"))
	{
		exit(SS_RC_LIBSTRONGSWAN_INTEGRITY);
	}
	if (lib->integrity &&
		!lib->integrity->check_file(lib->integrity, "pki", argv[0]))
	{
		fprintf(stderr, "integrity check of pki failed\n");
		exit(SS_RC_DAEMON_INTEGRITY);
	}
	if (!lib->plugins->load(lib->plugins,
			lib->settings->get_str(lib->settings, "pki.load", PLUGINS)))
	{
		exit(SS_RC_INITIALIZATION_FAILED);
	}

	add_callback();
	atexit(remove_callback);
	return command_dispatch(argc, argv);
}

