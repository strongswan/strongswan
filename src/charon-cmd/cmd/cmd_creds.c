/*
 * Copyright (C) 2013 Martin Willi
 * Copyright (C) 2013 revosec AG
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

#include "cmd_creds.h"

#include <utils/debug.h>
#include <credentials/sets/mem_cred.h>

typedef struct private_cmd_creds_t private_cmd_creds_t;

/**
 * Private data of an cmd_creds_t object.
 */
struct private_cmd_creds_t {

	/**
	 * Public cmd_creds_t interface.
	 */
	cmd_creds_t public;

	/**
	 * Reused in-memory credential set
	 */
	mem_cred_t *creds;
};

/**
 * Load a trusted certificate from path
 */
static void load_cert(private_cmd_creds_t *this, char *path)
{
	certificate_t *cert;

	cert = lib->creds->create(lib->creds, CRED_CERTIFICATE, CERT_X509,
							  BUILD_FROM_FILE, path, BUILD_END);
	if (!cert)
	{
		DBG1(DBG_CFG, "loading certificate from '%s' failed", path);
		exit(1);
	}
	this->creds->add_cert(this->creds, TRUE, cert);
}

/**
 * Load a private key of given kind from path
 */
static void load_key(private_cmd_creds_t *this, key_type_t type, char *path)
{
	private_key_t *privkey;

	privkey = lib->creds->create(lib->creds, CRED_PRIVATE_KEY, type,
								 BUILD_FROM_FILE, path, BUILD_END);
	if (!privkey)
	{
		DBG1(DBG_CFG, "loading %N private key from '%s' failed",
			 key_type_names, type, path);
		exit(1);
	}
	this->creds->add_key(this->creds, privkey);
}

METHOD(cmd_creds_t, handle, bool,
	private_cmd_creds_t *this, cmd_option_type_t opt, char *arg)
{
	switch (opt)
	{
		case CMD_OPT_CERT:
			load_cert(this, arg);
			break;
		case CMD_OPT_RSA:
			load_key(this, KEY_RSA, arg);
			break;
		default:
			return FALSE;
	}
	return TRUE;
}

METHOD(cmd_creds_t, destroy, void,
	private_cmd_creds_t *this)
{
	lib->credmgr->remove_set(lib->credmgr, &this->creds->set);
	this->creds->destroy(this->creds);
	free(this);
}

/**
 * See header
 */
cmd_creds_t *cmd_creds_create()
{
	private_cmd_creds_t *this;

	INIT(this,
		.public = {
			.handle = _handle,
			.destroy = _destroy,
		},
		.creds = mem_cred_create(),
	);

	lib->credmgr->add_set(lib->credmgr, &this->creds->set);

	return &this->public;
}
