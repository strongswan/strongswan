/*
 * Copyright (C) 2014 Martin Willi
 * Copyright (C) 2014 revosec AG
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
#include <errno.h>
#include <unistd.h>
#include <sys/stat.h>

#include "command.h"
#include "swanctl.h"

#include <credentials/sets/callback_cred.h>

/**
 * Load a single certificate over vici
 */
static bool load_cert(vici_conn_t *conn, bool raw, char *dir,
					  char *type, chunk_t data)
{
	vici_req_t *req;
	vici_res_t *res;
	bool ret = TRUE;

	req = vici_begin("load-cert");

	vici_add_key_valuef(req, "type", "%s", type);
	vici_add_key_value(req, "data", data.ptr, data.len);

	res = vici_submit(req, conn);
	if (!res)
	{
		fprintf(stderr, "load-cert request failed: %s\n", strerror(errno));
		return FALSE;
	}
	if (raw)
	{
		vici_dump(res, "load-cert reply", stdout);
	}
	else if (!streq(vici_find_str(res, "no", "success"), "yes"))
	{
		fprintf(stderr, "loading '%s' failed: %s\n",
				dir, vici_find_str(res, "", "errmsg"));
		ret = FALSE;
	}
	vici_free_res(res);
	return ret;
}

/**
 * Load certficiates from a directory
 */
static void load_certs(vici_conn_t *conn, bool raw, char *type, char *dir)
{
	enumerator_t *enumerator;
	struct stat st;
	chunk_t *map;
	char *path;

	enumerator = enumerator_create_directory(dir);
	if (enumerator)
	{
		while (enumerator->enumerate(enumerator, NULL, &path, &st))
		{
			if (S_ISREG(st.st_mode))
			{
				map = chunk_map(path, FALSE);
				if (map)
				{
					load_cert(conn, raw, path, type, *map);
					chunk_unmap(map);
				}
				else
				{
					fprintf(stderr, "mapping '%s' failed: %s, skipped\n",
							path, strerror(errno));
				}
			}
		}
		enumerator->destroy(enumerator);
	}
}

/**
 * Load a single private key over vici
 */
static bool load_key(vici_conn_t *conn, bool raw, char *dir,
					  char *type, chunk_t data)
{
	vici_req_t *req;
	vici_res_t *res;
	bool ret = TRUE;

	req = vici_begin("load-key");

	vici_add_key_valuef(req, "type", "%s", type);
	vici_add_key_value(req, "data", data.ptr, data.len);

	res = vici_submit(req, conn);
	if (!res)
	{
		fprintf(stderr, "load-key request failed: %s\n", strerror(errno));
		return FALSE;
	}
	if (raw)
	{
		vici_dump(res, "load-key reply", stdout);
	}
	else if (!streq(vici_find_str(res, "no", "success"), "yes"))
	{
		fprintf(stderr, "loading '%s' failed: %s\n",
				dir, vici_find_str(res, "", "errmsg"));
		ret = FALSE;
	}
	vici_free_res(res);
	return ret;
}

/**
 * Callback function to prompt for private key passwords
 */
CALLBACK(password_cb, shared_key_t*,
	char *prompt, shared_key_type_t type,
	identification_t *me, identification_t *other,
	id_match_t *match_me, id_match_t *match_other)
{
	char *pwd;

	if (type != SHARED_PRIVATE_KEY_PASS)
	{
		return NULL;
	}
	pwd = getpass(prompt);
	if (!pwd || strlen(pwd) == 0)
	{
		return NULL;
	}
	if (match_me)
	{
		*match_me = ID_MATCH_PERFECT;
	}
	if (match_other)
	{
		*match_other = ID_MATCH_PERFECT;
	}
	return shared_key_create(type, chunk_clone(chunk_from_str(pwd)));
}

/**
 * Try to parse a potentially encrypted private key
 */
static private_key_t* decrypt_key(char *name, char *type, chunk_t encoding)
{
	key_type_t kt = KEY_ANY;
	private_key_t *private;
	callback_cred_t *cb;
	char buf[128];

	if (streq(type, "rsa"))
	{
		kt = KEY_RSA;
	}
	else if (streq(type, "ecdsa"))
	{
		kt = KEY_ECDSA;
	}

	snprintf(buf, sizeof(buf), "Password for '%s': ", name);

	cb = callback_cred_create_shared(password_cb, buf);
	lib->credmgr->add_set(lib->credmgr, &cb->set);

	private = lib->creds->create(lib->creds, CRED_PRIVATE_KEY, kt,
								 BUILD_BLOB_PEM, encoding, BUILD_END);

	lib->credmgr->remove_set(lib->credmgr, &cb->set);
	cb->destroy(cb);

	return private;
}

/**
 * Try to decrypt and load a private key
 */
static bool load_encrypted_key(vici_conn_t *conn, bool raw,
							   char *rel, char *path, char *type, chunk_t data)
{
	private_key_t *private;
	bool loaded = FALSE;
	chunk_t encoding;

	private = decrypt_key(rel, type, data);
	if (private)
	{
		if (private->get_encoding(private, PRIVKEY_ASN1_DER,
								  &encoding))
		{
			switch (private->get_type(private))
			{
				case KEY_RSA:
					loaded = load_key(conn, raw, path, "rsa", encoding);
					break;
				case KEY_ECDSA:
					loaded = load_key(conn, raw, path, "ecdsa", encoding);
					break;
				default:
					break;
			}
			chunk_clear(&encoding);
		}
		private->destroy(private);
	}
	return loaded;
}

/**
 * Load private keys from a directory
 */
static void load_keys(vici_conn_t *conn, bool raw, bool noprompt,
					  char *type, char *dir)
{
	enumerator_t *enumerator;
	struct stat st;
	chunk_t *map;
	char *path, *rel;

	enumerator = enumerator_create_directory(dir);
	if (enumerator)
	{
		while (enumerator->enumerate(enumerator, &rel, &path, &st))
		{
			if (S_ISREG(st.st_mode))
			{
				map = chunk_map(path, FALSE);
				if (map)
				{
					if (noprompt ||
						!load_encrypted_key(conn, raw, rel, path, type, *map))
					{
						load_key(conn, raw, path, type, *map);
					}
					chunk_unmap(map);
				}
				else
				{
					fprintf(stderr, "mapping '%s' failed: %s, skipped\n",
							path, strerror(errno));
				}
			}
		}
		enumerator->destroy(enumerator);
	}
}

/**
 * Clear all currently loaded credentials
 */
static bool clear_creds(vici_conn_t *conn, bool raw)
{
	vici_res_t *res;

	res = vici_submit(vici_begin("clear-creds"), conn);
	if (!res)
	{
		fprintf(stderr, "clear-creds request failed: %s\n", strerror(errno));
		return FALSE;
	}
	if (raw)
	{
		vici_dump(res, "clear-creds reply", stdout);
	}
	vici_free_res(res);
	return TRUE;
}

static int load_creds(vici_conn_t *conn)
{
	bool raw = FALSE, clear = FALSE, noprompt = FALSE;
	char *arg;

	while (TRUE)
	{
		switch (command_getopt(&arg))
		{
			case 'h':
				return command_usage(NULL);
			case 'c':
				clear = TRUE;
				continue;
			case 'n':
				noprompt = TRUE;
				continue;
			case 'r':
				raw = TRUE;
				continue;
			case EOF:
				break;
			default:
				return command_usage("invalid --load-creds option");
		}
		break;
	}

	if (clear)
	{
		if (!clear_creds(conn, raw))
		{
			return ECONNREFUSED;
		}
	}

	load_certs(conn, raw, "x509", SWANCTL_X509DIR);
	load_certs(conn, raw, "x509ca", SWANCTL_X509CADIR);
	load_certs(conn, raw, "x509aa", SWANCTL_X509AADIR);
	load_certs(conn, raw, "x509crl", SWANCTL_X509CRLDIR);
	load_certs(conn, raw, "x509ac", SWANCTL_X509ACDIR);

	load_keys(conn, raw, noprompt, "rsa", SWANCTL_RSADIR);
	load_keys(conn, raw, noprompt, "ecdsa", SWANCTL_ECDSADIR);
	load_keys(conn, raw, noprompt, "any", SWANCTL_PKCS8DIR);

	return 0;
}

/**
 * Register the command.
 */
static void __attribute__ ((constructor))reg()
{
	command_register((command_t) {
		load_creds, 's', "load-creds", "(re-)load credentials",
		{"[--raw]"},
		{
			{"help",		'h', 0, "show usage information"},
			{"clear",		'c', 0, "clear previously loaded credentials"},
			{"noprompt",	'n', 0, "do not prompt for passwords"},
			{"raw",			'r', 0, "dump raw response message"},
		}
	});
}
