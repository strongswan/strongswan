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
#include "load_creds.h"

#include <credentials/sets/mem_cred.h>
#include <credentials/sets/callback_cred.h>
#include <credentials/containers/pkcs12.h>

/**
 * Load a single certificate over vici
 */
static bool load_cert(vici_conn_t *conn, command_format_options_t format,
					  char *dir, char *type, chunk_t data)
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
	if (format & COMMAND_FORMAT_RAW)
	{
		vici_dump(res, "load-cert reply", format & COMMAND_FORMAT_PRETTY,
				  stdout);
	}
	else if (!streq(vici_find_str(res, "no", "success"), "yes"))
	{
		fprintf(stderr, "loading '%s' failed: %s\n",
				dir, vici_find_str(res, "", "errmsg"));
		ret = FALSE;
	}
	else
	{
		printf("loaded %s certificate from '%s'\n", type, dir);
	}
	vici_free_res(res);
	return ret;
}

/**
 * Load certficiates from a directory
 */
static void load_certs(vici_conn_t *conn, command_format_options_t format,
					   char *type, char *dir)
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
					load_cert(conn, format, path, type, *map);
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
static bool load_key(vici_conn_t *conn, command_format_options_t format,
					 char *dir, char *type, chunk_t data)
{
	vici_req_t *req;
	vici_res_t *res;
	bool ret = TRUE;

	req = vici_begin("load-key");

	if (streq(type, "pkcs8"))
	{	/* as used by vici */
		vici_add_key_valuef(req, "type", "any");
	}
	else
	{
		vici_add_key_valuef(req, "type", "%s", type);
	}
	vici_add_key_value(req, "data", data.ptr, data.len);

	res = vici_submit(req, conn);
	if (!res)
	{
		fprintf(stderr, "load-key request failed: %s\n", strerror(errno));
		return FALSE;
	}
	if (format & COMMAND_FORMAT_RAW)
	{
		vici_dump(res, "load-key reply", format & COMMAND_FORMAT_PRETTY,
				  stdout);
	}
	else if (!streq(vici_find_str(res, "no", "success"), "yes"))
	{
		fprintf(stderr, "loading '%s' failed: %s\n",
				dir, vici_find_str(res, "", "errmsg"));
		ret = FALSE;
	}
	else
	{
		printf("loaded %s key from '%s'\n", type, dir);
	}
	vici_free_res(res);
	return ret;
}

/**
 * Load a private key of any type to vici
 */
static bool load_key_anytype(vici_conn_t *conn, command_format_options_t format,
							 char *path, private_key_t *private)
{
	bool loaded = FALSE;
	chunk_t encoding;

	if (!private->get_encoding(private, PRIVKEY_ASN1_DER, &encoding))
	{
		fprintf(stderr, "encoding private key from '%s' failed\n", path);
		return FALSE;
	}
	switch (private->get_type(private))
	{
		case KEY_RSA:
			loaded = load_key(conn, format, path, "rsa", encoding);
			break;
		case KEY_ECDSA:
			loaded = load_key(conn, format, path, "ecdsa", encoding);
			break;
		default:
			fprintf(stderr, "unsupported key type in '%s'\n", path);
			break;
	}
	chunk_clear(&encoding);
	return loaded;
}

/**
 * Data passed to password callback
 */
typedef struct {
	char prompt[128];
	mem_cred_t *cache;
} cb_data_t;

/**
 * Callback function to prompt for private key passwords
 */
CALLBACK(password_cb, shared_key_t*,
	cb_data_t *data, shared_key_type_t type,
	identification_t *me, identification_t *other,
	id_match_t *match_me, id_match_t *match_other)
{
	shared_key_t *shared;
	char *pwd = NULL;

	if (type != SHARED_PRIVATE_KEY_PASS)
	{
		return NULL;
	}
#ifdef HAVE_GETPASS
	pwd = getpass(data->prompt);
#endif
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
	shared = shared_key_create(type, chunk_clone(chunk_from_str(pwd)));
	/* cache secret if it is required more than once (PKCS#12) */
	data->cache->add_shared(data->cache, shared, NULL);
	return shared->get_ref(shared);
}

/**
 * Determine credential type and subtype from a type string
 */
static bool determine_credtype(char *type, credential_type_t *credtype,
							   int *subtype)
{
	struct {
		char *type;
		credential_type_t credtype;
		int subtype;
	} map[] = {
		{ "pkcs8",			CRED_PRIVATE_KEY,		KEY_ANY,			},
		{ "rsa",			CRED_PRIVATE_KEY,		KEY_RSA,			},
		{ "ecdsa",			CRED_PRIVATE_KEY,		KEY_ECDSA,			},
		{ "pkcs12",			CRED_CONTAINER,			CONTAINER_PKCS12,	},
	};
	int i;

	for (i = 0; i < countof(map); i++)
	{
		if (streq(map[i].type, type))
		{
			*credtype = map[i].credtype;
			*subtype = map[i].subtype;
			return TRUE;
		}
	}
	return FALSE;
}

/**
 * Try to parse a potentially encrypted credential using password prompt
 */
static void* decrypt(char *name, char *type, chunk_t encoding)
{
	credential_type_t credtype;
	int subtype;
	void *cred;
	callback_cred_t *cb;
	cb_data_t data;

	if (!determine_credtype(type, &credtype, &subtype))
	{
		return NULL;
	}

	snprintf(data.prompt, sizeof(data.prompt), "Password for %s file '%s': ",
			 type, name);

	data.cache = mem_cred_create();
	lib->credmgr->add_set(lib->credmgr, &data.cache->set);
	cb = callback_cred_create_shared(password_cb, &data);
	lib->credmgr->add_set(lib->credmgr, &cb->set);

	cred = lib->creds->create(lib->creds, credtype, subtype,
							  BUILD_BLOB_PEM, encoding, BUILD_END);

	lib->credmgr->remove_set(lib->credmgr, &data.cache->set);
	data.cache->destroy(data.cache);
	lib->credmgr->remove_set(lib->credmgr, &cb->set);
	cb->destroy(cb);

	return cred;
}

/**
 * Try to parse a potentially encrypted credential using configured secret
 */
static void* decrypt_with_config(settings_t *cfg, char *name, char *type,
								 chunk_t encoding)
{
	credential_type_t credtype;
	int subtype;
	enumerator_t *enumerator, *secrets;
	char *section, *key, *value, *file, buf[128];
	shared_key_t *shared;
	void *cred = NULL;
	mem_cred_t *mem = NULL;

	if (!determine_credtype(type, &credtype, &subtype))
	{
		return NULL;
	}

	/* load all secrets for this key type */
	enumerator = cfg->create_section_enumerator(cfg, "secrets");
	while (enumerator->enumerate(enumerator, &section))
	{
		if (strpfx(section, type))
		{
			file = cfg->get_str(cfg, "secrets.%s.file", NULL, section);
			if (file && strcaseeq(file, name))
			{
				snprintf(buf, sizeof(buf), "secrets.%s", section);
				secrets = cfg->create_key_value_enumerator(cfg, buf);
				while (secrets->enumerate(secrets, &key, &value))
				{
					if (strpfx(key, "secret"))
					{
						if (!mem)
						{
							mem = mem_cred_create();
						}
						shared = shared_key_create(SHARED_PRIVATE_KEY_PASS,
											chunk_clone(chunk_from_str(value)));
						mem->add_shared(mem, shared, NULL);
					}
				}
				secrets->destroy(secrets);
			}
		}
	}
	enumerator->destroy(enumerator);

	if (mem)
	{
		lib->credmgr->add_local_set(lib->credmgr, &mem->set, FALSE);

		cred = lib->creds->create(lib->creds, credtype, subtype,
								  BUILD_BLOB_PEM, encoding, BUILD_END);

		lib->credmgr->remove_local_set(lib->credmgr, &mem->set);

		if (!cred)
		{
			fprintf(stderr, "configured decryption secret for '%s' invalid\n",
					name);
		}

		mem->destroy(mem);
	}

	return cred;
}

/**
 * Try to decrypt and load a private key
 */
static bool load_encrypted_key(vici_conn_t *conn,
							   command_format_options_t format, settings_t *cfg,
							   char *rel, char *path, char *type, bool noprompt,
							   chunk_t data)
{
	private_key_t *private;
	bool loaded = FALSE;

	private = decrypt_with_config(cfg, rel, type, data);
	if (!private && !noprompt)
	{
		private = decrypt(rel, type, data);
	}
	if (private)
	{
		loaded = load_key_anytype(conn, format, path, private);
		private->destroy(private);
	}
	return loaded;
}

/**
 * Load private keys from a directory
 */
static void load_keys(vici_conn_t *conn, command_format_options_t format,
					  bool noprompt, settings_t *cfg, char *type, char *dir)
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
					if (!load_encrypted_key(conn, format, cfg, rel, path, type,
											noprompt, *map))
					{
						load_key(conn, format, path, type, *map);
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
 * Load credentials from a PKCS#12 container over vici
 */
static bool load_pkcs12(vici_conn_t *conn, command_format_options_t format,
						char *path, pkcs12_t *p12)
{
	enumerator_t *enumerator;
	certificate_t *cert;
	private_key_t *private;
	chunk_t encoding;
	bool loaded = TRUE;

	enumerator = p12->create_cert_enumerator(p12);
	while (loaded && enumerator->enumerate(enumerator, &cert))
	{
		loaded = FALSE;
		if (cert->get_encoding(cert, CERT_ASN1_DER, &encoding))
		{
			loaded = load_cert(conn, format, path, "x509", encoding);
			if (loaded)
			{
				fprintf(stderr, "  %Y\n", cert->get_subject(cert));
			}
			free(encoding.ptr);
		}
		else
		{
			fprintf(stderr, "encoding certificate from '%s' failed\n", path);
		}
	}
	enumerator->destroy(enumerator);

	enumerator = p12->create_key_enumerator(p12);
	while (loaded && enumerator->enumerate(enumerator, &private))
	{
		loaded = load_key_anytype(conn, format, path, private);
	}
	enumerator->destroy(enumerator);

	return loaded;
}

/**
 * Try to decrypt and load credentials from a container
 */
static bool load_encrypted_container(vici_conn_t *conn,
					command_format_options_t format, settings_t *cfg, char *rel,
					char *path, char *type, bool noprompt, chunk_t data)
{
	container_t *container;
	bool loaded = FALSE;

	container = decrypt_with_config(cfg, rel, type, data);
	if (!container && !noprompt)
	{
		container = decrypt(rel, type, data);
	}
	if (container)
	{
		switch (container->get_type(container))
		{
			case CONTAINER_PKCS12:
				loaded = load_pkcs12(conn, format, path, (pkcs12_t*)container);
				break;
			default:
				break;
		}
		container->destroy(container);
	}
	return loaded;
}

/**
 * Load credential containers from a directory
 */
static void load_containers(vici_conn_t *conn, command_format_options_t format,
						bool noprompt, settings_t *cfg, char *type, char *dir)
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
					load_encrypted_container(conn, format, cfg, rel, path,
											 type, noprompt, *map);
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
 * Load a single secret over VICI
 */
static bool load_secret(vici_conn_t *conn, settings_t *cfg,
						char *section, command_format_options_t format)
{
	enumerator_t *enumerator;
	vici_req_t *req;
	vici_res_t *res;
	chunk_t data;
	char *key, *value, buf[128], *type = NULL;
	bool ret = TRUE;
	int i;
	char *types[] = {
		"eap",
		"xauth",
		"ike",
		"rsa",
		"ecdsa",
		"pkcs8",
		"pkcs12",
	};

	for (i = 0; i < countof(types); i++)
	{
		if (strpfx(section, types[i]))
		{
			type = types[i];
			break;
		}
	}
	if (!type)
	{
		fprintf(stderr, "ignoring unsupported secret '%s'\n", section);
		return FALSE;
	}
	if (!streq(type, "eap") && !streq(type, "xauth") && !streq(type, "ike"))
	{	/* skip non-shared secrets */
		return TRUE;
	}

	value = cfg->get_str(cfg, "secrets.%s.secret", NULL, section);
	if (!value)
	{
		fprintf(stderr, "missing secret in '%s', ignored\n", section);
		return FALSE;
	}
	if (strcasepfx(value, "0x"))
	{
		data = chunk_from_hex(chunk_from_str(value + 2), NULL);
	}
	else if (strcasepfx(value, "0s"))
	{
		data = chunk_from_base64(chunk_from_str(value + 2), NULL);
	}
	else
	{
		data = chunk_clone(chunk_from_str(value));
	}

	req = vici_begin("load-shared");

	vici_add_key_valuef(req, "type", "%s", type);
	vici_add_key_value(req, "data", data.ptr, data.len);
	chunk_clear(&data);

	vici_begin_list(req, "owners");
	snprintf(buf, sizeof(buf), "secrets.%s", section);
	enumerator = cfg->create_key_value_enumerator(cfg, buf);
	while (enumerator->enumerate(enumerator, &key, &value))
	{
		if (strpfx(key, "id"))
		{
			vici_add_list_itemf(req, "%s", value);
		}
	}
	enumerator->destroy(enumerator);
	vici_end_list(req);

	res = vici_submit(req, conn);
	if (!res)
	{
		fprintf(stderr, "load-shared request failed: %s\n", strerror(errno));
		return FALSE;
	}
	if (format & COMMAND_FORMAT_RAW)
	{
		vici_dump(res, "load-shared reply", format & COMMAND_FORMAT_PRETTY,
				  stdout);
	}
	else if (!streq(vici_find_str(res, "no", "success"), "yes"))
	{
		fprintf(stderr, "loading shared secret failed: %s\n",
				vici_find_str(res, "", "errmsg"));
		ret = FALSE;
	}
	else
	{
		printf("loaded %s secret '%s'\n", type, section);
	}
	vici_free_res(res);
	return ret;
}

/**
 * Clear all currently loaded credentials
 */
static bool clear_creds(vici_conn_t *conn, command_format_options_t format)
{
	vici_res_t *res;

	res = vici_submit(vici_begin("clear-creds"), conn);
	if (!res)
	{
		fprintf(stderr, "clear-creds request failed: %s\n", strerror(errno));
		return FALSE;
	}
	if (format & COMMAND_FORMAT_RAW)
	{
		vici_dump(res, "clear-creds reply", format & COMMAND_FORMAT_PRETTY,
				  stdout);
	}
	vici_free_res(res);
	return TRUE;
}

/**
 * See header.
 */
int load_creds_cfg(vici_conn_t *conn, command_format_options_t format,
				   settings_t *cfg, bool clear, bool noprompt)
{
	enumerator_t *enumerator;
	char *section;

	if (clear)
	{
		if (!clear_creds(conn, format))
		{
			return ECONNREFUSED;
		}
	}

	load_certs(conn, format, "x509", SWANCTL_X509DIR);
	load_certs(conn, format, "x509ca", SWANCTL_X509CADIR);
	load_certs(conn, format, "x509aa", SWANCTL_X509AADIR);
	load_certs(conn, format, "x509crl", SWANCTL_X509CRLDIR);
	load_certs(conn, format, "x509ac", SWANCTL_X509ACDIR);

	load_keys(conn, format, noprompt, cfg, "rsa", SWANCTL_RSADIR);
	load_keys(conn, format, noprompt, cfg, "ecdsa", SWANCTL_ECDSADIR);
	load_keys(conn, format, noprompt, cfg, "pkcs8", SWANCTL_PKCS8DIR);

	load_containers(conn, format, noprompt, cfg, "pkcs12", SWANCTL_PKCS12DIR);

	enumerator = cfg->create_section_enumerator(cfg, "secrets");
	while (enumerator->enumerate(enumerator, &section))
	{
		load_secret(conn, cfg, section, format);
	}
	enumerator->destroy(enumerator);

	return 0;
}

static int load_creds(vici_conn_t *conn)
{
	bool clear = FALSE, noprompt = FALSE;
	command_format_options_t format = COMMAND_FORMAT_NONE;
	settings_t *cfg;
	char *arg;
	int ret;

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
			case 'P':
				format |= COMMAND_FORMAT_PRETTY;
				/* fall through to raw */
			case 'r':
				format |= COMMAND_FORMAT_RAW;
				continue;
			case EOF:
				break;
			default:
				return command_usage("invalid --load-creds option");
		}
		break;
	}

	cfg = settings_create(SWANCTL_CONF);
	if (!cfg)
	{
		fprintf(stderr, "parsing '%s' failed\n", SWANCTL_CONF);
		return EINVAL;
	}

	ret = load_creds_cfg(conn, format, cfg, clear, noprompt);

	cfg->destroy(cfg);

	return ret;
}

/**
 * Register the command.
 */
static void __attribute__ ((constructor))reg()
{
	command_register((command_t) {
		load_creds, 's', "load-creds", "(re-)load credentials",
		{"[--raw|--pretty] [--clear] [--noprompt]"},
		{
			{"help",		'h', 0, "show usage information"},
			{"clear",		'c', 0, "clear previously loaded credentials"},
			{"noprompt",	'n', 0, "do not prompt for passwords"},
			{"raw",			'r', 0, "dump raw response message"},
			{"pretty",		'P', 0, "dump raw response message in pretty print"},
		}
	});
}
