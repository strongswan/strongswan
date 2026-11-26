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

#include <unistd.h>

#include <daemon.h>
#include <library.h>
#include <plugins/vici/vici_dispatcher.h>
#include <plugins/vici/vici_authority.h>
#include <plugins/vici/vici_cred.h>
#include <plugins/vici/vici_message.h>
#include <plugins/vici/vici_builder.h>

/* process_request has external linkage in vici_dispatcher.c. */
struct private_vici_dispatcher_t;
extern void process_request(struct private_vici_dispatcher_t *this,
							 char *name, u_int id, chunk_t data);

/* Commands registered by vici_cred.c, each driven by a mutator selector. */
enum cred_cmd {
	CMD_CLEAR_CREDS = 0,
	CMD_FLUSH_CERTS,
	CMD_LOAD_CERT,
	CMD_LOAD_KEY,
	CMD_UNLOAD_KEY,
	CMD_GET_KEYS,
	CMD_LOAD_SHARED,
	CMD_UNLOAD_SHARED,
	CMD_GET_SHARED,
	CMD_COUNT
};

static const char *cmd_names[CMD_COUNT] = {
	[CMD_CLEAR_CREDS]   = "clear-creds",
	[CMD_FLUSH_CERTS]   = "flush-certs",
	[CMD_LOAD_CERT]     = "load-cert",
	[CMD_LOAD_KEY]      = "load-key",
	[CMD_UNLOAD_KEY]    = "unload-key",
	[CMD_GET_KEYS]      = "get-keys",
	[CMD_LOAD_SHARED]   = "load-shared",
	[CMD_UNLOAD_SHARED] = "unload-shared",
	[CMD_GET_SHARED]    = "get-shared",
};

/* Lookup tables for command-specific selector bytes. */
static const char *cert_type_strs[] = {
	"x509", "x509ca", "x509aa", "x509ocsp", "x509ac",
	"x509crl", "ocsp_response", "pubkey", "pgp",
	"X509", "X509_AA", "X509_AC", "X509_CRL", "X509_OCSP_RESPONSE",
	"TRUSTED_PUBKEY", "GPG", "unknown-type",
};

static const char *cert_flag_strs[] = {
	"NONE", "CA", "AA", "OCSP", "AC", "SERVER", "IKE", "bogus-flag",
};

static const char *key_type_strs[] = {
	"any", "rsa", "ecdsa", "ed25519", "ed448", "bliss", "unknown-key",
};

static const char *shared_type_strs[] = {
	"ike", "eap", "xauth", "ntlm", "ppk", "unknown-shared",
};

/* Identification owners used by load-shared / unload-key / unload-shared. */
static const char *owner_strs[] = {
	"%any", "alice@example.com", "moon.strongswan.org", "C=CH, O=strongSwan, CN=moon",
	"192.0.2.1", "2001:db8::1", "",
};

static vici_dispatcher_t *dispatcher;
static vici_authority_t  *authority;
static vici_cred_t       *cred;

/* Empty message: a builder with no entries, finalized. */
static vici_message_t *empty_msg(void)
{
	vici_builder_t *b = vici_builder_create();
	return b->finalize(b);
}

/* Build a message containing key-value pairs from a {key, str} tuple list. */
static vici_message_t *build_msg(const char *keys[], const char *values[],
								 int n, chunk_t data)
{
	vici_builder_t *b;
	int i;

	b = vici_builder_create();
	for (i = 0; i < n; i++)
	{
		b->add_kv(b, (char*)keys[i], "%s", values[i]);
	}
	if (data.len > 0)
	{
		b->add(b, VICI_KEY_VALUE, "data", data);
	}
	return b->finalize(b);
}

int LLVMFuzzerInitialize(int *argc, char ***argv)
{
	char uri[128];

	dbg_default_set_level(-1);
	library_init(NULL, "fuzz_vici_cred");
	libcharon_init();

	if (!lib->plugins->load(lib->plugins, PLUGINS))
	{
		return 1;
	}

	snprintf(uri, sizeof(uri), "unix:///tmp/vici-cred-fuzz-%d.sock", getpid());
	dispatcher = vici_dispatcher_create(uri);
	authority = dispatcher ? vici_authority_create(dispatcher) : NULL;
	cred = authority ? vici_cred_create(dispatcher, authority) : NULL;
	if (!dispatcher || !authority || !cred)
	{
		return 1;
	}
	return 0;
}

int LLVMFuzzerTestOneInput(const uint8_t *buf, size_t len)
{
	enum cred_cmd cmd;
	vici_message_t *msg = NULL;
	vici_builder_t *b;
	chunk_t data = chunk_empty;
	const char *keys[2];
	const char *values[2];

	if (len < 1)
	{
		return 0;
	}

	cmd = buf[0] % CMD_COUNT;

	switch (cmd)
	{
		case CMD_CLEAR_CREDS:
		case CMD_GET_KEYS:
		case CMD_GET_SHARED:
			msg = empty_msg();
			break;

		case CMD_FLUSH_CERTS:
			if (len < 2) { msg = empty_msg(); break; }
			keys[0] = "type";
			values[0] = cert_type_strs[buf[1] % countof(cert_type_strs)];
			msg = build_msg(keys, values, 1, chunk_empty);
			break;

		case CMD_LOAD_CERT:
			if (len < 3) { return 0; }
			keys[0] = "type";  values[0] = cert_type_strs[buf[1] % countof(cert_type_strs)];
			keys[1] = "flag";  values[1] = cert_flag_strs[buf[2] % countof(cert_flag_strs)];
			data = chunk_create((u_char*)buf + 3, len - 3);
			msg = build_msg(keys, values, 2, data);
			break;

		case CMD_LOAD_KEY:
			if (len < 2) { return 0; }
			keys[0] = "type";
			values[0] = key_type_strs[buf[1] % countof(key_type_strs)];
			data = chunk_create((u_char*)buf + 2, len - 2);
			msg = build_msg(keys, values, 1, data);
			break;

		case CMD_UNLOAD_KEY:
		case CMD_UNLOAD_SHARED:
			if (len < 2) { return 0; }
			keys[0] = "id";
			values[0] = owner_strs[buf[1] % countof(owner_strs)];
			msg = build_msg(keys, values, 1, chunk_empty);
			break;

		case CMD_LOAD_SHARED:
			if (len < 3) { return 0; }
			b = vici_builder_create();
			b->add_kv(b, "type", "%s",
					  shared_type_strs[buf[1] % countof(shared_type_strs)]);
			b->add_kv(b, "owners", "%s",
					  owner_strs[buf[2] % countof(owner_strs)]);
			data = chunk_create((u_char*)buf + 3, len - 3);
			if (data.len > 0)
			{
				b->add(b, VICI_KEY_VALUE, "data", data);
			}
			msg = b->finalize(b);
			break;

		case CMD_COUNT:
			return 0;
	}

	if (!msg)
	{
		return 0;
	}

	process_request((struct private_vici_dispatcher_t*)dispatcher,
					(char*)cmd_names[cmd], 0, msg->get_encoding(msg));

	msg->destroy(msg);
	return 0;
}
