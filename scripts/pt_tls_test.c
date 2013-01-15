/*
 * Copyright (C) 2010-2013 Martin Willi
 * Copyright (C) 2010-2013 revosec AG
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
#include <stdio.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <getopt.h>
#include <errno.h>
#include <string.h>

#include <library.h>
#include <utils/debug.h>
#include <pt_tls_client.h>
#include <pt_tls_dispatcher.h>
#include <tnc/tnc.h>
#include <tls.h>

#include <hydra.h>
#include <daemon.h>
#include <credentials/sets/mem_cred.h>

/**
 * Print usage information
 */
static void usage(FILE *out, char *cmd)
{
	fprintf(out, "usage:\n");
	fprintf(out, "  %s --connect <address> --port <port> [--cert <file>]+\n", cmd);
	fprintf(out, "               [--client <client-id>] [--secret <password>]\n");
	fprintf(out, "  %s --listen <address> --port <port> --key <key> [--cert <file>]+ \n", cmd);
	fprintf(out, "               [--secret <password>]\n");
}

/**
 * Client routine
 */
static int client(char *address, u_int16_t port, char *identity)
{
	pt_tls_client_t *assessment;
	tls_t *tnccs;
	identification_t *server, *client;
	host_t *host;
	status_t status;

	host = host_create_from_dns(address, AF_UNSPEC, port);
	if (!host)
	{
		return 1;
	}
	server = identification_create_from_string(address);
	client = identification_create_from_string(identity);
	tnccs = (tls_t*)tnc->tnccs->create_instance(tnc->tnccs, TNCCS_2_0, FALSE,
												server, client, TNC_IFT_TLS_2_0);
	if (!tnccs)
	{
		fprintf(stderr, "loading TNCCS failed: %s\n", PLUGINS);
		host->destroy(host);
		server->destroy(server);
		client->destroy(client);
		return 1;
	}
	assessment = pt_tls_client_create(host, server, client);
	status = assessment->run_assessment(assessment, (tnccs_t*)tnccs);
	assessment->destroy(assessment);
	tnccs->destroy(tnccs);
	return status;
}

/**
 * TNCCS server constructor callback
 */
static tnccs_t* create_tnccs(identification_t *server, identification_t *peer)
{
	return tnc->tnccs->create_instance(tnc->tnccs, TNCCS_2_0, TRUE,
									   server, peer, TNC_IFT_TLS_2_0);
}

/**
 * Server routine
 */
static int serve(char *server, u_int16_t port, pt_tls_auth_t auth)
{
	pt_tls_dispatcher_t *dispatcher;
	identification_t *id;
	host_t *host;

	host = host_create_from_dns(server, AF_UNSPEC, port);
	if (!host)
	{
		return 1;
	}
	id = identification_create_from_string(server);
	dispatcher = pt_tls_dispatcher_create(host, id, auth);
	if (!dispatcher)
	{
		return 1;
	}
	dispatcher->dispatch(dispatcher, create_tnccs);
	dispatcher->destroy(dispatcher);

	return 0;
}

/**
 * In-Memory credential set
 */
static mem_cred_t *creds;

/**
 * Load certificate from file
 */
static bool load_certificate(char *filename)
{
	certificate_t *cert;

	cert = lib->creds->create(lib->creds, CRED_CERTIFICATE, CERT_X509,
							  BUILD_FROM_FILE, filename, BUILD_END);
	if (!cert)
	{
		DBG1(DBG_TLS, "loading certificate from '%s' failed", filename);
		return FALSE;
	}
	creds->add_cert(creds, TRUE, cert);
	return TRUE;
}

/**
 * Load private key from file
 */
static bool load_key(char *filename)
{
	private_key_t *key;

	key = lib->creds->create(lib->creds, CRED_PRIVATE_KEY, KEY_RSA,
							 BUILD_FROM_FILE, filename, BUILD_END);
	if (!key)
	{
		DBG1(DBG_TLS, "loading key from '%s' failed", filename);
		return FALSE;
	}
	creds->add_key(creds, key);
	return TRUE;
}

/**
 * Debug level
 */
static level_t pt_tls_level = 1;

static void dbg_pt_tls(debug_t group, level_t level, char *fmt, ...)
{
	if (level <= pt_tls_level)
	{
		va_list args;

		va_start(args, fmt);
		vfprintf(stderr, fmt, args);
		fprintf(stderr, "\n");
		va_end(args);
	}
}

/**
 * Cleanup
 */
static void cleanup()
{
	lib->processor->cancel(lib->processor);
	lib->credmgr->remove_set(lib->credmgr, &creds->set);
	creds->destroy(creds);
	libcharon_deinit();
	libtnccs_deinit();
	libhydra_deinit();
	library_deinit();
}

/**
 * Initialize library
 */
static void init()
{
	library_init(NULL);

	libhydra_init("pt-tls-test");
	libtnccs_init();
	libcharon_init("pt-tls-test");

	dbg = dbg_pt_tls;

	lib->plugins->load(lib->plugins, NULL, PLUGINS);
	lib->processor->set_threads(lib->processor, 16);

	creds = mem_cred_create();
	lib->credmgr->add_set(lib->credmgr, &creds->set);

	atexit(cleanup);
}

int main(int argc, char *argv[])
{
	char *address = NULL, *identity = "%any", *secret = NULL;
	bool listen = FALSE;
	int port = 0, res;

	init();

	while (TRUE)
	{
		struct option long_opts[] = {
			{"help",		no_argument,			NULL,		'h' },
			{"connect",		required_argument,		NULL,		'c' },
			{"client",		required_argument,		NULL,		'i' },
			{"secret",		required_argument,		NULL,		's' },
			{"listen",		required_argument,		NULL,		'l' },
			{"port",		required_argument,		NULL,		'p' },
			{"cert",		required_argument,		NULL,		'x' },
			{"key",			required_argument,		NULL,		'k' },
			{"debug",		required_argument,		NULL,		'd' },
			{0,0,0,0 }
		};
		switch (getopt_long(argc, argv, "", long_opts, NULL))
		{
			case EOF:
				break;
			case 'h':
				usage(stdout, argv[0]);
				return 0;
			case 'x':
				if (!load_certificate(optarg))
				{
					return 1;
				}
				continue;
			case 'k':
				if (!load_key(optarg))
				{
					return 1;
				}
				continue;
			case 'l':
				listen = TRUE;
				/* fall */
			case 'c':
				if (address)
				{
					usage(stderr, argv[0]);
					return 1;
				}
				address = optarg;
				continue;
			case 'i':
				identity = optarg;
				continue;
			case 's':
				secret = optarg;
				continue;
			case 'p':
				port = atoi(optarg);
				continue;
			case 'd':
				pt_tls_level = atoi(optarg);
				continue;
			default:
				usage(stderr, argv[0]);
				return 1;
		}
		break;
	}
	if (!port || !address)
	{
		usage(stderr, argv[0]);
		return 1;
	}
	if (secret)
	{
		creds->add_shared(creds, shared_key_create(SHARED_EAP,
										chunk_clone(chunk_from_str(secret))),
							identification_create_from_string(identity), NULL);
	}
	if (listen)
	{
		res = serve(address, port, secret ? PT_TLS_AUTH_SASL : PT_TLS_AUTH_NONE);
	}
	else
	{
		res = client(address, port, identity);
	}
	return res;
}
