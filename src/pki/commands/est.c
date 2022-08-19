/*
 * Copyright (C) 2022 Andreas Steffen, strongSec GmbH
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

#include <errno.h>
#include <unistd.h>

#include "pki.h"
#include "pki_cert.h"
#include "est/est.h"
#include "est/est_tls.h"

#include <credentials/certificates/certificate.h>
#include <credentials/sets/mem_cred.h>

/* default polling time interval in EST manual mode */
#define DEFAULT_POLL_INTERVAL    60      /* seconds */

/**
 * Enroll an X.509 certificate with an EST server (RFC 7030)
 */
static int est()
{
	char *arg, *url = NULL, *file = NULL, *error = NULL;
	char *client_cert_file = NULL, *client_key_file = NULL;
	cred_encoding_type_t form = CERT_ASN1_DER;
	chunk_t pkcs10_encoding = chunk_empty, est_response = chunk_empty;
	certificate_t *pkcs10 = NULL, *client_cert = NULL, *cacert = NULL;
	mem_cred_t *creds = NULL;
	private_key_t *client_key = NULL;
	est_op_t est_op = EST_SIMPLE_ENROLL;
	est_tls_t *est_tls;
	u_int poll_interval = DEFAULT_POLL_INTERVAL;
	u_int max_poll_time = 0, poll_start = 0;
	u_int http_code = 0, retry_after = 0;
	int status = 1;

	/* initialize CA certificate storage */
	creds = mem_cred_create();
	lib->credmgr->add_set(lib->credmgr, &creds->set);

	while (TRUE)
	{
		switch (command_getopt(&arg))
		{
			case 'h':
				goto usage;
			case 'u':
				url = arg;
				continue;
			case 'i':
				file = arg;
				continue;
			case 'c':
				cacert = lib->creds->create(lib->creds, CRED_CERTIFICATE,
							 CERT_X509,	BUILD_FROM_FILE, arg, BUILD_END);
				if (!cacert)
				{
					DBG1(DBG_APP, "could not load cacert file '%s'", arg);
					goto end;
				}
				creds->add_cert(creds, TRUE, cacert);
				continue;
			case 'o':
				client_cert_file = arg;
				continue;
			case 'k':
				client_key_file = arg;
				continue;
			case 't':       /* --pollinterval */
				poll_interval = atoi(arg);
				if (poll_interval <= 0)
				{
					error = "invalid interval specified";
					goto usage;
				}
				continue;
			case 'm':       /* --maxpolltime */
				max_poll_time = atoi(arg);
				continue;
			case 'f':
				if (!get_form(arg, &form, CRED_CERTIFICATE))
				{
					error = "invalid certificate output format";
					goto usage;
				}
				continue;
			case EOF:
				break;
			default:
				error =  "invalid --est option";
				goto usage;
		}
		break;
	}

	if (!url)
	{
		error = "--url is required";
		goto usage;
	}

	if (client_cert_file && !client_key_file)
	{
		error = "--key is required if --cert is set";
		goto usage;
	}

	/* load PKCS#10 certificate request from file or stdin */
	if (file)
	{
		pkcs10 = lib->creds->create(lib->creds, CRED_CERTIFICATE,
									CERT_PKCS10_REQUEST,
									BUILD_FROM_FILE, file, BUILD_END);
	}
	else
	{
		chunk_t chunk;

		set_file_mode(stdin, CERT_ASN1_DER);
		if (!chunk_from_fd(0, &chunk))
		{
			DBG1(DBG_APP, "reading PKCS#10 certificate request failed: %s\n",
						   strerror(errno));
			goto end;
		}
		pkcs10 = lib->creds->create(lib->creds, CRED_CERTIFICATE,
									  CERT_PKCS10_REQUEST,
									  BUILD_BLOB, chunk, BUILD_END);
		free(chunk.ptr);
	}
	if (!pkcs10)
	{
		DBG1(DBG_APP, "parsing certificate request failed");
		goto end;
	}

	/* generate PKCS#10 encoding */
	if (!pkcs10->get_encoding(pkcs10, CERT_ASN1_DER, &pkcs10_encoding))
	{
		DBG1(DBG_APP, "encoding certificate request failed");
		goto end;
	}

	if (client_cert_file)
	{
		/* load old client certificate */
		client_cert = lib->creds->create(lib->creds, CRED_CERTIFICATE, CERT_X509,
									BUILD_FROM_FILE, client_cert_file, BUILD_END);
		if (!client_cert)
		{
			DBG1(DBG_APP, "could not load client cert file '%s'", client_cert_file);
			goto end;
		}
		creds->add_cert(creds, FALSE, client_cert->get_ref(client_cert));

		/* load old client private key */
		client_key = lib->creds->create(lib->creds, CRED_PRIVATE_KEY, KEY_ANY,
									 BUILD_FROM_FILE, client_key_file, BUILD_END);
		if (!client_key)
		{
			DBG1(DBG_APP, "parsing client private key failed");
			goto end;
		}
		creds->add_key(creds, client_key->get_ref(client_key));
		est_op = EST_SIMPLE_REENROLL;
	}

	est_tls = est_tls_create(url, client_cert, NULL);
	if (!est_tls)
	{
		DBG1(DBG_APP, "TLS connection to EST server was not established");
		goto end;
	}
	if (!est_tls->request(est_tls, est_op, pkcs10_encoding, &est_response,
						  &http_code, &retry_after))
	{
		DBG1(DBG_APP, "EST request failed: HTTP %u", http_code);
		goto end;
	}

	/* in case of manual mode, we are going into a polling loop */
	if (http_code == EST_HTTP_CODE_ACCEPTED)
	{
		if (retry_after > 0 && poll_interval < retry_after)
		{
			poll_interval = retry_after;
		}
		if (max_poll_time > 0)
		{
			DBG1(DBG_APP, "  EST request pending, polling every %d seconds"
						  " up to %d seconds", poll_interval, max_poll_time);
		}
		else
		{
			DBG1(DBG_APP, "  EST request pending, polling indefinitely"
						  " every %d seconds", poll_interval);
		}
		poll_start = time_monotonic(NULL);
	}

	while (http_code == EST_HTTP_CODE_ACCEPTED)
	{
		if (max_poll_time > 0 &&
		   (time_monotonic(NULL) - poll_start) >= max_poll_time)
		{
			DBG1(DBG_APP, "maximum poll time reached: %d seconds", max_poll_time);
			goto end;
		}
		DBG1(DBG_APP, "  going to sleep for %d seconds", poll_interval);
		sleep(poll_interval);
		chunk_free(&est_response);

		est_tls->destroy(est_tls);
		est_tls = est_tls_create(url, client_cert, NULL);
		if (!est_tls)
		{
			DBG1(DBG_APP, "TLS connection to EST server was not established");
			goto end;
		}
		if (!est_tls->request(est_tls, est_op, pkcs10_encoding, &est_response,
							  &http_code, &retry_after))
		{
			DBG1(DBG_APP, "EST request failed: HTTP %u", http_code);
			goto end;
		}
	}

	if (http_code == EST_HTTP_CODE_OK)
	{
		status = pki_cert_extract_cert(est_response, form, creds) ? 0 : 1;
	}

end:
	lib->credmgr->remove_set(lib->credmgr, &creds->set);
	creds->destroy(creds);
	DESTROY_IF(est_tls);
	DESTROY_IF(client_cert);
	DESTROY_IF(client_key);
	DESTROY_IF(pkcs10);
	chunk_free(&pkcs10_encoding);
	chunk_free(&est_response);

	return status;

usage:
	lib->credmgr->remove_set(lib->credmgr, &creds->set);
	creds->destroy(creds);

	return command_usage(error);
}

/**
 * Register the command.
 */
static void __attribute__ ((constructor))reg()
{
	command_register((command_t) {
		est, 'E', "est",
		"Enroll an X.509 certificate with an EST server",
		{"--url url [--in file] [--cacert file]+ [--cert file --key file]",
		 "[--interval time] [--maxpolltime time] [--outform der|pem]"},
		{
			{"help",        'h', 0, "show usage information"},
			{"url",         'u', 1, "URL of the EST server"},
			{"in",          'i', 1, "PKCS#10 input file, default: stdin"},
			{"cacert",      'c', 1, "CA certificate"},
			{"cert",        'o', 1, "Old certificate about to be renewed"},
			{"key",         'k', 1, "Old RSA private key about to be replaced"},
			{"interval",    't', 1, "poll interval, default: 60s"},
			{"maxpolltime", 'm', 1, "maximum poll time, default: 0 (no limit)"},
			{"outform",     'f', 1, "encoding of stored certificates, default: der"},
		}
	});
}
