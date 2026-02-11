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
#include <tls.h>

/**
 * Minimal TLS application stub for fuzzing
 */
typedef struct {
	tls_application_t public;
} fuzz_tls_application_t;

static status_t app_process(tls_application_t *this, bio_reader_t *reader)
{
	/* Consume application data without processing */
	return NEED_MORE;
}

static status_t app_build(tls_application_t *this, bio_writer_t *writer)
{
	/* No application data to send */
	return INVALID_STATE;
}

static void app_destroy(tls_application_t *this)
{
	free(this);
}

static tls_application_t *create_tls_application()
{
	fuzz_tls_application_t *app;

	INIT(app,
		.public = {
			.process = app_process,
			.build = app_build,
			.destroy = app_destroy,
		},
	);

	return &app->public;
}

int LLVMFuzzerInitialize(int *argc, char ***argv)
{
	/* Disable all logging */
	dbg_default_set_level(-1);

	/* Initialize strongSwan library */
	library_init(NULL, "fuzz_tls");

	/* Load required plugins for TLS */
	if (!lib->plugins->load(lib->plugins, PLUGINS))
	{
		return 1;
	}

	return 0;
}

int LLVMFuzzerTestOneInput(const uint8_t *buf, size_t len)
{
	tls_t *tls;
	identification_t *server_id, *peer_id;
	tls_application_t *app;
	status_t status;
	bool is_server;
	char out[TLS_MAX_FRAGMENT_LEN + 2048];
	size_t outlen, msglen;

	/* Need one role byte plus minimum TLS record header (5 bytes) */
	if (len < 6)
	{
		return 0;
	}

	/* First byte selects role: input is then either a request (server) or response (client) */
	is_server = (buf[0] & 1) != 0;
	buf++;
	len--;

	server_id = identification_create_from_string("server.test");
	peer_id = identification_create_from_string("peer.test");
	app = create_tls_application();

	tls = tls_create(is_server, server_id, peer_id, TLS_PURPOSE_GENERIC,
					 app, NULL, TLS_FLAG_ENCRYPTION_OPTIONAL);
	tls->set_version(tls, TLS_SUPPORTED_MIN, TLS_SUPPORTED_MAX);

	/* Client must emit ClientHello first so input is interpreted as the server's reply */
	if (!is_server)
	{
		do
		{
			outlen = sizeof(out);
			status = tls->build(tls, out, &outlen, &msglen);
		}
		while (status == NEED_MORE);
	}

	status = tls->process(tls, (void*)buf, len);

	/* Drive build() naturally based on process() status */
	if (status == NEED_MORE)
	{
		do
		{
			outlen = sizeof(out);
			status = tls->build(tls, out, &outlen, &msglen);
		}
		while (status == NEED_MORE);
	}

	tls->destroy(tls);
	server_id->destroy(server_id);
	peer_id->destroy(peer_id);

	return 0;
}
