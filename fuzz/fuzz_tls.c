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
#include <credentials/sets/mem_cred.h>

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
	plugin_loader_add_plugindirs(PLUGINDIR, PLUGINS);
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

	/* Minimum TLS record header: 1 byte type + 2 bytes version + 2 bytes length */
	if (len < 5)
	{
		return 0;
	}

	/* Use first byte to determine test mode */
	bool is_server = (buf[0] & 0x01) != 0;
	bool test_build = (buf[0] & 0x02) != 0;

	/* Skip mode byte for actual TLS data */
	buf++;
	len--;

	/* Create identities */
	server_id = identification_create_from_string("server.test");
	peer_id = identification_create_from_string("peer.test");
	if (!server_id || !peer_id)
	{
		DESTROY_IF(server_id);
		DESTROY_IF(peer_id);
		return 0;
	}

	/* Create TLS application stub */
	app = create_tls_application();
	if (!app)
	{
		server_id->destroy(server_id);
		peer_id->destroy(peer_id);
		return 0;
	}

	/* Create TLS instance - test both server and peer modes */
	tls = tls_create(is_server, server_id, peer_id, TLS_PURPOSE_GENERIC,
					 app, NULL, TLS_FLAG_ENCRYPTION_OPTIONAL);
	if (!tls)
	{
		app->destroy(app);
		server_id->destroy(server_id);
		peer_id->destroy(peer_id);
		return 0;
	}

	/* Fuzz TLS record processing - the main attack surface */
	status = tls->process(tls, (void*)buf, len);

	/* Optionally test build path if status allows and flag is set */
	if (test_build && status == NEED_MORE)
	{
		chunk_t out = chunk_empty;
		/* Try to build response, ignore failures */
		tls->build(tls, &out.ptr, &out.len, NULL);
		chunk_free(&out);
	}

	/* Cleanup */
	tls->destroy(tls);
	server_id->destroy(server_id);
	peer_id->destroy(peer_id);

	return 0;
}
