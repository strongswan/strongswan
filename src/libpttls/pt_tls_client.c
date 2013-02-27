/*
 * Copyright (C) 2012 Martin Willi
 * Copyright (C) 2012 revosec AG
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

#include "pt_tls_client.h"
#include "pt_tls.h"

#include <tls_socket.h>
#include <utils/debug.h>

#include <errno.h>
#include <stdio.h>
#include <unistd.h>

typedef struct private_pt_tls_client_t private_pt_tls_client_t;

/**
 * Private data of an pt_tls_client_t object.
 */
struct private_pt_tls_client_t {

	/**
	 * Public pt_tls_client_t interface.
	 */
	pt_tls_client_t public;

	/**
	 * TLS secured socket used by PT-TLS
	 */
	tls_socket_t *tls;

	/**
	 * Server address/port
	 */
	host_t *address;

	/**
	 * Server identity
	 */
	identification_t *server;

	/**
	 * Client authentication identity
	 */
	identification_t *client;

	/**
	 * Current PT-TLS message identifier
	 */
	u_int32_t identifier;
};

/**
 * Establish TLS secured TCP connection to TNC server
 */
static bool make_connection(private_pt_tls_client_t *this)
{
	int fd;

	fd = socket(this->address->get_family(this->address), SOCK_STREAM, 0);
	if (fd == -1)
	{
		DBG1(DBG_TNC, "opening PT-TLS socket failed: %s", strerror(errno));
		return FALSE;
	}
	if (connect(fd, this->address->get_sockaddr(this->address),
				*this->address->get_sockaddr_len(this->address)) == -1)
	{
		DBG1(DBG_TNC, "connecting to PT-TLS server failed: %s", strerror(errno));
		close(fd);
		return FALSE;
	}

	this->tls = tls_socket_create(FALSE, this->server, this->client, fd, NULL);
	if (!this->tls)
	{
		close(fd);
		return FALSE;
	}
	return TRUE;
}

/**
 * Negotiate PT-TLS version
 */
static bool negotiate_version(private_pt_tls_client_t *this)
{
	bio_writer_t *writer;
	bio_reader_t *reader;
	u_int32_t type, vendor, identifier, reserved;
	u_int8_t version;

	DBG1(DBG_TNC, "sending offer for PT-TLS version %d", PT_TLS_VERSION);

	writer = bio_writer_create(4);
	writer->write_uint8(writer, 0);
	writer->write_uint8(writer, PT_TLS_VERSION);
	writer->write_uint8(writer, PT_TLS_VERSION);
	writer->write_uint8(writer, PT_TLS_VERSION);
	if (!pt_tls_write(this->tls, writer, PT_TLS_VERSION_REQUEST,
					  this->identifier++))
	{
		return FALSE;
	}

	reader = pt_tls_read(this->tls, &vendor, &type, &identifier);
	if (!reader)
	{
		return FALSE;
	}
	if (vendor != 0 || type != PT_TLS_VERSION_RESPONSE ||
		!reader->read_uint24(reader, &reserved) ||
		!reader->read_uint8(reader, &version) ||
		version != PT_TLS_VERSION)
	{
		DBG1(DBG_TNC, "PT-TLS version negotiation failed");
		reader->destroy(reader);
		return FALSE;
	}
	reader->destroy(reader);
	return TRUE;
}

/**
 * Authenticate session using SASL
 */
static bool authenticate(private_pt_tls_client_t *this)
{
	bio_reader_t *reader;
	u_int32_t type, vendor, identifier;

	reader = pt_tls_read(this->tls, &vendor, &type, &identifier);
	if (!reader)
	{
		return FALSE;
	}
	if (vendor != 0 || type != PT_TLS_SASL_MECHS)
	{
		DBG1(DBG_TNC, "PT-TLS authentication failed");
		reader->destroy(reader);
		return FALSE;
	}

	if (reader->remaining(reader))
	{	/* mechanism list not empty, FAIL until we support it */
		reader->destroy(reader);
		return FALSE;
	}
	DBG1(DBG_TNC, "PT-TLS authentication complete");
	reader->destroy(reader);
	return TRUE;
}

/**
 * Perform assessment
 */
static bool assess(private_pt_tls_client_t *this, tls_t *tnccs)
{
	while (TRUE)
	{
		bio_writer_t *writer;
		bio_reader_t *reader;
		u_int32_t vendor, type, identifier;
		chunk_t data;

		writer = bio_writer_create(32);
		while (TRUE)
		{
			char buf[2048];
			size_t buflen, msglen;

			buflen = sizeof(buf);
			switch (tnccs->build(tnccs, buf, &buflen, &msglen))
			{
				case SUCCESS:
					writer->destroy(writer);
					return tnccs->is_complete(tnccs);
				case FAILED:
				default:
					writer->destroy(writer);
					return FALSE;
				case INVALID_STATE:
					writer->destroy(writer);
					break;
				case NEED_MORE:
					writer->write_data(writer, chunk_create(buf, buflen));
					continue;
				case ALREADY_DONE:
					writer->write_data(writer, chunk_create(buf, buflen));
					if (!pt_tls_write(this->tls, writer, PT_TLS_PB_TNC_BATCH,
									  this->identifier++))
					{
						return FALSE;
					}
					writer = bio_writer_create(32);
					continue;
			}
			break;
		}

		reader = pt_tls_read(this->tls, &vendor, &type, &identifier);
		if (!reader)
		{
			return FALSE;
		}
		if (vendor == 0)
		{
			if (type == PT_TLS_ERROR)
			{
				DBG1(DBG_TNC, "received PT-TLS error");
				reader->destroy(reader);
				return FALSE;
			}
			if (type != PT_TLS_PB_TNC_BATCH)
			{
				DBG1(DBG_TNC, "unexpected PT-TLS message: %d", type);
				reader->destroy(reader);
				return FALSE;
			}
			data = reader->peek(reader);
			switch (tnccs->process(tnccs, data.ptr, data.len))
			{
				case SUCCESS:
					reader->destroy(reader);
					return tnccs->is_complete(tnccs);
				case FAILED:
				default:
					reader->destroy(reader);
					return FALSE;
				case NEED_MORE:
					break;
			}
		}
		else
		{
			DBG1(DBG_TNC, "ignoring vendor specific PT-TLS message");
		}
		reader->destroy(reader);
	}
}

METHOD(pt_tls_client_t, run_assessment, status_t,
	private_pt_tls_client_t *this, tnccs_t *tnccs)
{
	if (!this->tls)
	{
		if (!make_connection(this))
		{
			return FAILED;
		}
	}
	if (!negotiate_version(this))
	{
		return FAILED;
	}
	if (!authenticate(this))
	{
		return FAILED;
	}
	if (!assess(this, (tls_t*)tnccs))
	{
		return FAILED;
	}
	return SUCCESS;
}


METHOD(pt_tls_client_t, destroy, void,
	private_pt_tls_client_t *this)
{
	if (this->tls)
	{
		int fd;

		fd = this->tls->get_fd(this->tls);
		this->tls->destroy(this->tls);
		close(fd);
	}
	this->address->destroy(this->address);
	this->server->destroy(this->server);
	this->client->destroy(this->client);
	free(this);
}

/**
 * See header
 */
pt_tls_client_t *pt_tls_client_create(host_t *address, identification_t *server,
									  identification_t *client)
{
	private_pt_tls_client_t *this;

	INIT(this,
		.public = {
			.run_assessment = _run_assessment,
			.destroy = _destroy,
		},
		.address = address,
		.server = server,
		.client = client,
	);

	return &this->public;
}
