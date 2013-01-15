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

#include "pt_tls_server.h"
#include "pt_tls.h"

#include <utils/debug.h>

#include <tnc/tnc.h>

typedef struct private_pt_tls_server_t private_pt_tls_server_t;

/**
 * Private data of an pt_tls_server_t object.
 */
struct private_pt_tls_server_t {

	/**
	 * Public pt_tls_server_t interface.
	 */
	pt_tls_server_t public;

	/**
	 * TLS protected socket
	 */
	tls_socket_t *tls;

	enum {
		/* expecting version negotiation */
		PT_TLS_SERVER_VERSION,
		/* expecting an SASL exchange */
		PT_TLS_SERVER_AUTH,
		/* expecting TNCCS exchange */
		PT_TLS_SERVER_TNCCS,
		/* terminating state */
		PT_TLS_SERVER_END,
	} state;

	/**
	 * Message Identifier
	 */
	u_int32_t identifier;

	/**
	 * TNCCS protocol handler, implemented as tls_t
	 */
	tls_t *tnccs;
};

/**
 * Negotiate PT-TLS version
 */
static bool negotiate_version(private_pt_tls_server_t *this)
{
	bio_reader_t *reader;
	bio_writer_t *writer;
	u_int32_t vendor, type, identifier;
	u_int8_t reserved, vmin, vmax, vpref;

	reader = pt_tls_read(this->tls, &vendor, &type, &identifier);
	if (!reader)
	{
		return FALSE;
	}
	if (vendor != 0 || type != PT_TLS_VERSION_REQUEST ||
		!reader->read_uint8(reader, &reserved) ||
		!reader->read_uint8(reader, &vmin) ||
		!reader->read_uint8(reader, &vmax) ||
		!reader->read_uint8(reader, &vpref))
	{
		DBG1(DBG_TNC, "PT-TLS version negotiation failed");
		reader->destroy(reader);
		return FALSE;
	}
	reader->destroy(reader);

	if (vmin > PT_TLS_VERSION || vmax < PT_TLS_VERSION)
	{
		/* TODO: send error */
		return FALSE;
	}

	writer = bio_writer_create(4);
	writer->write_uint24(writer, 0);
	writer->write_uint8(writer, PT_TLS_VERSION);

	return pt_tls_write(this->tls, writer, PT_TLS_VERSION_RESPONSE,
						this->identifier++);
}

/**
 * Authenticated PT-TLS session with SASL
 */
static bool authenticate(private_pt_tls_server_t *this)
{
	bio_writer_t *writer;

	/* send empty SASL mechanims list to skip authentication */
	writer = bio_writer_create(0);
	return pt_tls_write(this->tls, writer, PT_TLS_SASL_MECHS,
						this->identifier++);
}

/**
 * Perform assessment
 */
static bool assess(private_pt_tls_server_t *this, tls_t *tnccs)
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

METHOD(pt_tls_server_t, handle, status_t,
	private_pt_tls_server_t *this)
{
	switch (this->state)
	{
		case PT_TLS_SERVER_VERSION:
			if (!negotiate_version(this))
			{
				return FAILED;
			}
			DBG1(DBG_TNC, "negotiated PT-TLS version %d", PT_TLS_VERSION);
			this->state = PT_TLS_SERVER_AUTH;
			break;
		case PT_TLS_SERVER_AUTH:
			DBG1(DBG_TNC, "sending empty mechanism list to skip SASL");
			if (!authenticate(this))
			{
				return FAILED;
			}
			this->state = PT_TLS_SERVER_TNCCS;
			this->tnccs = (tls_t*)tnc->tnccs->create_instance(tnc->tnccs,
															  TNCCS_2_0, TRUE);
			if (!this->tnccs)
			{
				return FAILED;
			}
			break;
		case PT_TLS_SERVER_TNCCS:
			if (!assess(this, (tls_t*)this->tnccs))
			{
				return FAILED;
			}
			this->state = PT_TLS_SERVER_END;
			return SUCCESS;
		default:
			return FAILED;
	}
	return NEED_MORE;
}

METHOD(pt_tls_server_t, get_fd, int,
	private_pt_tls_server_t *this)
{
	return this->tls->get_fd(this->tls);
}

METHOD(pt_tls_server_t, destroy, void,
	private_pt_tls_server_t *this)
{
	DESTROY_IF(this->tnccs);
	this->tls->destroy(this->tls);
	free(this);
}

/**
 * See header
 */
pt_tls_server_t *pt_tls_server_create(identification_t *server, int fd)
{
	private_pt_tls_server_t *this;

	INIT(this,
		.public = {
			.handle = _handle,
			.get_fd = _get_fd,
			.destroy = _destroy,
		},
		.state = PT_TLS_SERVER_VERSION,
		.tls = tls_socket_create(TRUE, server, NULL, fd, NULL),
	);

	if (!this->tls)
	{
		free(this);
		return NULL;
	}

	return &this->public;
}
