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

#include <sasl/sasl_mechanism.h>

#include <utils/debug.h>

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

	/**
	 * Client authentication requirements
	 */
	pt_tls_auth_t auth;

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
 * Process SASL data, send result
 */
static status_t process_sasl(private_pt_tls_server_t *this,
							 sasl_mechanism_t *sasl, chunk_t data)
{
	bio_writer_t *writer;

	switch (sasl->process(sasl, data))
	{
		case NEED_MORE:
			return NEED_MORE;
		case SUCCESS:
			DBG1(DBG_TNC, "SASL %s authentication successful",
				 sasl->get_name(sasl));
			writer = bio_writer_create(1);
			writer->write_uint8(writer, PT_TLS_SASL_RESULT_SUCCESS);
			if (pt_tls_write(this->tls, writer, PT_TLS_SASL_RESULT,
							 this->identifier++))
			{
				return SUCCESS;
			}
			return FAILED;
		case FAILED:
		default:
			DBG1(DBG_TNC, "SASL %s authentication failed",
				 sasl->get_name(sasl));
			writer = bio_writer_create(1);
			/* sending abort does not allow the client to retry */
			writer->write_uint8(writer, PT_TLS_SASL_RESULT_ABORT);
			pt_tls_write(this->tls, writer, PT_TLS_SASL_RESULT,
						 this->identifier++);
			return FAILED;
	}
}

/**
 * Read a SASL message and process it
 */
static status_t read_sasl(private_pt_tls_server_t *this,
						  sasl_mechanism_t *sasl)
{
	u_int32_t vendor, type, identifier;
	bio_reader_t *reader;
	status_t status;
	chunk_t data;

	reader = pt_tls_read(this->tls, &vendor, &type, &identifier);
	if (!reader)
	{
		return FAILED;
	}
	if (vendor != 0 || type != PT_TLS_SASL_AUTH_DATA ||
		!reader->read_data(reader, reader->remaining(reader), &data))
	{
		reader->destroy(reader);
		return FAILED;
	}
	status = process_sasl(this, sasl, data);
	reader->destroy(reader);
	return status;
}

/**
 * Build and write SASL message, or result message
 */
static status_t write_sasl(private_pt_tls_server_t *this,
						   sasl_mechanism_t *sasl)
{
	bio_writer_t *writer;
	chunk_t chunk;

	switch (sasl->build(sasl, &chunk))
	{
		case NEED_MORE:
			writer = bio_writer_create(chunk.len);
			writer->write_data(writer, chunk);
			free(chunk.ptr);
			if (pt_tls_write(this->tls, writer, PT_TLS_SASL_AUTH_DATA,
							 this->identifier++))
			{
				return NEED_MORE;
			}
			return FAILED;
		case SUCCESS:
			DBG1(DBG_TNC, "SASL %s authentication successful",
				 sasl->get_name(sasl));
			writer = bio_writer_create(1 + chunk.len);
			writer->write_uint8(writer, PT_TLS_SASL_RESULT_SUCCESS);
			writer->write_data(writer, chunk);
			free(chunk.ptr);
			if (pt_tls_write(this->tls, writer, PT_TLS_SASL_RESULT,
							 this->identifier++))
			{
				return SUCCESS;
			}
			return FAILED;
		case FAILED:
		default:
			DBG1(DBG_TNC, "SASL %s authentication failed",
				 sasl->get_name(sasl));
			writer = bio_writer_create(1);
			/* sending abort does not allow the client to retry */
			writer->write_uint8(writer, PT_TLS_SASL_RESULT_ABORT);
			pt_tls_write(this->tls, writer, PT_TLS_SASL_RESULT,
						 this->identifier++);
			return FAILED;
	}
}

/**
 * Send the list of supported SASL mechanisms
 */
static bool send_sasl_mechs(private_pt_tls_server_t *this)
{
	enumerator_t *enumerator;
	bio_writer_t *writer = NULL;
	char *name;

	enumerator = sasl_mechanism_create_enumerator(TRUE);
	while (enumerator->enumerate(enumerator, &name))
	{
		if (!writer)
		{
			writer = bio_writer_create(32);
		}
		DBG1(DBG_TNC, "offering SASL %s", name);
		writer->write_data8(writer, chunk_from_str(name));
	}
	enumerator->destroy(enumerator);

	if (!writer)
	{	/* no mechanisms available? */
		return FALSE;
	}
	return pt_tls_write(this->tls, writer, PT_TLS_SASL_MECHS,
						this->identifier++);
}

/**
 * Read the selected SASL mechanism, and process piggybacked data
 */
static status_t read_sasl_mech_selection(private_pt_tls_server_t *this,
										 sasl_mechanism_t **out)
{
	u_int32_t vendor, type, identifier;
	sasl_mechanism_t *sasl;
	bio_reader_t *reader;
	chunk_t chunk;
	u_int8_t len;
	char buf[21];

	reader = pt_tls_read(this->tls, &vendor, &type, &identifier);
	if (!reader)
	{
		return FAILED;
	}
	if (vendor != 0 || type != PT_TLS_SASL_MECH_SELECTION ||
		!reader->read_uint8(reader, &len) ||
		!reader->read_data(reader, len & 0x1F, &chunk))
	{
		reader->destroy(reader);
		return FAILED;
	}
	snprintf(buf, sizeof(buf), "%.*s", (int)chunk.len, chunk.ptr);

	DBG1(DBG_TNC, "client starts SASL %s authentication", buf);

	sasl = sasl_mechanism_create(buf, NULL);
	if (!sasl)
	{
		reader->destroy(reader);
		return FAILED;
	}
	/* initial SASL data piggybacked? */
	if (reader->remaining(reader))
	{
		switch (process_sasl(this, sasl, reader->peek(reader)))
		{
			case NEED_MORE:
				break;
			case SUCCESS:
				reader->destroy(reader);
				*out = sasl;
				return SUCCESS;
			case FAILED:
			default:
				reader->destroy(reader);
				sasl->destroy(sasl);
				return FAILED;
		}
	}
	reader->destroy(reader);
	*out = sasl;
	return NEED_MORE;
}

/**
 * Do a single SASL exchange
 */
static bool do_sasl(private_pt_tls_server_t *this)
{
	sasl_mechanism_t *sasl;
	status_t status;

	switch (this->auth)
	{
		case PT_TLS_AUTH_NONE:
			return TRUE;
		case PT_TLS_AUTH_TLS:
			if (this->tls->get_peer_id(this->tls))
			{
				return TRUE;
			}
			DBG1(DBG_TNC, "requiring TLS certificate client authentication");
			return FALSE;
		case PT_TLS_AUTH_SASL:
			break;
		case PT_TLS_AUTH_TLS_OR_SASL:
			if (this->tls->get_peer_id(this->tls))
			{
				DBG1(DBG_TNC, "skipping SASL, client authenticated with TLS "
					 "certificate");
				return TRUE;
			}
			break;
		case PT_TLS_AUTH_TLS_AND_SASL:
		default:
			if (!this->tls->get_peer_id(this->tls))
			{
				DBG1(DBG_TNC, "requiring TLS certificate client authentication");
				return FALSE;
			}
			break;
	}

	if (!send_sasl_mechs(this))
	{
		return FALSE;
	}
	status = read_sasl_mech_selection(this, &sasl);
	if (status == FAILED)
	{
		return FALSE;
	}
	while (status == NEED_MORE)
	{
		status = write_sasl(this, sasl);
		if (status == NEED_MORE)
		{
			status = read_sasl(this, sasl);
		}
	}
	sasl->destroy(sasl);
	return status == SUCCESS;
}

/**
 * Authenticated PT-TLS session with a single SASL method
 */
static bool authenticate(private_pt_tls_server_t *this)
{
	if (do_sasl(this))
	{
		/* complete SASL with emtpy mechanism list */
		bio_writer_t *writer;

		writer = bio_writer_create(0);
		return pt_tls_write(this->tls, writer, PT_TLS_SASL_MECHS,
							this->identifier++);
	}
	return FALSE;
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
			if (!authenticate(this))
			{
				return FAILED;
			}
			this->state = PT_TLS_SERVER_TNCCS;
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
	this->tnccs->destroy(this->tnccs);
	this->tls->destroy(this->tls);
	free(this);
}

/**
 * See header
 */
pt_tls_server_t *pt_tls_server_create(identification_t *server, int fd,
									  pt_tls_auth_t auth, tnccs_t *tnccs)
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
		.tnccs = (tls_t*)tnccs,
		.auth = auth,
	);

	if (!this->tls)
	{
		this->tnccs->destroy(this->tnccs);
		free(this);
		return NULL;
	}

	return &this->public;
}
