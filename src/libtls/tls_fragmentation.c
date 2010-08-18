/*
 * Copyright (C) 2010 Martin Willi
 * Copyright (C) 2010 revosec AG
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

#include "tls_fragmentation.h"

#include "tls_reader.h"

#include <debug.h>

typedef struct private_tls_fragmentation_t private_tls_fragmentation_t;

/**
 * Private data of an tls_fragmentation_t object.
 */
struct private_tls_fragmentation_t {

	/**
	 * Public tls_fragmentation_t interface.
	 */
	tls_fragmentation_t public;

	/**
	 * Upper layer handshake protocol
	 */
	tls_handshake_t *handshake;

	/**
	 * Handshake input buffer
	 */
	chunk_t input;

	/**
	 * Position in input buffer
	 */
	size_t inpos;

	/**
	 * Currently processed handshake message type
	 */
	tls_handshake_type_t type;

	/**
	 * Handshake output buffer
	 */
	chunk_t output;

	/**
	 * Upper layer application data protocol
	 */
	tls_application_t *application;
};

/**
 * Maximum size of a TLS fragment
 */
#define MAX_TLS_FRAGMENT_LEN 16384

/**
 * Maximum size of a TLS handshake message we accept
 */
#define MAX_TLS_HANDSHAKE_LEN 65536

/**
 * Process TLS handshake protocol data
 */
static status_t process_handshake(private_tls_fragmentation_t *this,
								  tls_reader_t *reader)
{
	while (reader->remaining(reader))
	{
		tls_reader_t *msg;
		u_int8_t type;
		u_int32_t len;
		status_t status;
		chunk_t data;

		if (reader->remaining(reader) > MAX_TLS_FRAGMENT_LEN)
		{
			DBG1(DBG_IKE, "TLS fragment has invalid length");
			return FAILED;
		}

		if (this->input.len == 0)
		{	/* new handshake message */
			if (!reader->read_uint8(reader, &type) ||
				!reader->read_uint24(reader, &len))
			{
				return FAILED;
			}
			this->type = type;
			if (len > MAX_TLS_HANDSHAKE_LEN)
			{
				DBG1(DBG_IKE, "TLS handshake message exceeds maximum length");
				return FAILED;
			}
			chunk_free(&this->input);
			this->inpos = 0;
			if (len)
			{
				this->input = chunk_alloc(len);
			}
		}

		len = min(this->input.len - this->inpos, reader->remaining(reader));
		if (!reader->read_data(reader, len, &data))
		{
			return FAILED;
		}
		memcpy(this->input.ptr + this->inpos, data.ptr, len);
		this->inpos += len;

		if (this->input.len == this->inpos)
		{	/* message completely defragmented, process */
			msg = tls_reader_create(this->input);
			DBG2(DBG_IKE, "received TLS %N message (%u bytes)",
				 tls_handshake_type_names, this->type, 4 + this->input.len);
			status = this->handshake->process(this->handshake, this->type, msg);
			msg->destroy(msg);
			chunk_free(&this->input);
			if (status != NEED_MORE)
			{
				return status;
			}
		}
	}
	return NEED_MORE;
}

/**
 * Process TLS application data
 */
static status_t process_application(private_tls_fragmentation_t *this,
									tls_reader_t *reader)
{
	while (reader->remaining(reader))
	{
		status_t status;

		if (reader->remaining(reader) > MAX_TLS_FRAGMENT_LEN)
		{
			DBG1(DBG_IKE, "TLS fragment has invalid length");
			return FAILED;
		}
		DBG2(DBG_IKE, "received TLS application data");
		status = this->application->process(this->application, reader);
		if (status != NEED_MORE)
		{
			return status;
		}
	}
	return NEED_MORE;
}

METHOD(tls_fragmentation_t, process, status_t,
	private_tls_fragmentation_t *this, tls_content_type_t type, chunk_t data)
{
	tls_reader_t *reader;
	status_t status;

	reader = tls_reader_create(data);
	switch (type)
	{
		case TLS_CHANGE_CIPHER_SPEC:
			if (this->handshake->change_cipherspec(this->handshake))
			{
				status = NEED_MORE;
				break;
			}
			status = FAILED;
			break;
		case TLS_ALERT:
			/* TODO: handle Alert */
			status = FAILED;
			break;
		case TLS_HANDSHAKE:
			status = process_handshake(this, reader);
			break;
		case TLS_APPLICATION_DATA:
			status = process_application(this, reader);
			break;
		default:
			DBG1(DBG_IKE, "received unknown TLS content type %d, ignored", type);
			status = NEED_MORE;
			break;
	}
	reader->destroy(reader);
	return status;
}

METHOD(tls_fragmentation_t, build, status_t,
	private_tls_fragmentation_t *this, tls_content_type_t *type, chunk_t *data)
{
	chunk_t hs_data;
	tls_handshake_type_t hs_type;
	tls_writer_t *writer, *msg;
	status_t status = INVALID_STATE;

	if (this->handshake->cipherspec_changed(this->handshake))
	{
		*type = TLS_CHANGE_CIPHER_SPEC;
		*data = chunk_clone(chunk_from_chars(0x01));
		return NEED_MORE;
	}

	if (!this->output.len)
	{
		msg = tls_writer_create(64);

		if (this->handshake->finished(this->handshake))
		{
			if (this->application)
			{
				status = this->application->build(this->application, msg);
				if (status == INVALID_STATE)
				{
					*type = TLS_APPLICATION_DATA;
					this->output = chunk_clone(msg->get_buf(msg));
					if (this->output.len)
					{
						DBG2(DBG_IKE, "sending TLS application data");
					}
				}
			}
		}
		else
		{
			do
			{
				writer = tls_writer_create(64);
				status = this->handshake->build(this->handshake, &hs_type, writer);
				switch (status)
				{
					case NEED_MORE:
						hs_data = writer->get_buf(writer);
						msg->write_uint8(msg, hs_type);
						msg->write_data24(msg, hs_data);
						DBG2(DBG_IKE, "sending TLS %N message (%u bytes)",
							 tls_handshake_type_names, hs_type, 4 + hs_data.len);
						break;
					case INVALID_STATE:
						*type = TLS_HANDSHAKE;
						this->output = chunk_clone(msg->get_buf(msg));
						break;
					default:
						break;
				}
				writer->destroy(writer);
			}
			while (status == NEED_MORE);
		}

		msg->destroy(msg);
		if (status != INVALID_STATE)
		{
			return status;
		}
	}

	if (this->output.len)
	{
		if (this->output.len <= MAX_TLS_FRAGMENT_LEN)
		{
			*data = this->output;
			this->output = chunk_empty;
			return NEED_MORE;
		}
		*data = chunk_create(this->output.ptr, MAX_TLS_FRAGMENT_LEN);
		this->output = chunk_clone(chunk_skip(this->output, MAX_TLS_FRAGMENT_LEN));
		return NEED_MORE;
	}
	return status;
}

METHOD(tls_fragmentation_t, destroy, void,
	private_tls_fragmentation_t *this)
{
	free(this->input.ptr);
	free(this->output.ptr);
	free(this);
}

/**
 * See header
 */
tls_fragmentation_t *tls_fragmentation_create(tls_handshake_t *handshake,
											  tls_application_t *application)
{
	private_tls_fragmentation_t *this;

	INIT(this,
		.public = {
			.process = _process,
			.build = _build,
			.destroy = _destroy,
		},
		.handshake = handshake,
		.application = application,
	);

	return &this->public;
}
