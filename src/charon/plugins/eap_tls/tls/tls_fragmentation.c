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

#include <daemon.h>

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
 * TLS handshake message header
 */
typedef union  {
	u_int8_t type;
	/* 24bit length field */
	u_int32_t length;
} tls_handshake_header_t;

/**
 * Process TLS handshake protocol data
 */
static status_t process_handshake(private_tls_fragmentation_t *this,
								  chunk_t data)
{
	while (data.len)
	{
		u_int32_t len;
		status_t status;
		tls_handshake_header_t *hdr;

		if (data.len == 0 || data.len > MAX_TLS_FRAGMENT_LEN)
		{
			DBG1(DBG_IKE, "TLS fragment has invalid length");
			return FAILED;
		}

		if (this->input.len == 0)
		{	/* new handshake message */
			if (data.len < sizeof(tls_handshake_header_t))
			{
				DBG1(DBG_IKE, "initial TLS fragment too short %B", &data);
				return FAILED;
			}
			hdr = (tls_handshake_header_t*)data.ptr;
			len = untoh32(&hdr->length) & 0x00FFFFFF;
			this->type = hdr->type;
			if (len > MAX_TLS_HANDSHAKE_LEN)
			{
				DBG1(DBG_IKE, "TLS handshake message exceeds maximum length");
				return FAILED;
			}
			this->input = len ? chunk_alloc(len) : chunk_empty;
			this->inpos = 0;
			data = chunk_skip(data, sizeof(tls_handshake_header_t));
		}

		len = min(this->input.len - this->inpos, data.len);
		memcpy(this->input.ptr + this->inpos, data.ptr, len);
		this->inpos += len;
		data = chunk_skip(data, len);

		if (this->input.len == this->inpos)
		{	/* message completely defragmented, process */
			status = this->handshake->process(this->handshake,
											  this->type, this->input);
			chunk_free(&this->input);
			if (status != NEED_MORE)
			{
				return status;
			}
		}
	}
	return NEED_MORE;
}

METHOD(tls_fragmentation_t, process, status_t,
	private_tls_fragmentation_t *this, tls_content_type_t type, chunk_t data)
{
	switch (type)
	{
		case TLS_CHANGE_CIPHER_SPEC:
			/* TODO: handle ChangeCipherSpec */
			return FAILED;
		case TLS_ALERT:
			/* TODO: handle Alert */
			return FAILED;
		case TLS_HANDSHAKE:
			return process_handshake(this, data);
		case TLS_APPLICATION_DATA:
			/* skip application data */
			return NEED_MORE;
		default:
			DBG1(DBG_IKE, "received unknown TLS content type %d, ignored", type);
			return NEED_MORE;
	}
}

METHOD(tls_fragmentation_t, build, status_t,
	private_tls_fragmentation_t *this, tls_content_type_t *type, chunk_t *data)
{
	tls_handshake_header_t header;
	tls_handshake_type_t hs_type;
	chunk_t hs_data;
	status_t status;

	status = this->handshake->build(this->handshake, &hs_type, &hs_data);
	if (status != NEED_MORE)
	{
		return status;
	}
	htoun32(&header.length, hs_data.len);
	header.type |= hs_type;
	*data = chunk_cat("cm", chunk_from_thing(header), hs_data);
	*type = TLS_HANDSHAKE;
	return NEED_MORE;
}

METHOD(tls_fragmentation_t, destroy, void,
	private_tls_fragmentation_t *this)
{
	free(this->input.ptr);
	free(this);
}

/**
 * See header
 */
tls_fragmentation_t *tls_fragmentation_create(tls_handshake_t *handshake)
{
	private_tls_fragmentation_t *this;

	INIT(this,
		.public = {
			.process = _process,
			.build = _build,
			.destroy = _destroy,
		},
		.handshake = handshake,
	);

	return &this->public;
}
