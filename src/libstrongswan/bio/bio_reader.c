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

#include "bio_reader.h"

#include <debug.h>

typedef struct private_bio_reader_t private_bio_reader_t;

/**
 * Private data of an bio_reader_t object.
 */
struct private_bio_reader_t {

	/**
	 * Public bio_reader_t interface.
	 */
	bio_reader_t public;

	/**
	 * Remaining data to process
	 */
	chunk_t buf;
};

METHOD(bio_reader_t, remaining, u_int32_t,
	private_bio_reader_t *this)
{
	return this->buf.len;
}

METHOD(bio_reader_t, peek, chunk_t,
	private_bio_reader_t *this)
{
	return this->buf;
}

METHOD(bio_reader_t, read_uint8, bool,
	private_bio_reader_t *this, u_int8_t *res)
{
	if (this->buf.len < 1)
	{
		DBG1(DBG_LIB, "%d bytes insufficient to parse u_int8 data",
			 this->buf.len);
		return FALSE;
	}
	*res = this->buf.ptr[0];
	this->buf = chunk_skip(this->buf, 1);
	return TRUE;
}

METHOD(bio_reader_t, read_uint16, bool,
	private_bio_reader_t *this, u_int16_t *res)
{
	if (this->buf.len < 2)
	{
		DBG1(DBG_LIB, "%d bytes insufficient to parse u_int16 data",
			 this->buf.len);
		return FALSE;
	}
	*res = untoh16(this->buf.ptr);
	this->buf = chunk_skip(this->buf, 2);
	return TRUE;
}

METHOD(bio_reader_t, read_uint24, bool,
	private_bio_reader_t *this, u_int32_t *res)
{
	if (this->buf.len < 3)
	{
		DBG1(DBG_LIB, "%d bytes insufficient to parse u_int24 data",
			 this->buf.len);
		return FALSE;
	}
	*res = untoh32(this->buf.ptr) >> 8;
	this->buf = chunk_skip(this->buf, 3);
	return TRUE;
}

METHOD(bio_reader_t, read_uint32, bool,
	private_bio_reader_t *this, u_int32_t *res)
{
	if (this->buf.len < 4)
	{
		DBG1(DBG_LIB, "%d bytes insufficient to parse u_int32 data",
			 this->buf.len);
		return FALSE;
	}
	*res = untoh32(this->buf.ptr);
	this->buf = chunk_skip(this->buf, 4);
	return TRUE;
}

METHOD(bio_reader_t, read_uint64, bool,
	private_bio_reader_t *this, u_int64_t *res)
{
	if (this->buf.len < 8)
	{
		DBG1(DBG_LIB, "%d bytes insufficient to parse u_int64 data",
			 this->buf.len);
		return FALSE;
	}
	*res = untoh64(this->buf.ptr);
	this->buf = chunk_skip(this->buf, 8);
	return TRUE;
}

METHOD(bio_reader_t, read_data, bool,
	private_bio_reader_t *this, u_int32_t len, chunk_t *res)
{
	if (this->buf.len < len)
	{
		DBG1(DBG_LIB, "%d bytes insufficient to parse %d bytes of data",
			 this->buf.len, len);
		return FALSE;
	}
	*res = chunk_create(this->buf.ptr, len);
	this->buf = chunk_skip(this->buf, len);
	return TRUE;
}

METHOD(bio_reader_t, read_data8, bool,
	private_bio_reader_t *this, chunk_t *res)
{
	u_int8_t len;

	if (!read_uint8(this, &len))
	{
		return FALSE;
	}
	return read_data(this, len, res);
}

METHOD(bio_reader_t, read_data16, bool,
	private_bio_reader_t *this, chunk_t *res)
{
	u_int16_t len;

	if (!read_uint16(this, &len))
	{
		return FALSE;
	}
	return read_data(this, len, res);
}

METHOD(bio_reader_t, read_data24, bool,
	private_bio_reader_t *this, chunk_t *res)
{
	u_int32_t len;

	if (!read_uint24(this, &len))
	{
		return FALSE;
	}
	return read_data(this, len, res);
}

METHOD(bio_reader_t, read_data32, bool,
	private_bio_reader_t *this, chunk_t *res)
{
	u_int32_t len;

	if (!read_uint32(this, &len))
	{
		return FALSE;
	}
	return read_data(this, len, res);
}

METHOD(bio_reader_t, destroy, void,
	private_bio_reader_t *this)
{
	free(this);
}

/**
 * See header
 */
bio_reader_t *bio_reader_create(chunk_t data)
{
	private_bio_reader_t *this;

	INIT(this,
		.public = {
			.remaining = _remaining,
			.peek = _peek,
			.read_uint8 = _read_uint8,
			.read_uint16 = _read_uint16,
			.read_uint24 = _read_uint24,
			.read_uint32 = _read_uint32,
			.read_uint64 = _read_uint64,
			.read_data = _read_data,
			.read_data8 = _read_data8,
			.read_data16 = _read_data16,
			.read_data24 = _read_data24,
			.read_data32 = _read_data32,
			.destroy = _destroy,
		},
		.buf = data,
	);

	return &this->public;
}
