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

/**
 * @defgroup bio_writer bio_writer
 * @{ @ingroup bio
 */

#ifndef BIO_WRITER_H_
#define BIO_WRITER_H_

typedef struct bio_writer_t bio_writer_t;

#include <library.h>

/**
 * Buffered output generator.
 */
struct bio_writer_t {

	/**
	 * Append a 8-bit integer to the buffer.
	 *
	 * @param value		value to append
	 */
	void (*write_uint8)(bio_writer_t *this, u_int8_t value);

	/**
	 * Append a 16-bit integer to the buffer.
	 *
	 * @param value		value to append
	 */
	void (*write_uint16)(bio_writer_t *this, u_int16_t value);

	/**
	 * Append a 24-bit integer to the buffer.
	 *
	 * @param value		value to append
	 */
	void (*write_uint24)(bio_writer_t *this, u_int32_t value);

	/**
	 * Append a 32-bit integer to the buffer.
	 *
	 * @param value		value to append
	 */
	void (*write_uint32)(bio_writer_t *this, u_int32_t value);

	/**
	 * Append a 64-bit integer to the buffer.
	 *
	 * @param value		value to append
	 */
	void (*write_uint64)(bio_writer_t *this, u_int64_t value);

	/**
	 * Append a chunk of data without a length header.
	 *
	 * @param value		value to append
	 */
	void (*write_data)(bio_writer_t *this, chunk_t value);

	/**
	 * Append a chunk of data with a 8-bit length header.
	 *
	 * @param value		value to append
	 */
	void (*write_data8)(bio_writer_t *this, chunk_t value);

	/**
	 * Append a chunk of data with a 16-bit length header.
	 *
	 * @param value		value to append
	 */
	void (*write_data16)(bio_writer_t *this, chunk_t value);

	/**
	 * Append a chunk of data with a 24-bit length header.
	 *
	 * @param value		value to append
	 */
	void (*write_data24)(bio_writer_t *this, chunk_t value);

	/**
	 * Append a chunk of data with a 32-bit length header.
	 *
	 * @param value		value to append
	 */
	void (*write_data32)(bio_writer_t *this, chunk_t value);

	/**
	 * Prepend a 8-bit length header to existing data.
	 */
	void (*wrap8)(bio_writer_t *this);

	/**
	 * Prepend a 16-bit length header to existing data.
	 */
	void (*wrap16)(bio_writer_t *this);

	/**
	 * Prepend a 24-bit length header to existing data.
	 */
	void (*wrap24)(bio_writer_t *this);

	/**
	 * Prepend a 32-bit length header to existing data.
	 */
	void (*wrap32)(bio_writer_t *this);

	/**
	 * Get the encoded data buffer.
	 *
	 * @return			chunk to internal buffer
	 */
	chunk_t (*get_buf)(bio_writer_t *this);

	/**
	 * Destroy a bio_writer_t.
	 */
	void (*destroy)(bio_writer_t *this);
};

/**
 * Create a bio_writer instance.
 *
 * @param bufsize		initially allocated buffer size
 */
bio_writer_t *bio_writer_create(u_int32_t bufsize);

#endif /** BIO_WRITER_H_ @}*/
