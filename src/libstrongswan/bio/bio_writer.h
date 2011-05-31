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
 * @defgroup tls_writer tls_writer
 * @{ @ingroup libtls
 */

#ifndef TLS_WRITER_H_
#define TLS_WRITER_H_

typedef struct tls_writer_t tls_writer_t;

#include <library.h>

/**
 * TLS record generator.
 */
struct tls_writer_t {

	/**
	 * Append a 8-bit integer to the buffer.
	 *
	 * @param value		value to append
	 */
	void (*write_uint8)(tls_writer_t *this, u_int8_t value);

	/**
	 * Append a 16-bit integer to the buffer.
	 *
	 * @param value		value to append
	 */
	void (*write_uint16)(tls_writer_t *this, u_int16_t value);

	/**
	 * Append a 24-bit integer to the buffer.
	 *
	 * @param value		value to append
	 */
	void (*write_uint24)(tls_writer_t *this, u_int32_t value);

	/**
	 * Append a 32-bit integer to the buffer.
	 *
	 * @param value		value to append
	 */
	void (*write_uint32)(tls_writer_t *this, u_int32_t value);

	/**
	 * Append a chunk of data without a length header.
	 *
	 * @param value		value to append
	 */
	void (*write_data)(tls_writer_t *this, chunk_t value);

	/**
	 * Append a chunk of data with a 8-bit length header.
	 *
	 * @param value		value to append
	 */
	void (*write_data8)(tls_writer_t *this, chunk_t value);

	/**
	 * Append a chunk of data with a 16-bit length header.
	 *
	 * @param value		value to append
	 */
	void (*write_data16)(tls_writer_t *this, chunk_t value);

	/**
	 * Append a chunk of data with a 24-bit length header.
	 *
	 * @param value		value to append
	 */
	void (*write_data24)(tls_writer_t *this, chunk_t value);

	/**
	 * Append a chunk of data with a 32-bit length header.
	 *
	 * @param value		value to append
	 */
	void (*write_data32)(tls_writer_t *this, chunk_t value);

	/**
	 * Prepend a 8-bit length header to existing data.
	 */
	void (*wrap8)(tls_writer_t *this);

	/**
	 * Prepend a 16-bit length header to existing data.
	 */
	void (*wrap16)(tls_writer_t *this);

	/**
	 * Prepend a 24-bit length header to existing data.
	 */
	void (*wrap24)(tls_writer_t *this);

	/**
	 * Prepend a 32-bit length header to existing data.
	 */
	void (*wrap32)(tls_writer_t *this);

	/**
	 * Get the encoded data buffer.
	 *
	 * @return			chunk to internal buffer
	 */
	chunk_t (*get_buf)(tls_writer_t *this);

	/**
	 * Destroy a tls_writer_t.
	 */
	void (*destroy)(tls_writer_t *this);
};

/**
 * Create a tls_writer instance.
 *
 * @param bufsize		initially allocated buffer size
 */
tls_writer_t *tls_writer_create(u_int32_t bufsize);

#endif /** TLS_WRITER_H_ @}*/
