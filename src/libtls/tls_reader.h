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
 * @defgroup tls_reader tls_reader
 * @{ @ingroup libtls
 */

#ifndef TLS_READER_H_
#define TLS_READER_H_

typedef struct tls_reader_t tls_reader_t;

#include <library.h>

/**
 * TLS record parser.
 */
struct tls_reader_t {

	/**
	 * Get the number of remaining bytes.
	 *
	 * @return			number of remaining bytes in buffer
	 */
	u_int32_t (*remaining)(tls_reader_t *this);

	/**
	 * Peek the remaining data, not consuming any bytes.
	 *
	 * @return			remaining data
	 */
	chunk_t (*peek)(tls_reader_t *this);

	/**
	 * Read a 8-bit integer from the buffer, advance.
	 *
	 * @param res		pointer to result
	 * @return			TRUE if integer read successfully
	 */
	bool (*read_uint8)(tls_reader_t *this, u_int8_t *res);

	/**
	 * Read a 16-bit integer from the buffer, advance.
	 *
	 * @param res		pointer to result
	 * @return			TRUE if integer read successfully
	 */
	bool (*read_uint16)(tls_reader_t *this, u_int16_t *res);

	/**
	 * Read a 24-bit integer from the buffer, advance.
	 *
	 * @param res		pointer to result
	 * @return			TRUE if integer read successfully
	 */
	bool (*read_uint24)(tls_reader_t *this, u_int32_t *res);

	/**
	 * Read a 32-bit integer from the buffer, advance.
	 *
	 * @param res		pointer to result
	 * @return			TRUE if integer read successfully
	 */
	bool (*read_uint32)(tls_reader_t *this, u_int32_t *res);

	/**
	 * Read a chunk of len bytes, advance.
	 *
	 * @param len		number of bytes to read
	 * @param res		pointer to result, not cloned
	 * @return			TRUE if data read successfully
	 */
	bool (*read_data)(tls_reader_t *this, u_int32_t len, chunk_t *res);

	/**
	 * Read a chunk of bytes with a 8-bit length header, advance.
	 *
	 * @param res		pointer to result, not cloned
	 * @return			TRUE if data read successfully
	 */
	bool (*read_data8)(tls_reader_t *this, chunk_t *res);

	/**
	 * Read a chunk of bytes with a 16-bit length header, advance.
	 *
	 * @param res		pointer to result, not cloned
	 * @return			TRUE if data read successfully
	 */
	bool (*read_data16)(tls_reader_t *this, chunk_t *res);

	/**
	 * Read a chunk of bytes with a 24-bit length header, advance.
	 *
	 * @param res		pointer to result, not cloned
	 * @return			TRUE if data read successfully
	 */
	bool (*read_data24)(tls_reader_t *this, chunk_t *res);

	/**
	 * Read a chunk of bytes with a 32-bit length header, advance.
	 *
	 * @param res		pointer to result, not cloned
	 * @return			TRUE if data read successfully
	 */
	bool (*read_data32)(tls_reader_t *this, chunk_t *res);

	/**
	 * Destroy a tls_reader_t.
	 */
	void (*destroy)(tls_reader_t *this);
};

/**
 * Create a tls_reader instance.
 */
tls_reader_t *tls_reader_create(chunk_t data);

#endif /** tls_reader_H_ @}*/
