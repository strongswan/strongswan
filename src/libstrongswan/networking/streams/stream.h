/*
 * Copyright (C) 2013 Martin Willi
 * Copyright (C) 2013 revosec AG
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
 * @defgroup stream stream
 * @{ @ingroup streams
 */

#ifndef STREAM_H_
#define STREAM_H_

typedef struct stream_t stream_t;

#include <library.h>

/**
 * Constructor function prototype for stream_t.
 *
 * @param uri			URI to create a stream for
 * @return				stream instance, NULL on error
 */
typedef stream_t*(*stream_constructor_t)(char *uri);

/**
 * Abstraction of a Berkley socket using stream semantics.
 */
struct stream_t {

	/**
	 * Read data from the stream.
	 *
	 * If "block" is FALSE and no data is available, the function returns -1
	 * and sets errno to EWOULDBLOCK.
	 *
	 * @param buf		data buffer to read into
	 * @param len		number of bytes to read
	 * @param block		TRUE to use a blocking read
	 * @return			number of bytes read, -1 on error
	 */
	ssize_t (*read)(stream_t *this, void *buf, size_t len, bool block);

	/**
	 * Write data to the stream.
	 *
	 * If "block" is FALSE and the write would block, the function returns -1
	 * and sets errno to EWOULDBLOCK.
	 *
	 * @param buf		data buffer to write
	 * @param len		number of bytes to write
	 * @param block		TRUE to use a blocking write
	 * @return			number of bytes written, -1 on error
	 */
	ssize_t (*write)(stream_t *this, void *buf, size_t len, bool block);

	/**
	 * Destroy a stream_t.
	 */
	void (*destroy)(stream_t *this);
};

/**
 * Create a stream from a file descriptor.
 *
 * The file descriptor MUST be a socket for non-blocking operation.
 *
 * @param fd		file descriptor to wrap into a stream_t
 * @return			stream instance
 */
stream_t *stream_create_from_fd(int fd);

#endif /** STREAM_H_ @}*/
