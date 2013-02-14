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

#include "pt_tls.h"

#include <utils/debug.h>

/*
 * PT-TNC Message format:
 *                       1                   2                   3
 *   0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *  |    Reserved   |           Message Type Vendor ID              |
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *  |                          Message Type                         |
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *  |                         Message Length                        |
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *  |                       Message Identifier                      |
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *  |                Message Value (e.g. PB-TNC Batch) . . .        |
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 */

/**
 * Read a chunk of data from TLS, returning a reader for it
 */
static bio_reader_t* read_tls(tls_socket_t *tls, size_t len)
{
	ssize_t got, total = 0;
	char *buf;

	buf = malloc(len);
	while (total < len)
	{
		got = tls->read(tls, buf + total, len - total, TRUE);
		if (got <= 0)
		{
			free(buf);
			return NULL;
		}
		total += got;
	}
	return bio_reader_create_own(chunk_create(buf, len));
}

/**
 * Read a PT-TLS message, return header data
 */
bio_reader_t* pt_tls_read(tls_socket_t *tls, u_int32_t *vendor,
						  u_int32_t *type, u_int32_t *identifier)
{
	bio_reader_t *reader;
	u_int32_t len;
	u_int8_t reserved;

	reader = read_tls(tls, PT_TLS_HEADER_LEN);
	if (!reader)
	{
		return NULL;
	}
	if (!reader->read_uint8(reader, &reserved) ||
		!reader->read_uint24(reader, vendor) ||
		!reader->read_uint32(reader, type) ||
		!reader->read_uint32(reader, &len) ||
		!reader->read_uint32(reader, identifier))
	{
		reader->destroy(reader);
		return NULL;
	}
	reader->destroy(reader);

	if (len < PT_TLS_HEADER_LEN)
	{
		DBG1(DBG_TNC, "received short PT-TLS header (%d bytes)", len);
		return NULL;
	}
	return read_tls(tls, len - PT_TLS_HEADER_LEN);
}

/**
 * Prepend a PT-TLS header to a writer, send data, destroy writer
 */
bool pt_tls_write(tls_socket_t *tls, bio_writer_t *writer,
				  pt_tls_message_type_t type, u_int32_t identifier)
{
	bio_writer_t *header;
	ssize_t len;
	chunk_t data;

	data =  writer->get_buf(writer);
	len = PT_TLS_HEADER_LEN + data.len;
	header = bio_writer_create(len);
	header->write_uint8(header, 0);
	header->write_uint24(header, 0);
	header->write_uint32(header, type);
	header->write_uint32(header, len);
	header->write_uint32(header, identifier);

	header->write_data(header, data);
	writer->destroy(writer);

	data = header->get_buf(header);
	len = tls->write(tls, data.ptr, data.len);
	header->destroy(header);

	return len == data.len;
}
