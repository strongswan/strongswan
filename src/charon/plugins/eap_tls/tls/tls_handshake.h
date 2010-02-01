/*
 * Copyright (C) 2010 Martin Willi
 * Hochschule fuer Technik Rapperswil
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
 * @defgroup tls_handshake tls_handshake
 * @{ @ingroup tls
 */

#ifndef TLS_HANDSHAKE_H_
#define TLS_HANDSHAKE_H_

typedef struct tls_handshake_t tls_handshake_t;

#include "tls.h"
#include "tls_reader.h"
#include "tls_writer.h"

/**
 * TLS handshake state machine interface.
 */
struct tls_handshake_t {

	/**
	 * Process received TLS handshake message.
	 *
	 * @param type		TLS handshake message type
	 * @param reader	TLS data buffer
	 * @return
	 *					- SUCCESS if handshake complete
	 *					- FAILED if handshake failed
	 *					- NEED_MORE if another invocation of process/build needed
	 */
	status_t (*process)(tls_handshake_t *this,
						tls_handshake_type_t type, tls_reader_t *reader);

	/**
	 * Build TLS handshake messages to send out.
	 *
	 * @param type		type of created handshake message
	 * @param writer	TLS data buffer to write to
	 * @return
	 *					- SUCCESS if handshake complete
	 *					- FAILED if handshake failed
	 *					- NEED_MORE if more messages ready for delivery
	 *					- INVALID_STATE if more input to process() required
	 */
	status_t (*build)(tls_handshake_t *this,
					  tls_handshake_type_t *type, tls_writer_t *writer);

	/**
	 * Destroy a tls_handshake_t.
	 */
	void (*destroy)(tls_handshake_t *this);
};

#endif /** TLS_HANDSHAKE_H_ @}*/
