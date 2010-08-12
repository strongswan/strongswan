/*
 * Copyright (C) 2010 Andreas Steffen
 * Copyright (C) 2010 HSR Hochschule fuer Technik Rapperswil
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

#include "eap_ttls_peer.h"

#include <debug.h>

#define AVP_EAP_MESSAGE		79

typedef struct private_eap_ttls_peer_t private_eap_ttls_peer_t;

/**
 * Private data of an eap_ttls_peer_t object.
 */
struct private_eap_ttls_peer_t {

	/**
	 * Public eap_ttls_peer_t interface.
	 */
	eap_ttls_peer_t public;

	/**
	 * Peer identity
	 */
	identification_t *peer;

	/**
	 * EAP-TTLS state information
	 */
	bool start_phase2;
};


METHOD(tls_application_t, process, status_t,
	private_eap_ttls_peer_t *this, tls_reader_t *reader)
{
	return NEED_MORE;
}

METHOD(tls_application_t, build, status_t,
	private_eap_ttls_peer_t *this, tls_writer_t *writer)
{
	if (this->start_phase2)
	{
		chunk_t data = chunk_from_chars(
			0x02, 0x00, 0x00, 10, 0x01, 'c', 'a', 'r', 'o', 'l', 0x00, 0x00);
		u_int8_t avp_flags = 0x40;
		u_int32_t avp_len;

		avp_len = 8 + data.len - 2;
		writer->write_uint32(writer, AVP_EAP_MESSAGE);
		writer->write_uint8(writer, avp_flags);
		writer->write_uint24(writer, avp_len);
		writer->write_data(writer, data);
		this->start_phase2 = FALSE;
	}
	return INVALID_STATE;
}

METHOD(tls_application_t, destroy, void,
	private_eap_ttls_peer_t *this)
{
	free(this);
}

/**
 * See header
 */
eap_ttls_peer_t *eap_ttls_peer_create(identification_t *peer)
{
	private_eap_ttls_peer_t *this;

	INIT(this,
		.public.application = {
			.process = _process,
			.build = _build,
			.destroy = _destroy,
		},
		.peer = peer,
		.start_phase2 = TRUE,
	);

	return &this->public;
}
