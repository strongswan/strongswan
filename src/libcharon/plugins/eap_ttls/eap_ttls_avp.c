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

#include "eap_ttls_avp.h"

#include <debug.h>

#define AVP_EAP_MESSAGE		79

typedef struct private_eap_ttls_avp_t private_eap_ttls_avp_t;

/**
 * Private data of an eap_ttls_avp_t object.
 */
struct private_eap_ttls_avp_t {

	/**
	 * Public eap_ttls_avp_t interface.
	 */
	eap_ttls_avp_t public;
};

METHOD(eap_ttls_avp_t, build, void,
	private_eap_ttls_avp_t *this, tls_writer_t *writer, chunk_t data)
{
	char zero_padding[] = { 0x00, 0x00, 0x00 };
	chunk_t   avp_padding;
	u_int8_t  avp_flags;
	u_int32_t avp_len;

	avp_flags = 0x40;
	avp_len = 8 + data.len;
	avp_padding = chunk_create(zero_padding, (4 - data.len) % 4);

	writer->write_uint32(writer, AVP_EAP_MESSAGE);
	writer->write_uint8(writer, avp_flags);
	writer->write_uint24(writer, avp_len);
	writer->write_data(writer, data);
	writer->write_data(writer, avp_padding);
}

METHOD(eap_ttls_avp_t, process, status_t,
	private_eap_ttls_avp_t* this, tls_reader_t *reader, chunk_t *data)
{
	u_int32_t avp_code;
	u_int8_t  avp_flags;
	u_int32_t avp_len, data_len;

	if (!reader->read_uint32(reader, &avp_code) ||
		!reader->read_uint8(reader, &avp_flags) ||
		!reader->read_uint24(reader, &avp_len))
	{
		DBG1(DBG_IKE, "received invalid AVP");
		return FAILED;
	}
 	if (avp_code != AVP_EAP_MESSAGE)
	{
		DBG1(DBG_IKE, "expected AVP_EAP_MESSAGE but received %u", avp_code);
		return FAILED;
	}
	data_len = avp_len - 8;
	if (!reader->read_data(reader, data_len + (4 - avp_len) % 4, data))
	{
		DBG1(DBG_IKE, "received insufficient AVP data");
		return FAILED;
	}
	data->len = data_len;
	return SUCCESS;	
}

METHOD(eap_ttls_avp_t, destroy, void,
	private_eap_ttls_avp_t *this)
{
	free(this);
}

/**
 * See header
 */
eap_ttls_avp_t *eap_ttls_avp_create(void)
{
	private_eap_ttls_avp_t *this;

	INIT(this,
		.public= {
			.process = _process,
			.build = _build,
			.destroy = _destroy,
		},
	);

	return &this->public;
}
