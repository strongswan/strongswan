/*
 * Copyright (C) 2005-2006 Martin Willi
 * Copyright (C) 2005 Jan Hutter
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

#include "packet.h"

typedef struct private_packet_t private_packet_t;

/**
 * Private data of an packet_t object.
 */
struct private_packet_t {

	/**
	 * Public part of a packet_t object.
	 */
	packet_t public;

	/**
	 * source address
	 */
	host_t *source;

	/**
	 * destination address
	 */
	host_t *destination;

	 /**
	  * message data
	  */
	chunk_t data;
};

METHOD(packet_t, set_source, void,
	private_packet_t *this, host_t *source)
{
	DESTROY_IF(this->source);
	this->source = source;
}

METHOD(packet_t, set_destination, void,
	private_packet_t *this, host_t *destination)
{
	DESTROY_IF(this->destination);
	this->destination = destination;
}

METHOD(packet_t, get_source, host_t*,
	private_packet_t *this)
{
	return this->source;
}

METHOD(packet_t, get_destination, host_t*,
	private_packet_t *this)
{
	return this->destination;
}

METHOD(packet_t, get_data, chunk_t,
	private_packet_t *this)
{
	return this->data;
}

METHOD(packet_t, set_data, void,
	private_packet_t *this, chunk_t data)
{
	free(this->data.ptr);
	this->data = data;
}

METHOD(packet_t, destroy, void,
	private_packet_t *this)
{
	DESTROY_IF(this->source);
	DESTROY_IF(this->destination);
	free(this->data.ptr);
	free(this);
}

METHOD(packet_t, clone_, packet_t*,
	private_packet_t *this)
{
	packet_t *other;

	other = packet_create();
	if (this->destination != NULL)
	{
		other->set_destination(other, this->destination->clone(this->destination));
	}
	if (this->source != NULL)
	{
		other->set_source(other, this->source->clone(this->source));
	}
	if (this->data.ptr != NULL)
	{
		other->set_data(other, chunk_clone(this->data));
	}
	return other;
}

/*
 * Documented in header
 */
packet_t *packet_create(void)
{
	private_packet_t *this;

	INIT(this,
		.public = {
			.set_data = _set_data,
			.get_data = _get_data,
			.set_source = _set_source,
			.get_source = _get_source,
			.set_destination = _set_destination,
			.get_destination = _get_destination,
			.clone = _clone_,
			.destroy = _destroy,
		},
	);

	return &this->public;
}

