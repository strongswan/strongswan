/**
 * @file ike_sa_id.c
 *
 * @brief Class for identification of an IKE_SA
 *
 */

/*
 * Copyright (C) 2005 Jan Hutter, Martin Willi
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

#include <stdlib.h>
#include <string.h>

#include "ike_sa_id.h"

#include "types.h"
#include "utils/allocator.h"

/**
 * Private data of an ike_sa_id object
 */
typedef struct private_ike_sa_id_s private_ike_sa_id_t;

struct private_ike_sa_id_s {
	/**
	 * Public part of a ike_sa_id object
	 */
	ike_sa_id_t public;


	/* Private values */

	 /**
	  * SPI of Initiator
	  */
	u_int64_t initiator_spi;

	 /**
	  * SPI of Responder
	  */
	u_int64_t responder_spi;

	/**
	 * Role for specific IKE_SA
	 */
	bool is_initiator;

};


/**
 * @brief implements function set_responder_spi of ike_sa_id_t
 */
static status_t set_responder_spi (private_ike_sa_id_t *this, u_int64_t responder_spi)
{
	this->responder_spi = responder_spi;
	return SUCCESS;
}

static status_t set_initiator_spi(private_ike_sa_id_t *this, u_int64_t initiator_spi)
{
	this->initiator_spi = initiator_spi;
	return SUCCESS;
}

/**
 * @brief implements function initiator_spi_is_set of ike_sa_id_t
 */
static bool initiator_spi_is_set (private_ike_sa_id_t *this)
{
	return (this->initiator_spi != 0);
}

/**
 * @brief implements function responder_spi_is_set of ike_sa_id_t
 */
static bool responder_spi_is_set (private_ike_sa_id_t *this)
{
	return (this->responder_spi != 0);
}

/**
 * @brief implements function equals of ike_sa_id_t
 */
static status_t equals (private_ike_sa_id_t *this,private_ike_sa_id_t *other, bool *are_equal)
{
	if ((this == NULL)||(other == NULL))
	{
		return FAILED;
	}
	if ((this->is_initiator == other->is_initiator) &&
		(this->initiator_spi == other->initiator_spi) &&
		(this->responder_spi == other->responder_spi))

	{
		/* private_ike_sa_id's are equal */
		*are_equal = TRUE;
	}
	else
	{
		/* private_ike_sa_id's are not equal */
		*are_equal = FALSE;
	}

	return SUCCESS;
}

/**
 * @brief implements function replace_values of ike_sa_id_t
 */
status_t replace_values (private_ike_sa_id_t *this, private_ike_sa_id_t *other)
{
	if ((this == NULL) || (other == NULL))
	{
		return FAILED;
	}

	this->initiator_spi = other->initiator_spi;
	this->responder_spi = other->responder_spi;
	this->is_initiator = other->is_initiator;

	return SUCCESS;
}

/**
 * @brief implements function ike_sa_id_t.get_values
 */
static status_t get_values(private_ike_sa_id_t *this, u_int64_t *initiator, u_int64_t *responder, bool *is_initiator)
{
	memcpy(initiator, &(this->initiator_spi), sizeof(initiator));
	memcpy(responder, &(this->responder_spi), sizeof(responder));
	*is_initiator = this->is_initiator;

	return SUCCESS;
}


/**
 * @brief implements function clone of ike_sa_id_t
 */
static status_t clone (private_ike_sa_id_t *this, ike_sa_id_t **clone_of_this)
{
	*clone_of_this = ike_sa_id_create(this->initiator_spi, this->responder_spi, this->is_initiator);

	return (*clone_of_this == NULL)	? OUT_OF_RES : SUCCESS;
}

/**
 * @brief implements function destroy of ike_sa_id_t
 */
static status_t destroy (private_ike_sa_id_t *this)
{
	allocator_free(this);
	return SUCCESS;
}

/*
 * Described in Header-File
 */
ike_sa_id_t * ike_sa_id_create(u_int64_t initiator_spi, u_int64_t responder_spi, bool is_initiator)
{
	private_ike_sa_id_t *this = allocator_alloc_thing(private_ike_sa_id_t);
	if (this == NULL)
	{
		return NULL;
	}

	/* Public functions */
	this->public.set_responder_spi = (status_t(*)(ike_sa_id_t*,u_int64_t)) set_responder_spi;
	this->public.set_initiator_spi = (status_t(*)(ike_sa_id_t*,u_int64_t)) set_initiator_spi;
	this->public.responder_spi_is_set = (bool(*)(ike_sa_id_t*)) responder_spi_is_set;
	this->public.initiator_spi_is_set = (bool(*)(ike_sa_id_t*)) initiator_spi_is_set;
	this->public.equals = (status_t(*)(ike_sa_id_t*,ike_sa_id_t*,bool*)) equals;
	this->public.replace_values = (status_t(*)(ike_sa_id_t*,ike_sa_id_t*)) replace_values;
	this->public.get_values = (status_t(*)(ike_sa_id_t*,u_int64_t*,u_int64_t*,bool*)) get_values;
	this->public.clone = (status_t(*)(ike_sa_id_t*,ike_sa_id_t**)) clone;
	this->public.destroy = (status_t(*)(ike_sa_id_t*))destroy;

	/* private data */
	this->initiator_spi = initiator_spi;
	this->responder_spi = responder_spi;
	this->is_initiator = is_initiator;

	return (&this->public);
}
