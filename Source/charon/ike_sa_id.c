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
	bool is_initiator_flag;

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
 * @brief implements ike_sa_id_t.get_initiator_spi
 */
static u_int64_t get_initiator_spi (private_ike_sa_id_t *this)
{
	return this->initiator_spi;
}

/**
 * @brief implements ike_sa_id_t.get_responder_spi
 */
static u_int64_t get_responder_spi (private_ike_sa_id_t *this)
{
	return this->responder_spi;
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
	if ((this->is_initiator_flag == other->is_initiator_flag) &&
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
	this->is_initiator_flag = other->is_initiator_flag;

	return SUCCESS;
}


/**
 * @brief implements ike_sa_id_t.is_initiator
 */
static bool is_initiator(private_ike_sa_id_t *this)
{
	return this->is_initiator_flag;
}

/**
 * @brief implements ike_sa_id_t.switch_initiator
 */
static bool switch_initiator(private_ike_sa_id_t *this)
{
	if (this->is_initiator_flag)
	{
		this->is_initiator_flag = FALSE;
	}
	else
	{
		this->is_initiator_flag = TRUE;	
	}
	return this->is_initiator_flag;
}


/**
 * @brief implements function clone of ike_sa_id_t
 */
static status_t clone (private_ike_sa_id_t *this, ike_sa_id_t **clone_of_this)
{
	*clone_of_this = ike_sa_id_create(this->initiator_spi, this->responder_spi, this->is_initiator_flag);

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
ike_sa_id_t * ike_sa_id_create(u_int64_t initiator_spi, u_int64_t responder_spi, bool is_initiator_flag)
{
	private_ike_sa_id_t *this = allocator_alloc_thing(private_ike_sa_id_t);
	if (this == NULL)
	{
		return NULL;
	}

	/* Public functions */
	this->public.set_responder_spi = (status_t(*)(ike_sa_id_t*,u_int64_t)) set_responder_spi;
	this->public.set_initiator_spi = (status_t(*)(ike_sa_id_t*,u_int64_t)) set_initiator_spi;
	this->public.get_responder_spi = (u_int64_t(*)(ike_sa_id_t*)) get_responder_spi;
	this->public.get_initiator_spi = (u_int64_t(*)(ike_sa_id_t*)) get_initiator_spi;
	this->public.equals = (status_t(*)(ike_sa_id_t*,ike_sa_id_t*,bool*)) equals;
	this->public.replace_values = (status_t(*)(ike_sa_id_t*,ike_sa_id_t*)) replace_values;

	this->public.is_initiator = (bool(*)(ike_sa_id_t*)) is_initiator;
	this->public.switch_initiator = (bool(*)(ike_sa_id_t*)) switch_initiator;

	this->public.clone = (status_t(*)(ike_sa_id_t*,ike_sa_id_t**)) clone;
	this->public.destroy = (status_t(*)(ike_sa_id_t*))destroy;

	/* private data */
	this->initiator_spi = initiator_spi;
	this->responder_spi = responder_spi;
	this->is_initiator_flag = is_initiator_flag;

	return (&this->public);
}
