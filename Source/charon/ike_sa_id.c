/**
 * @file ihe_sa_id.c
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
#include <freeswan.h>
#include <pluto/constants.h>
#include <pluto/defs.h>

#include "types.h"
#include "ike_sa_id.h"

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
	spi_t initiator_spi;
	
	 /**
	  * SPI of Responder
	  */
	spi_t responder_spi;
	
	/**
	 * Role for specific IKE_SA
	 */
	ike_sa_role_t role;
	
};


/**
 * @brief implements function set_responder_spi of ike_sa_id_t
 */
static status_t set_responder_spi (private_ike_sa_id_t *this, spi_t responder_spi)
{
	if (this == NULL)
	{
		return FAILED;
	}
	this->responder_spi = responder_spi;
	return SUCCESS;
}

/**
 * @brief implements function initiator_spi_is_set of ike_sa_id_t
 */
static bool initiator_spi_is_set (private_ike_sa_id_t *this)
{
	return (!((this->initiator_spi.high == 0) && (this->initiator_spi.low == 0)));
}

/**
 * @brief implements function responder_spi_is_set of ike_sa_id_t
 */
static bool responder_spi_is_set (private_ike_sa_id_t *this)
{
	return (!((this->responder_spi.high == 0) && (this->responder_spi.low == 0)));
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
	if (	(this->role == other->role) && 
		(this->initiator_spi.high == other->initiator_spi.high) &&
		(this->initiator_spi.low == other->initiator_spi.low) &&
		(this->responder_spi.high == other->responder_spi.high) &&
		(this->responder_spi.low == other->responder_spi.low))
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

static status_t clone (private_ike_sa_id_t *this,ike_sa_id_t **clone_of_this)
{
	if ((this == NULL) || (clone_of_this == NULL))
	{
		return FAILED;
	}
	
	*clone_of_this = ike_sa_id_create(this->initiator_spi, this->responder_spi, this->role);
	
	return (*clone_of_this == NULL)	? FAILED : SUCCESS;
}

/**
 * @brief implements function destroy of ike_sa_id_t
 */
static status_t destroy (private_ike_sa_id_t *this)
{
	if (this == NULL)
	{
		return FAILED;
	}
	pfree(this);
	return SUCCESS;
}

/*
 * Described in Header-File
 */
ike_sa_id_t * ike_sa_id_create(spi_t initiator_spi, spi_t responder_spi, ike_sa_role_t role)
{
	private_ike_sa_id_t *this = alloc_thing(private_ike_sa_id_t, "private_ike_sa_id_t");
	if (this == NULL)
	{
		return NULL;
	}
	
	/* Public functions */
	this->public.set_responder_spi = (status_t(*)(ike_sa_id_t*,spi_t))set_responder_spi;
	this->public.responder_spi_is_set = (bool(*)(ike_sa_id_t*))responder_spi_is_set;
	this->public.initiator_spi_is_set = (bool(*)(ike_sa_id_t*))initiator_spi_is_set;
	this->public.equals = (status_t(*)(ike_sa_id_t*,ike_sa_id_t*,bool*))equals;
	this->public.clone = (status_t(*)(ike_sa_id_t*,ike_sa_id_t**))clone;
	this->public.destroy = (status_t(*)(ike_sa_id_t*))destroy;

	/* private data */
	this->initiator_spi = initiator_spi;
	this->responder_spi = responder_spi;
	this->role = role;
	
	return (&this->public);	
}
