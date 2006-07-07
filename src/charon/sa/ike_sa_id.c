/**
 * @file ike_sa_id.c
 *
 * @brief Implementation of ike_sa_id_t.
 *
 */

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


#include "ike_sa_id.h"



typedef struct private_ike_sa_id_t private_ike_sa_id_t;

/**
 * Private data of an ike_sa_id_t object.
 */
struct private_ike_sa_id_t {
	/**
	 * Public interface of ike_sa_id_t.
	 */
	ike_sa_id_t public;

	 /**
	  * SPI of Initiator.
	  */
	u_int64_t initiator_spi;

	 /**
	  * SPI of Responder.
	  */
	u_int64_t responder_spi;

	/**
	 * Role for specific IKE_SA.
	 */
	bool is_initiator_flag;
};

/**
 * Implementation of ike_sa_id_t.set_responder_spi.
 */
static void set_responder_spi (private_ike_sa_id_t *this, u_int64_t responder_spi)
{
	this->responder_spi = responder_spi;
}

/**
 * Implementation of ike_sa_id_t.set_initiator_spi.
 */
static void set_initiator_spi(private_ike_sa_id_t *this, u_int64_t initiator_spi)
{
	this->initiator_spi = initiator_spi;
}

/**
 * Implementation of ike_sa_id_t.get_initiator_spi.
 */
static u_int64_t get_initiator_spi (private_ike_sa_id_t *this)
{
	return this->initiator_spi;
}

/**
 * Implementation of ike_sa_id_t.get_responder_spi.
 */
static u_int64_t get_responder_spi (private_ike_sa_id_t *this)
{
	return this->responder_spi;
}

/**
 * Implementation of ike_sa_id_t.equals.
 */
static bool equals (private_ike_sa_id_t *this, private_ike_sa_id_t *other)
{
	if (other == NULL)
	{
		return FALSE;
	}
	if ((this->is_initiator_flag == other->is_initiator_flag) &&
		(this->initiator_spi == other->initiator_spi) &&
		(this->responder_spi == other->responder_spi))
	{
		/* private_ike_sa_id's are equal */
		return TRUE;
	}
	else
	{
		/* private_ike_sa_id's are not equal */
		return FALSE;
	}
}

/**
 * Implementation of ike_sa_id_t.replace_values.
 */
static void replace_values(private_ike_sa_id_t *this, private_ike_sa_id_t *other)
{
	this->initiator_spi = other->initiator_spi;
	this->responder_spi = other->responder_spi;
	this->is_initiator_flag = other->is_initiator_flag;
}

/**
 * Implementation of ike_sa_id_t.is_initiator.
 */
static bool is_initiator(private_ike_sa_id_t *this)
{
	return this->is_initiator_flag;
}

/**
 * Implementation of ike_sa_id_t.switch_initiator.
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
 * Implementation of ike_sa_id_t.clone.
 */
static ike_sa_id_t* clone(private_ike_sa_id_t *this)
{
	return ike_sa_id_create(this->initiator_spi, this->responder_spi, this->is_initiator_flag);
}

/**
 * Implementation of ike_sa_id_t.destroy.
 */
static void destroy(private_ike_sa_id_t *this)
{
	free(this);
}

/*
 * Described in header.
 */
ike_sa_id_t * ike_sa_id_create(u_int64_t initiator_spi, u_int64_t responder_spi, bool is_initiator_flag)
{
	private_ike_sa_id_t *this = malloc_thing(private_ike_sa_id_t);

	/* public functions */
	this->public.set_responder_spi = (void(*)(ike_sa_id_t*,u_int64_t)) set_responder_spi;
	this->public.set_initiator_spi = (void(*)(ike_sa_id_t*,u_int64_t)) set_initiator_spi;
	this->public.get_responder_spi = (u_int64_t(*)(ike_sa_id_t*)) get_responder_spi;
	this->public.get_initiator_spi = (u_int64_t(*)(ike_sa_id_t*)) get_initiator_spi;
	this->public.equals = (bool(*)(ike_sa_id_t*,ike_sa_id_t*)) equals;
	this->public.replace_values = (void(*)(ike_sa_id_t*,ike_sa_id_t*)) replace_values;
	this->public.is_initiator = (bool(*)(ike_sa_id_t*)) is_initiator;
	this->public.switch_initiator = (bool(*)(ike_sa_id_t*)) switch_initiator;
	this->public.clone = (ike_sa_id_t*(*)(ike_sa_id_t*)) clone;
	this->public.destroy = (void(*)(ike_sa_id_t*))destroy;

	/* private data */
	this->initiator_spi = initiator_spi;
	this->responder_spi = responder_spi;
	this->is_initiator_flag = is_initiator_flag;

	return &this->public;
}
