/**
 * @file xml_interface.c
 * 
 * @brief Implementation of xml_interface_t.
 * 
 */

/*
 * Copyright (C) 2007 Martin Willi
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

#include "xml_interface.h"

#include <library.h>
#include <daemon.h>


typedef struct private_xml_interface_t private_xml_interface_t;

/**
 * Private data of an xml_interface_t object.
 */
struct private_xml_interface_t {

	/**
	 * Public part of xml_t object.
	 */
	xml_interface_t public;
};


/**
 * Implementation of itnerface_t.destroy.
 */
static void destroy(private_xml_interface_t *this)
{
	free(this);
}

/*
 * Described in header file
 */
interface_t *interface_create()
{
	private_xml_interface_t *this = malloc_thing(private_xml_interface_t);

	this->public.interface.destroy = (void (*)(xml_interface_t*))destroy;
	
	return &this->public;
}
