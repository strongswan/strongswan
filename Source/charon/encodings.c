/**
 * @file encodings.c
 * 
 * @brief Type definitions for parser and generator, 
 * 		  also payload types are defined here.
 * 
 * Header is parsed like a payload and gets its one payload_id 
 * from PRIVATE USE space. Also the substructures 
 * of specific payload types get their own payload_id 
 * from PRIVATE_USE space. See RFC for mor informations.
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
 
 #include "encodings.h"
 #include "encodings/ike_header.h" 

extern payload_info_t ike_header_info;

/**
 * List containing all payload informations 
 * supported by parser and generator.
 * 
 * @warning This list must be NULL terminated.
 */
payload_info_t *payload_infos[] = {
	&ike_header_info,
 	NULL
};
 
 
