/*
 * Copyright (C) 2009 Martin Willi
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

#include <daemon.h>

/*******************************************************************************
 * identification part enumeration test
 ******************************************************************************/
bool test_id_parts()
{
	identification_t *id;
	enumerator_t *enumerator;
	id_part_t part;
	chunk_t data;
	int i = 0;
	
	id = identification_create_from_string("C=CH, O=strongSwan, CN=tester");
	
	enumerator = id->create_part_enumerator(id);
	while (enumerator->enumerate(enumerator, &part, &data))
	{
		switch (i++)
		{
			case 0:
				if (part != ID_PART_RDN_C ||
					!chunk_equals(data, chunk_create("CH", 2)))
				{
					return FALSE;
				}
				break;
			case 1:
				if (part != ID_PART_RDN_O ||
					!chunk_equals(data, chunk_create("strongSwan", 10)))
				{
					return FALSE;
				}
				break;
			case 2:
				if (part != ID_PART_RDN_CN ||
					!chunk_equals(data, chunk_create("tester", 6)))
				{
					return FALSE;
				}
				break;
			default:
				return FALSE;
		}
	}
	if (i < 3)
	{
		return FALSE;
	}
	enumerator->destroy(enumerator);
	id->destroy(id);
	return TRUE;
}

