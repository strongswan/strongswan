/*
 * Copyright (C) 2011 Tobias Brunner
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

#include "keymat.h"
#include "keymat_v1.h"
#include "keymat_v2.h"

/**
 * See header
 */
keymat_t *keymat_create(ike_version_t version, bool initiator)
{
	switch (version)
	{
		case IKEV1:
			return &keymat_v1_create(initiator)->keymat;
		case IKEV2:
			return &keymat_v2_create(initiator)->keymat;
	}
	return NULL;
}
