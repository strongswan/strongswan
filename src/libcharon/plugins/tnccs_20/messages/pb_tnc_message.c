/*
 * Copyright (C) 2010 Andreas Steffen
 * HSR Hochschule fuer Technik Rapperswil
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

#include "pb_tnc_message.h"
#include "pb_pa_message.h"

#include <library.h>

/**
 * See header
 */
pb_tnc_message_t* pb_tnc_message_create(pb_tnc_msg_type_t type, chunk_t value)
{
	switch (type)
	{
		case PB_MSG_PA:
			return pb_pa_message_create_from_data(value);
		case PB_MSG_ERROR:
			return NULL; /* TODO */
		case PB_MSG_EXPERIMENTAL:
			return NULL; /* TODO */
		case PB_MSG_LANGUAGE_PREFERENCE:
			return NULL; /* TODO */
		case PB_MSG_ASSESSMENT_RESULT:
			return NULL; /* TODO */
		case PB_MSG_ACCESS_RECOMMENDATION:
			return NULL; /* TODO */
		case PB_MSG_REMEDIATION_PARAMETERS:
			return NULL; /* TODO */
		case PB_MSG_REASON_STRING:
			return NULL; /* TODO */
	}
	return NULL;
}

