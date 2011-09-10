/*
 * Copyright (C) 2011 Andreas Steffen
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

#include "ita_attr.h"
#include "ita/ita_attr_command.h"

ENUM(ita_attr_names, ITA_ATTR_COMMAND, ITA_ATTR_COMMAND,
	"Command",
);

/**
 * See header
 */
pa_tnc_attr_t* ita_attr_create_from_data(u_int32_t type, chunk_t value)
{
	switch (type)
	{
		case ITA_ATTR_COMMAND:
			return ita_attr_command_create_from_data(value);
		default:
			return NULL;
	}
}
