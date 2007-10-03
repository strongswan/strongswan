/**
 * @file task.c
 * 
 * @brief Enum values for task types
 * 
 */

/*
 * Copyright (C) 2007 Tobias Brunner
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

#include "task.h"

ENUM(task_type_names, IKE_INIT, CHILD_REKEY,
	"IKE_INIT",
	"IKE_NATD",
	"IKE_MOBIKE",
	"IKE_AUTHENTICATE",
	"IKE_CERT",
	"IKE_CONFIG",
	"IKE_REKEY",
	"IKE_REAUTH",
	"IKE_DELETE",
	"IKE_DPD",
#ifdef P2P
	"IKE_P2P",
#endif /* P2P */
	"CHILD_CREATE",
	"CHILD_DELETE",
	"CHILD_REKEY",
);

