/*
 * Copyright (C) 2006 Martin Willi
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

#include <crypto/transform.h>

ENUM_BEGIN(transform_type_names, UNDEFINED_TRANSFORM_TYPE, UNDEFINED_TRANSFORM_TYPE, 
	"UNDEFINED_TRANSFORM_TYPE");
ENUM_NEXT(transform_type_names, ENCRYPTION_ALGORITHM, EXTENDED_SEQUENCE_NUMBERS, UNDEFINED_TRANSFORM_TYPE,
	"ENCRYPTION_ALGORITHM",
	"PSEUDO_RANDOM_FUNCTION",
	"INTEGRITY_ALGORITHM",
	"DIFFIE_HELLMAN_GROUP",
	"EXTENDED_SEQUENCE_NUMBERS");
ENUM_END(transform_type_names, EXTENDED_SEQUENCE_NUMBERS);

