/*
 * Copyright (C) 2006-2009 Martin Willi
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
#include <crypto/hashers/hasher.h>
#include <crypto/rngs/rng.h>

ENUM_BEGIN(transform_type_names, UNDEFINED_TRANSFORM_TYPE, EXTENDED_OUTPUT_FUNCTION,
	"UNDEFINED_TRANSFORM_TYPE",
	"HASH_ALGORITHM",
	"RANDOM_NUMBER_GENERATOR",
	"AEAD_ALGORITHM",
	"COMPRESSION_ALGORITHM",
	"EXTENDED OUTPUT FUNCTION");
ENUM_NEXT(transform_type_names, ENCRYPTION_ALGORITHM, EXTENDED_SEQUENCE_NUMBERS,
								EXTENDED_OUTPUT_FUNCTION,
	"ENCRYPTION_ALGORITHM",
	"PSEUDO_RANDOM_FUNCTION",
	"INTEGRITY_ALGORITHM",
	"DIFFIE_HELLMAN_GROUP",
	"EXTENDED_SEQUENCE_NUMBERS");
ENUM_END(transform_type_names, EXTENDED_SEQUENCE_NUMBERS);


ENUM(extended_sequence_numbers_names, NO_EXT_SEQ_NUMBERS, EXT_SEQ_NUMBERS,
	"NO_EXT_SEQ",
	"EXT_SEQ",
);


/**
 * See header
 */
enum_name_t* transform_get_enum_names(transform_type_t type)
{
	switch (type)
	{
		case HASH_ALGORITHM:
			return hash_algorithm_names;
		case RANDOM_NUMBER_GENERATOR:
			return rng_quality_names;
		case AEAD_ALGORITHM:
		case ENCRYPTION_ALGORITHM:
			return encryption_algorithm_names;
		case PSEUDO_RANDOM_FUNCTION:
			return pseudo_random_function_names;
		case INTEGRITY_ALGORITHM:
			return integrity_algorithm_names;
		case DIFFIE_HELLMAN_GROUP:
			return diffie_hellman_group_names;
		case EXTENDED_SEQUENCE_NUMBERS:
			return extended_sequence_numbers_names;
		case EXTENDED_OUTPUT_FUNCTION:
			return ext_out_function_names;
		case UNDEFINED_TRANSFORM_TYPE:
		case COMPRESSION_ALGORITHM:
			break;
	}
	return NULL;
}
