/**
 * @file definitions.h
 * 
 * @brief General purpose definitions and macros.
 * 
 */

/*
 * Copyright (C) 2005-2006 Martin Willi
 * Copyright (C) 2005 Jan Hutter
 * Hochschule fuer Technik Rapperswil
 * Copyright (C) 1998, 1999  D. Hugh Redelmeier. (Endian stuff)
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

#ifndef DEFINITIONS_H_
#define DEFINITIONS_H_

#include <stddef.h>

/* stolen from FreeS/WAN */
#if linux
# if defined(i386) && !defined(__i386__)
#  define __i386__ 1
#  define MYHACKFORTHIS 1
# endif
# include <endian.h>
# ifdef MYHACKFORTHIS
#  undef __i386__
#  undef MYHACKFORTHIS
# endif
#elif !(defined(BIG_ENDIAN) && defined(LITTLE_ENDIAN) && defined(BYTE_ORDER))
 /* we don't know how to do this, so we require the macros to be defined
  * with compiler flags:
  *    -DBIG_ENDIAN=4321 -DLITTLE_ENDIAN=1234 -DBYTE_ORDER=BIG_ENDIAN
  * or -DBIG_ENDIAN=4321 -DLITTLE_ENDIAN=1234 -DBYTE_ORDER=LITTLE_ENDIAN
  * Thse match the GNU definitions
  */
# include <sys/endian.h>
#endif

#ifndef BIG_ENDIAN
 #error "BIG_ENDIAN must be defined"
#endif

#ifndef LITTLE_ENDIAN
 #error "LITTLE_ENDIAN must be defined"
#endif

#ifndef BYTE_ORDER
 #error "BYTE_ORDER must be defined"
#endif

#define BITS_PER_BYTE	8
#define RSA_MIN_OCTETS	(1024 / BITS_PER_BYTE)
#define RSA_MIN_OCTETS_UGH	"RSA modulus too small for security: less than 1024 bits"
#define RSA_MAX_OCTETS	(8192 / BITS_PER_BYTE)
#define RSA_MAX_OCTETS_UGH	"RSA modulus too large: more than 8192 bits"

/**
  * Default length for various auxiliary text buffers
  */
#define BUF_LEN		512

/**
 * Macro compares two strings for equality
 */
#define streq(x,y) (strcmp(x, y) == 0)

/**
 * Macro compares two binary blobs for equality
 */
#define memeq(x,y,len) (memcmp(x, y, len) == 0)

/**
 * Macro gives back larger of two values.
 */
#define max(x,y) ((x) > (y) ? (x):(y))

/**
 * Macro gives back smaller of two values.
 */
#define min(x,y) ((x) < (y) ? (x):(y))

/**
 * Call destructor of a object if object != NULL
 */
#define DESTROY_IF(obj) if (obj) obj->destroy(obj)

/**
 * Debug macro to follow control flow
 */
#define POS printf("%s, line %d\n", __FILE__, __LINE__)

/**
 * Macro to allocate a sized type.
 * 
 * @param thing 	object on which a sizeof is performed
 * @return 			poiner to allocated memory
 */
#define malloc_thing(thing) ((thing*)malloc(sizeof(thing)))


/**
 * Mapping entry which defines the end of a mapping_t array.
 */
#define MAPPING_END (-1)

typedef struct mapping_t mapping_t;

/**
 * @brief Mapping entry, where enum-to-string mappings are stored.
 */
struct mapping_t
{
	/**
	 * Enumeration value.
	 */
	int value;
	
	/**
	 * Mapped string.
	 */
	char *string;
};


/**
 * @brief Find a mapping_string in the mapping[].
 * 
 * @param mappings		mappings array
 * @param value			enum-value to get the string from
 * 
 */
char *mapping_find(mapping_t *mappings, int value);

/**
 * @brief Describes an enumeration
 * enum_name() returns the name of an enum value, or NULL if invalid.
 */
typedef const struct enum_names enum_names;

struct enum_names {
	unsigned long en_first;  	/* first value in range */
	unsigned long en_last;   	/* last value in range (inclusive) */
	const char *const *en_names;
	enum_names *en_next_range;	/* descriptor of next range */
};

/**
 * @brief Returns the name of an enum value, or NULL if invalid
 */
const char *enum_name(enum_names *ed, unsigned long val);

#endif /*DEFINITIONS_H_*/
