/**
 * @file definitions.h
 * 
 * @brief general purpose definitions and macros
 * 
 */

/*
 * Copyright (C) 2005 Jan Hutter, Martin Willi
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



/* stolen from strongswan */
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


/**
 * @addtogroup config
 * 
 * Configuration stuff.
 */

/**
 * @addtogroup encoding
 * 
 * Classes used to encode and decode IKEv2 Messages.
 */
 
 /**
 * @addtogroup payloads
 * 
 * Classes representing a specific IKEv2 Payload type.
 * 
 * @ingroup encoding
 */

/**
 * @addtogroup transforms
 * 
 * Transform algorithms of different kind.
 */
 
/**
 * @addtogroup prfs
 * 
 * Pseudo random functions, generate a lot of pseudo
 * randomness using random numbers.
 * 
 * @ingroup transforms
 */

/**
 * @addtogroup signers
 * 
 * Symmetric signing algorithms, used to ensure 
 * message integrity.
 * 
 * @ingroup transforms
 */

/**
 * @addtogroup crypters
 * 
 * Symmetric encryption algorithms, used to en-
 * and decrypt.
 * 
 * @ingroup transforms
 */
 
/**
 * @addtogroup hashers
 * 
 * Hashing algorithms.
 * 
 * Example for using hasher_t:
 * @code
 * chunk_t data;
 * chunk_t md5_hash;
 * u_int8_t sha1_hash[20];
 * 
 * hasher_t *hasher;
 * 
 * data.ptr = "string to hash";
 * data.len = strlen(data.ptr);
 * 
 * // use MD5, allocate hash
 * hasher = hasher_create(HASH_MD5);
 * hasher->allocate_hash(hasher, data, &hash);
 * hasher->destroy(hasher);
 * 
 * // use SHA1, hash in buffer
 * hasher = hasher_create(HASH_SHA1);
 * hasher->get_hash(hasher, data, &sha1_hash);
 * hasher->destroy(hasher);
 * @endcode
 * 
 * 
 * 
 * @ingroup transforms
 */
 
 /**
 * @addtogroup utils
 * 
 * Generic helper classes.
 */
  
/**
 * @addtogroup threads
 * 
 * Threaded classes, which will do their 
 * job alone.
 */
 
 

/**
 * macro gives back larger of two values
 */
#define max(x,y) (x > y ? x : y)


/**
 * macro gives back smaller of two values
 */
#define min(x,y) (x < y ? x : y)


/**
 * mapping entry which defines the end of a mapping_t array
 */
#define MAPPING_END (-1)

typedef struct mapping_t mapping_t;

/**
 * @brief mapping entry, where enum-to-string mappings are stored.
 */
struct mapping_t
{
	/**
	 * enumeration value
	 */
	int value;
	/**
	 * mapped string
	 */
	char *string;
};


/**
 * @brief find a mapping_string in the mapping[]
 * 
 * @param mappings		mappings array
 * @param value			enum-value to get the string from
 * 
 */
char *mapping_find(mapping_t *mappings, int value);


/**
 * Default random device used when no device is given.
 */
#define DEFAULT_RANDOM_DEVICE "/dev/random"

/**
 * Pseudo random device used when no device is given.
 */
#define DEFAULT_PSEUDO_RANDOM_DEVICE "/dev/urandom"


#endif /*DEFINITIONS_H_*/
