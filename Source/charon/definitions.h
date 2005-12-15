/**
 * @file definitions.h
 * 
 * @brief General purpose definitions and macros.
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
 * @defgroup config config
 * 
 * Classes implementing configuration related things.
 */

/**
 * @defgroup encoding encoding
 * 
 * Classes used to encode and decode IKEv2 messages.
 */

/**
 * @defgroup network network
 * 
 * Classes for network relevant stuff.
 */
 
 /**
 * @defgroup payloads payloads
 * 
 * Classes representing specific IKEv2 payloads.
 * 
 * @ingroup encoding
 */

/**
 * @defgroup sa sa
 * 
 * Security association and helper classes.
 */


/**
 * @defgroup states states
 *
 * Varius states in which an IKE SA can be.
 *
 * @ingroup sa
 */

/**
 * @defgroup queues queues
 * 
 * Different kind of queues.
 */
 
 /**
  * @defgroup jobs jobs
  * 
  * Jobs used in job queue and event queue.
  * 
  * @ingroup queues
  */

/**
 * @defgroup testcases testcases
 * 
 * Testcases used to test the different classes in seperate module tests.
 */

/**
 * @defgroup transforms transforms
 * 
 * Transform algorithms of different kind.
 */
 
/**
 * @defgroup rsa rsa
 * 
 * RSA public key algorithm.
 * 
 * @ingroup transforms
 */
 
/**
 * @defgroup prfs prfs
 * 
 * Pseudo random functions.
 * 
 * @ingroup transforms
 */

/**
 * @defgroup signers signers
 * 
 * Symmetric signing algorithms, used to ensure message integrity.
 * 
 * @ingroup transforms
 */

/**
 * @defgroup crypters crypters
 * 
 * Symmetric encryption algorithms, used to encrypt and decrypt.
 * 
 * @ingroup transforms
 */
 
/**
 * @defgroup hashers hashers
 * 
 * Hashing algorithms.
 * 
 * @ingroup transforms
 */
 
/**
 * @defgroup utils utils
 * 
 * Generic helper classes.
 */
  
/**
 * @defgroup threads threads
 * 
 * Threaded classes, which will do their job alone.
 */
 
/**
 * Macro gives back larger of two values.
 */
#define max(x,y) (x > y ? x : y)

/**
 * Macro gives back smaller of two values.
 */
#define min(x,y) (x < y ? x : y)

/**
 * Papping entry which defines the end of a mapping_t array.
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

#endif /*DEFINITIONS_H_*/
