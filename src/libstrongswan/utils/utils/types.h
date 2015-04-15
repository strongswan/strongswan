/*
 * Copyright (C) 2008-2014 Tobias Brunner
 * Copyright (C) 2008 Martin Willi
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

/**
 * @defgroup types_i types
 * @{ @ingroup utils_i
 */

#ifndef TYPES_H_
#define TYPES_H_

/**
 * General purpose boolean type.
 */
#ifdef HAVE_STDBOOL_H
# include <stdbool.h>
#else
# ifndef HAVE__BOOL
#  define _Bool signed char
# endif /* HAVE__BOOL */
# define bool _Bool
# define false 0
# define true 1
# define __bool_true_false_are_defined 1
#endif /* HAVE_STDBOOL_H */
#ifndef FALSE
# define FALSE false
#endif /* FALSE */
#ifndef TRUE
# define TRUE  true
#endif /* TRUE */

/**
 * define some missing fixed width int types on OpenSolaris.
 * TODO: since the uintXX_t types are defined by the C99 standard we should
 * probably use those anyway
 */
#if defined __sun || defined WIN32
#include <stdint.h>
typedef uint8_t  u_int8_t;
typedef uint16_t u_int16_t;
typedef uint32_t u_int32_t;
typedef uint64_t u_int64_t;
#endif

#ifdef HAVE_INT128
/**
 * 128 bit wide signed integer, if supported
 */
typedef __int128 int128_t;
/**
 * 128 bit wide unsigned integer, if supported
 */
typedef unsigned __int128 u_int128_t;

# define MAX_INT_TYPE int128_t
# define MAX_UINT_TYPE u_int128_t
#else
# define MAX_INT_TYPE int64_t
# define MAX_UINT_TYPE u_int64_t
#endif

/**
 * deprecated pluto style return value:
 * error message, NULL for success
 */
typedef const char *err_t;

/**
 * Handle struct sockaddr as a simpler sockaddr_t type.
 */
typedef struct sockaddr sockaddr_t;

#endif /** TYPES_H_ @} */
