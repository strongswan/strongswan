/*
 * Copyright (C) 2008-2009 Tobias Brunner
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
 * @defgroup utils utils
 * @{ @ingroup libstrongswan
 */

#ifndef UTILS_H_
#define UTILS_H_

#include <sys/types.h>
#include <stdlib.h>
#include <stddef.h>
#include <sys/time.h>

#include <enum.h>

/**
 * strongSwan program return codes
 */
#define SS_RC_LIBSTRONGSWAN_INTEGRITY	64
#define SS_RC_DAEMON_INTEGRITY			65
#define SS_RC_INITIALIZATION_FAILED		66

#define SS_RC_FIRST	SS_RC_LIBSTRONGSWAN_INTEGRITY
#define SS_RC_LAST	SS_RC_INITIALIZATION_FAILED

/**
 * Number of bits in a byte
 */
#define BITS_PER_BYTE 8

/**
 * Default length for various auxiliary text buffers
 */
#define BUF_LEN 512

/**
 * Macro compares two strings for equality
 */
#define streq(x,y) (strcmp(x, y) == 0)

/**
 * Macro compares two strings for equality
 */
#define strneq(x,y,len) (strncmp(x, y, len) == 0)

/**
 * Macro compares two strings for equality ignoring case
 */
#define strcaseeq(x,y) (strcasecmp(x, y) == 0)

/**
 * Macro compares two binary blobs for equality
 */
#define memeq(x,y,len) (memcmp(x, y, len) == 0)

/**
 * Macro gives back larger of two values.
 */
#define max(x,y) ({ \
	typeof(x) _x = (x); \
	typeof(y) _y = (y); \
	_x > _y ? _x : _y; })


/**
 * Macro gives back smaller of two values.
 */
#define min(x,y) ({ \
	typeof(x) _x = (x); \
	typeof(y) _y = (y); \
	_x < _y ? _x : _y; })

/**
 * Call destructor of an object, if object != NULL
 */
#define DESTROY_IF(obj) if (obj) (obj)->destroy(obj)

/**
 * Call offset destructor of an object, if object != NULL
 */
#define DESTROY_OFFSET_IF(obj, offset) if (obj) obj->destroy_offset(obj, offset);

/**
 * Call function destructor of an object, if object != NULL
 */
#define DESTROY_FUNCTION_IF(obj, fn) if (obj) obj->destroy_function(obj, fn);

/**
 * Debug macro to follow control flow
 */
#define POS printf("%s, line %d\n", __FILE__, __LINE__)

/**
 * Macro to allocate a sized type.
 */
#define malloc_thing(thing) ((thing*)malloc(sizeof(thing)))

/**
 * Get the number of elements in an array
 */
#define countof(array) (sizeof(array)/sizeof(array[0]))

/**
 * Ignore result of functions tagged with warn_unused_result attributes
 */
#define ignore_result(call) { if(call); }

/**
 * Assign a function as a class method
 */
#define ASSIGN(method, function) (method = (typeof(method))function)

/**
 * time_t not defined
 */
#define UNDEFINED_TIME 0

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
#ifdef __sun
        #include <stdint.h>
        typedef uint8_t         u_int8_t;
        typedef uint16_t        u_int16_t;
        typedef uint32_t        u_int32_t;
        typedef uint64_t        u_int64_t;
#endif

typedef enum status_t status_t;

/**
 * Return values of function calls.
 */
enum status_t {
	/**
	 * Call succeeded.
	 */
	SUCCESS,

	/**
	 * Call failed.
	 */
	FAILED,

	/**
	 * Out of resources.
	 */
	OUT_OF_RES,

	/**
	 * The suggested operation is already done
	 */
	ALREADY_DONE,

	/**
	 * Not supported.
	 */
	NOT_SUPPORTED,

	/**
	 * One of the arguments is invalid.
	 */
	INVALID_ARG,

	/**
	 * Something could not be found.
	 */
	NOT_FOUND,

	/**
	 * Error while parsing.
	 */
	PARSE_ERROR,

	/**
	 * Error while verifying.
	 */
	VERIFY_ERROR,

	/**
	 * Object in invalid state.
	 */
	INVALID_STATE,

	/**
	 * Destroy object which called method belongs to.
	 */
	DESTROY_ME,

	/**
	 * Another call to the method is required.
	 */
	NEED_MORE,
};

/**
 * enum_names for type status_t.
 */
extern enum_name_t *status_names;

/**
 * deprecated pluto style return value:
 * error message, NULL for success
 */
typedef const char *err_t;

/**
 * Handle struct timeval like an own type.
 */
typedef struct timeval timeval_t;

/**
 * Handle struct timespec like an own type.
 */
typedef struct timespec timespec_t;

/**
 * Handle struct chunk_t like an own type.
 */
typedef struct sockaddr sockaddr_t;

/**
 * Clone a data to a newly allocated buffer
 */
void *clalloc(void *pointer, size_t size);

/**
 * Same as memcpy, but XORs src into dst instead of copy
 */
void memxor(u_int8_t dest[], u_int8_t src[], size_t n);

/**
 * A variant of strstr with the characteristics of memchr, where haystack is not
 * a null-terminated string but simply a memory area of length n.
 */
void *memstr(const void *haystack, const char *needle, size_t n);

/**
 * Creates a directory and all required parent directories.
 *
 * @param path		path to the new directory
 * @param mode		permissions of the new directory/directories
 * @return			TRUE on success
 */
bool mkdir_p(const char *path, mode_t mode);

/**
 * Get a timestamp from a monotonic time source.
 *
 * While the time()/gettimeofday() functions are affected by leap seconds
 * and system time changes, this function returns ever increasing monotonic
 * time stamps.
 *
 * @param tv		timeval struct receiving monotonic timestamps, or NULL
 * @return			monotonic timestamp in seconds
 */
time_t time_monotonic(timeval_t *tv);

/**
 * returns null
 */
void *return_null();

/**
 * No-Operation function
 */
void nop();

/**
 * returns TRUE
 */
bool return_true();

/**
 * returns FALSE
 */
bool return_false();

/**
 * Special type to count references
 */
typedef volatile u_int refcount_t;


#ifdef HAVE_GCC_ATOMIC_OPERATIONS

#define ref_get(ref) {__sync_fetch_and_add(ref, 1); }
#define ref_put(ref) (!__sync_sub_and_fetch(ref, 1))

#else /* !HAVE_GCC_ATOMIC_OPERATIONS */

/**
 * Get a new reference.
 *
 * Increments the reference counter atomic.
 *
 * @param ref	pointer to ref counter
 */
void ref_get(refcount_t *ref);

/**
 * Put back a unused reference.
 *
 * Decrements the reference counter atomic and
 * says if more references available.
 *
 * @param ref	pointer to ref counter
 * @return		TRUE if no more references counted
 */
bool ref_put(refcount_t *ref);

#endif /* HAVE_GCC_ATOMIC_OPERATIONS */

/**
 * printf hook for time_t.
 *
 * Arguments are:
 *    time_t* time, bool utc
 */
int time_printf_hook(char *dst, size_t len, printf_hook_spec_t *spec,
					 const void *const *args);

/**
 * printf hook for time_t deltas.
 *
 * Arguments are:
 *    time_t* begin, time_t* end
 */
int time_delta_printf_hook(char *dst, size_t len, printf_hook_spec_t *spec,
						   const void *const *args);

/**
 * printf hook for memory areas.
 *
 * Arguments are:
 *    u_char *ptr, int len
 */
int mem_printf_hook(char *dst, size_t len, printf_hook_spec_t *spec,
					const void *const *args);

#endif /** UTILS_H_ @}*/
