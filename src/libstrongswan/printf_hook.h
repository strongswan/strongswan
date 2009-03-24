/*
 * Copyright (C) 2009 Tobias Brunner
 * Copyright (C) 2006-2008 Martin Willi
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
 *
 * $Id$
 */

/**
 * @defgroup printf_hook printf_hook
 * @{ @ingroup libstrongswan
 */

#ifndef PRINTF_HOOK_H_
#define PRINTF_HOOK_H_

typedef struct printf_hook_t printf_hook_t;
typedef struct printf_hook_spec_t printf_hook_spec_t;
typedef enum printf_hook_argtype_t printf_hook_argtype_t;

#ifdef HAVE_PRINTF_HOOKS

#include <printf.h>

enum printf_hook_argtype_t {
	PRINTF_HOOK_ARGTYPE_END = PA_LAST,
	PRINTF_HOOK_ARGTYPE_INT = PA_INT,
	PRINTF_HOOK_ARGTYPE_POINTER = PA_POINTER,
};

#else

#include <vstr.h>

enum printf_hook_argtype_t {
	PRINTF_HOOK_ARGTYPE_END = VSTR_TYPE_FMT_END,
	PRINTF_HOOK_ARGTYPE_INT = VSTR_TYPE_FMT_INT,
	PRINTF_HOOK_ARGTYPE_POINTER = VSTR_TYPE_FMT_PTR_VOID,
};

/**
 * Redefining printf and alike
 */
#include <stdio.h>
#include <stdarg.h>

int vstr_wrapper_printf(const char *format, ...);
int vstr_wrapper_fprintf(FILE *stream, const char *format, ...);
int vstr_wrapper_sprintf(char *str, const char *format, ...);
int vstr_wrapper_snprintf(char *str, size_t size, const char *format, ...);

int vstr_wrapper_vprintf(const char *format, va_list ap);
int vstr_wrapper_vfprintf(FILE *stream, const char *format, va_list ap);
int vstr_wrapper_vsprintf(char *str, const char *format, va_list ap);
int vstr_wrapper_vsnprintf(char *str, size_t size, const char *format, va_list ap);

#define printf vstr_wrapper_printf
#define fprintf vstr_wrapper_fprintf
#define sprintf vstr_wrapper_sprintf
#define snprintf vstr_wrapper_snprintf

#define vprintf vstr_wrapper_vprintf
#define vfprintf vstr_wrapper_vfprintf
#define vsprintf vstr_wrapper_vsprintf
#define vsnprintf vstr_wrapper_vsnprintf

#endif

/**
 * Callback function type for printf hooks.
 * 
 * @param dst		destination buffer
 * @param len		length of the buffer
 * @param spec		format specifier
 * @param args		arguments array
 * @return 			number of characters written
 */
typedef int (*printf_hook_function_t)(char *dst, size_t len,
									  printf_hook_spec_t *spec,
									  const void *const *args);

/**
 * Helper macro to be used in printf hook callbacks.
 * buf and buflen get modified.
 */
#define print_in_hook(buf, buflen, fmt, ...) ({\
	int _written = snprintf(buf, buflen, fmt, ##__VA_ARGS__);\
	if (_written < 0 || _written >= buflen)\
	{\
		_written = buflen - 1;\
	}\
	buf += _written;\
	buflen -= _written;\
	_written;\
})

/**
 * Properties of the format specifier
 */
struct printf_hook_spec_t {
	/**
	 * TRUE if a '#' was used in the format specifier
	 */
	int hash;
	
	/**
	 * TRUE if a '-' was used in the format specifier
	 */
	int minus;
	
	/**
	 * The width as given in the format specifier.
	 */
	int width;
};

/**
 * Printf handler management.
 */
struct printf_hook_t {
	
	/**
	 * Register a printf handler.
	 *
	 * @param spec		printf hook format character
	 * @param hook		hook function
	 * @param ...		list of PRINTF_HOOK_ARGTYPE_*, MUST end with PRINTF_HOOK_ARGTYPE_END
	 */
	void (*add_handler)(printf_hook_t *this, char spec,
						printf_hook_function_t hook, ...);
	
	/**
     * Destroy a printf_hook instance.
     */
    void (*destroy)(printf_hook_t *this);
};

/**
 * Create a printf_hook instance.
 */
printf_hook_t *printf_hook_create();

#endif /** PRINTF_HOOK_H_ @}*/
