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
 */

/**
 * @defgroup printf_hook printf_hook
 * @{ @ingroup utils
 */

#ifndef PRINTF_HOOK_H_
#define PRINTF_HOOK_H_

typedef struct printf_hook_t printf_hook_t;
typedef struct printf_hook_spec_t printf_hook_spec_t;
typedef struct printf_hook_data_t printf_hook_data_t;
typedef enum printf_hook_argtype_t printf_hook_argtype_t;

#if !defined(USE_VSTR) && \
	!defined(HAVE_PRINTF_FUNCTION) && \
	!defined(HAVE_PRINTF_SPECIFIER)
/* assume newer glibc register_printf_specifier if none given */
#define HAVE_PRINTF_SPECIFIER
#endif

#if !defined(USE_VSTR) && \
	(defined(HAVE_PRINTF_FUNCTION) || defined(HAVE_PRINTF_SPECIFIER))

#include <stdio.h>
#include <printf.h>

enum printf_hook_argtype_t {
	PRINTF_HOOK_ARGTYPE_END = -1,
	PRINTF_HOOK_ARGTYPE_INT = PA_INT,
	PRINTF_HOOK_ARGTYPE_POINTER = PA_POINTER,
};

/**
 * Data to pass to a printf hook.
 */
struct printf_hook_data_t {

	/**
	 * Output FILE stream
	 */
	FILE *stream;;
};

/**
 * Helper macro to be used in printf hook callbacks.
 */
#define print_in_hook(data, fmt, ...) ({\
	ssize_t _written = fprintf(data->stream, fmt, ##__VA_ARGS__);\
	if (_written < 0)\
	{\
		_written = 0;\
	}\
	_written;\
})

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
int vstr_wrapper_asprintf(char **str, const char *format, ...);

int vstr_wrapper_vprintf(const char *format, va_list ap);
int vstr_wrapper_vfprintf(FILE *stream, const char *format, va_list ap);
int vstr_wrapper_vsprintf(char *str, const char *format, va_list ap);
int vstr_wrapper_vsnprintf(char *str, size_t size, const char *format, va_list ap);
int vstr_wrapper_vasprintf(char **str, const char *format, va_list ap);

#ifdef printf
#undef printf
#endif
#ifdef fprintf
#undef fprintf
#endif
#ifdef sprintf
#undef sprintf
#endif
#ifdef snprintf
#undef snprintf
#endif
#ifdef asprintf
#undef asprintf
#endif
#ifdef vprintf
#undef vprintf
#endif
#ifdef vfprintf
#undef vfprintf
#endif
#ifdef vsprintf
#undef vsprintf
#endif
#ifdef vsnprintf
#undef vsnprintf
#endif
#ifdef vasprintf
#undef vasprintf
#endif

#define printf vstr_wrapper_printf
#define fprintf vstr_wrapper_fprintf
#define sprintf vstr_wrapper_sprintf
#define snprintf vstr_wrapper_snprintf
#define asprintf vstr_wrapper_asprintf

#define vprintf vstr_wrapper_vprintf
#define vfprintf vstr_wrapper_vfprintf
#define vsprintf vstr_wrapper_vsprintf
#define vsnprintf vstr_wrapper_vsnprintf
#define vasprintf vstr_wrapper_vasprintf

/**
 * Data to pass to a printf hook.
 */
struct printf_hook_data_t {

	/**
	 * Base to append printf to
	 */
	Vstr_base *base;

	/**
	 * Position in base to write to
	 */
	size_t pos;
};

/**
 * Wrapper around vstr_add_vfmt(), avoids having to link all users of
 * print_in_hook() against libvstr.
 *
 * @param base		Vstr_string to add string to
 * @param pos		position to write to
 * @param fmt		format string
 * @param ...		arguments
 * @return			number of characters written
 */
size_t vstr_print_in_hook(struct Vstr_base *base, size_t pos, const char *fmt,
						  ...);

/**
 * Helper macro to be used in printf hook callbacks.
 */
#define print_in_hook(data, fmt, ...) ({\
	size_t _written; \
	_written = vstr_print_in_hook(data->base, data->pos, fmt, ##__VA_ARGS__);\
	data->pos += _written;\
	_written;\
})

#endif

/**
 * Callback function type for printf hooks.
 *
 * @param data		hook data, to pass to print_in_hook()
 * @param spec		format specifier
 * @param args		arguments array
 * @return			number of characters written
 */
typedef int (*printf_hook_function_t)(printf_hook_data_t *data,
									  printf_hook_spec_t *spec,
									  const void *const *args);

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
	 * TRUE if a '+' was used in the format specifier
	 */
	int plus;

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
