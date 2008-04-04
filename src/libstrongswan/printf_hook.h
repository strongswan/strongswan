/*
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
typedef struct printf_hook_functions_t printf_hook_functions_t;

#include <printf.h>

/**
 * Printf hook function set.
 *
 * A printf hook has two functions, one to print the string, one to read
 * in the number of arguments. See <printf.h>.
 */
struct printf_hook_functions_t {

	/**
	 * Printf hook print function. This is actually of type "printf_function",
	 * however glibc does it typedef to function, but uclibc to a pointer.
	 * So we redefine it here.
	 */
	int (*print)(FILE *, const struct printf_info *info, const void *const *args);
	
	/**
	 * Printf hook arginfo function, which is actually of type
	 * "printf_arginfo_function".
	 */
	int (*arginfo)(const struct printf_info *info, size_t n, int *argtypes);
};

/**
 * Printf handler management.
 */
struct printf_hook_t {
	
	/**
	 * Register a printf handler.
	 *
	 * @param spec		printf hook format character
	 * @param hook		hook functions
	 */
	void (*add_handler)(printf_hook_t *this, char spec,
						printf_hook_functions_t hook);
	
	/**
     * Destroy a printf_hook instance.
     */
    void (*destroy)(printf_hook_t *this);
};

/**
 * Create a printf_hook instance.
 */
printf_hook_t *printf_hook_create();

#endif /* PRINTF_HOOK_H_ @}*/
