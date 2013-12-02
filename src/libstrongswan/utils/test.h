/*
 * Copyright (C) 2013 Tobias Brunner
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
 * @defgroup test test
 * @{ @ingroup utils
 */

#ifndef TEST_H_
#define TEST_H_

#include "collections/hashtable.h"

/**
 * Collection of testable functions.
 *
 * @note Is initialized only if libtest is loaded.
 */
extern hashtable_t *testable_functions;

/**
 * Register a (possibly static) function so that it can be called from tests.
 *
 * @param name		name (namespace/function)
 * @param fn		function to register (set to NULL to unregister)
 */
void testable_function_register(char *name, void *fn);

/**
 * Macro to automatically register/unregister a function that can be called
 * from tests.
 *
 * @note The constructor has a priority set so that it runs after the
 * constructor that creates the hashtable.  The destructor, on the other hand,
 * does not have a priority set, as test coverage would report that function as
 * untested otherwise.
 *
 * @param ns		namespace
 * @param fn		function to register
 */
#define EXPORT_FUNCTION_FOR_TESTS(ns, fn) \
static void testable_function_register_##fn() __attribute__ ((constructor(2000))); \
static void testable_function_register_##fn() \
{ \
	testable_function_register(#ns "/" #fn, fn); \
} \
static void testable_function_unregister_##fn() __attribute__ ((destructor)); \
static void testable_function_unregister_##fn() \
{ \
	testable_function_register(#ns "/" #fn, NULL); \
}

/**
 * Import a registered function so that it can be called from tests.
 *
 * @note If the imported function is static (or no conflicting header files
 * are included) ret can be prefixed with static to declare the function static.
 *
 * @note We allocate an arbitrary amount of stack space, hopefully enough for
 * all arguments.
 *
 * @param ns		namespace of the function
 * @param name		name of the function
 * @param ret		return type of the function
 * @param ...		arguments of the function
 */
#define IMPORT_FUNCTION_FOR_TESTS(ns, name, ret, ...) \
ret name(__VA_ARGS__) \
{ \
	void (*fn)() = NULL; \
	if (testable_functions) \
	{ \
		fn = testable_functions->get(testable_functions, #ns "/" #name); \
	} \
	if (fn) \
	{ \
		void *args = __builtin_apply_args(); \
		__builtin_return(__builtin_apply(fn, args, 16*sizeof(void*))); \
	} \
	test_fail_msg(__FILE__, __LINE__, "function " #name " (" #ns ") not found"); \
	__builtin_return(NULL); \
}

#endif /** TEST_H_ @}*/
