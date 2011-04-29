/*
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
 * @defgroup leak_detective leak_detective
 * @{ @ingroup utils
 */

#ifndef LEAK_DETECTIVE_H_
#define LEAK_DETECTIVE_H_

typedef struct leak_detective_t leak_detective_t;

#include <library.h>

/**
 * Leak detective finds leaks and bad frees using malloc hooks.
 *
 * Currently leaks are reported to stderr on destruction.
 *
 * @todo Build an API for leak detective, allowing leak enumeration, statistics
 * and dynamic whitelisting.
 */
struct leak_detective_t {

	/**
	 * Report leaks to stderr.
	 *
	 * @param detailed 		TRUE to resolve line/filename of leak (slow)
	 */
	void (*report)(leak_detective_t *this, bool detailed);

	/**
	 * Report current memory usage to out.
	 *
	 * @param out			target to write usage report to
	 */
	void (*usage)(leak_detective_t *this, FILE *out);

	/**
	 * Destroy a leak_detective instance.
	 */
	void (*destroy)(leak_detective_t *this);
};

/**
 * Create a leak_detective instance.
 */
leak_detective_t *leak_detective_create();

#endif /** LEAK_DETECTIVE_H_ @}*/

