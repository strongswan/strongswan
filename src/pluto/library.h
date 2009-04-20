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
 *
 * $Id: library.h 5003 2009-03-24 17:43:01Z martin $
 */

#ifndef LIBRARY_H_
#define LIBRARY_H_

#include <utils.h>
#include <settings.h>

typedef struct library_t library_t;

/**
 * Libstrongswan library context, contains library relevant globals.
 */
struct library_t {

	/**
	 * Printf hook registering facility
	 */
	printf_hook_t *printf_hook;
	
	/**
	 * various settings loaded from settings file
	 */
	settings_t *settings;
	
	/**
	 * is leak detective running?
	 */
	bool leak_detective;
};

/**
 * Initialize library, creates "lib" instance.
 *
 * @param settings		file to read settings from, may be NULL for none
 */
void library_init(char *settings);

/**
 * Deinitialize library, destroys "lib" instance.
 */
void library_deinit();

/**
 * Library instance, set after between library_init() and library_deinit() calls.
 */
extern library_t *lib;

#endif /** LIBRARY_H_ @}*/
