/**
 * @file library.c
 * 
 * @brief Library (de-)initialization.
 * 
 */

/*
 * Copyright (C) 2005-2006 Martin Willi
 * Copyright (C) 2005 Jan Hutter
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

#include <utils/logger_manager.h>
#include <utils/leak_detective.h>

/**
 * Called whenever the library is linked from a process
 */
void __attribute__ ((constructor)) library_init(void)
{
	logger_manager_init();
	leak_detective_init();	
}

/**
 * Called whenever the library is unlinked from a process
 */
void __attribute__ ((destructor)) library_cleanup(void)
{
	leak_detective_cleanup();
	logger_manager_cleanup();
}
