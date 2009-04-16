/*
 * Copyright (C) 2009 Tobias Brunner
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
 * $Id: library.c 4936 2009-03-12 18:07:32Z tobias $
 */

#include "library.h"

#include <stdlib.h>

#include <utils.h>
#ifdef LEAK_DETECTIVE
#include <utils/leak_detective.h>
#endif

typedef struct private_library_t private_library_t;

/**
 * private data of library
 */
struct private_library_t {

	/**
	 * public functions
	 */
	library_t public;

#ifdef LEAK_DETECTIVE
	/**
	 * Memory leak detective, if enabled
	 */
	leak_detective_t *detective;
#endif /* LEAK_DETECTIVE */
};

/**
 * library instance
 */
library_t *lib;

/**
 * Implementation of library_t.destroy
 */
void library_deinit()
{
	private_library_t *this = (private_library_t*)lib;

	this->public.settings->destroy(this->public.settings);
	
#ifdef LEAK_DETECTIVE
	if (this->detective)
	{
		this->detective->destroy(this->detective);
	}
#endif /* LEAK_DETECTIVE */
	free(this);
	lib = NULL;
}

/*
 * see header file
 */
void library_init(char *settings)
{
	private_library_t *this = malloc_thing(private_library_t);
	lib = &this->public;
	
	lib->leak_detective = FALSE;
	
#ifdef LEAK_DETECTIVE
	this->detective = leak_detective_create();
#endif /* LEAK_DETECTIVE */

	this->public.settings = settings_create(settings);
}

