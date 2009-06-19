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
 */

#include "library.h"

#include <stdlib.h>

#include <utils.h>
#include <chunk.h>
#include <debug.h>
#include <utils/identification.h>
#include <utils/host.h>
#ifdef LEAK_DETECTIVE
#include <utils/leak_detective.h>
#endif

#define CHECKSUM_LIBRARY IPSEC_DIR"/libchecksum.so"

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

	this->public.plugins->destroy(this->public.plugins);
	this->public.settings->destroy(this->public.settings);
	this->public.creds->destroy(this->public.creds);
	this->public.crypto->destroy(this->public.crypto);
	this->public.fetcher->destroy(this->public.fetcher);
	this->public.db->destroy(this->public.db);
	this->public.printf_hook->destroy(this->public.printf_hook);
	if (this->public.integrity)
	{
		this->public.integrity->destroy(this->public.integrity);
	}
	
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
bool library_init(char *settings)
{
	printf_hook_t *pfh;
	private_library_t *this = malloc_thing(private_library_t);
	lib = &this->public;
	
	lib->leak_detective = FALSE;
	
#ifdef LEAK_DETECTIVE
	this->detective = leak_detective_create();
#endif /* LEAK_DETECTIVE */

	pfh = printf_hook_create();
	this->public.printf_hook = pfh;
	
	pfh->add_handler(pfh, 'b', mem_printf_hook,
					 PRINTF_HOOK_ARGTYPE_POINTER, PRINTF_HOOK_ARGTYPE_INT,
					 PRINTF_HOOK_ARGTYPE_END);
	pfh->add_handler(pfh, 'B', chunk_printf_hook,
					 PRINTF_HOOK_ARGTYPE_POINTER, PRINTF_HOOK_ARGTYPE_END);
	pfh->add_handler(pfh, 'H', host_printf_hook,
					 PRINTF_HOOK_ARGTYPE_POINTER, PRINTF_HOOK_ARGTYPE_END);
	pfh->add_handler(pfh, 'N', enum_printf_hook,
					 PRINTF_HOOK_ARGTYPE_POINTER, PRINTF_HOOK_ARGTYPE_INT,
					 PRINTF_HOOK_ARGTYPE_END);
	pfh->add_handler(pfh, 'T', time_printf_hook,
					 PRINTF_HOOK_ARGTYPE_POINTER, PRINTF_HOOK_ARGTYPE_INT,
					 PRINTF_HOOK_ARGTYPE_END);
	pfh->add_handler(pfh, 'V', time_delta_printf_hook,
					 PRINTF_HOOK_ARGTYPE_POINTER, PRINTF_HOOK_ARGTYPE_POINTER,
					 PRINTF_HOOK_ARGTYPE_END);
	pfh->add_handler(pfh, 'Y', identification_printf_hook,
					 PRINTF_HOOK_ARGTYPE_POINTER, PRINTF_HOOK_ARGTYPE_END);
	
	this->public.settings = settings_create(settings);
	this->public.crypto = crypto_factory_create();
	this->public.creds = credential_factory_create();
	this->public.fetcher = fetcher_manager_create();
	this->public.db = database_factory_create();
	this->public.plugins = plugin_loader_create();
	this->public.integrity = NULL;
	
	if (lib->settings->get_bool(lib->settings,
								"libstrongswan.integrity_test", FALSE))
	{
		this->public.integrity = integrity_checker_create(CHECKSUM_LIBRARY);
		if (!lib->integrity->check(lib->integrity, "libstrongswan", library_init))
		{
			DBG1("integrity check of libstrongswan failed");
			return FALSE;
		}
	}
	return TRUE;
}

