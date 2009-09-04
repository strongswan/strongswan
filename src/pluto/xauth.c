/* Initialization and finalization of the dynamic XAUTH module
 * Copyright (C) 2006 Andreas Steffen
 * Hochschule fuer Technik Rapperswil, Switzerland
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

#include <dlfcn.h>

#include <freeswan.h>

#include "constants.h"
#include "defs.h"
#include "xauth.h"
#include "keys.h"
#include "log.h"

void
xauth_init(void)
{
#ifdef XAUTH_DEFAULT_LIB
	xauth_module.handle = dlopen(XAUTH_DEFAULT_LIB, RTLD_NOW);

	if (xauth_module.handle != NULL)
	{
		DBG(DBG_CONTROL,
			DBG_log("xauth module '%s' loading'", XAUTH_DEFAULT_LIB)
		)
		xauth_module.get_secret = (bool (*) (const xauth_t*))
						dlsym(xauth_module.handle, "get_secret");
		DBG(DBG_CONTROL,
			if (xauth_module.get_secret != NULL)
			{
				DBG_log("xauth module: found get_secret() function");
			}
		)
		xauth_module.verify_secret = (bool (*) (const xauth_peer_t*, const xauth_t*))
						dlsym(xauth_module.handle, "verify_secret");
		DBG(DBG_CONTROL,
			if (xauth_module.verify_secret != NULL)
			{
				DBG_log("xauth module: found verify_secret() function");
			}
		)
	}
#endif
	/* any null function pointers will be filled in by default functions */
	xauth_defaults();
}

void
xauth_finalize(void)
{
#ifdef XAUTH_DEFAULT_LIB
	if (xauth_module.handle != NULL)
	{
		if (dlclose(xauth_module.handle))
		{
			plog("failed to unload xauth module");
		}
		else
		{
			DBG(DBG_CONTROL,
				DBG_log("xauth module unloaded")
			)
		}
	}
#endif
}
