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
 *
 * RCSID $Id: xauth.c,v 1.1 2005/01/06 22:10:15 as Exp $
 */

#include <freeswan.h>

#include "constants.h"
#include "defs.h"
#include "xauth.h"
#include "keys.h"

void 
xauth_init(void)
{
    /* TODO: locate and load dynamic XAUTH module */
    xauth_defaults();
}

void
xauth_finalize(void)
{
    /* TODO: unload dynamic XAUTH module */
}
