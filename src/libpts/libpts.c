/*
 * Copyright (C) 2011 Andreas Steffen, HSR Hochschule fuer Technik Rapperswil
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

#include "libpts.h"
#include "tcg/tcg_attr.h"

#include <imcv.h>

#include <debug.h>

/**
 * Reference count for IMC/IMV instances
 */
static refcount_t libpts_ref = 0;

/**
 * Described in header.
 */
bool libpts_init(void)
{
	if (libpts_ref == 0)
	{
		if (!imcv_pa_tnc_attributes)
		{
			return FALSE;
		}
		imcv_pa_tnc_attributes->add_vendor(imcv_pa_tnc_attributes, PEN_TCG,
							tcg_attr_create_from_data, tcg_attr_names);
		DBG1(DBG_LIB, "libpts initialized");
	}
	ref_get(&libpts_ref);

	return TRUE;
}

/**
 * Described in header.
 */
void libpts_deinit(void)
{
	if (ref_put(&libpts_ref))
	{
		if (!imcv_pa_tnc_attributes)
		{
			return;
		}
		imcv_pa_tnc_attributes->remove_vendor(imcv_pa_tnc_attributes, PEN_TCG);
		DBG1(DBG_LIB, "libpts terminated");
	}
}

