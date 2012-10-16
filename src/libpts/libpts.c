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
#include "pts/components/pts_component.h"
#include "pts/components/pts_component_manager.h"
#include "pts/components/tcg/tcg_comp_func_name.h"
#include "pts/components/ita/ita_comp_func_name.h"
#include "pts/components/ita/ita_comp_ima.h"
#include "pts/components/ita/ita_comp_tboot.h"
#include "pts/components/ita/ita_comp_tgrub.h"

#include <imcv.h>
#include <utils/debug.h>

/**
 * PTS Functional Component manager
 */
pts_component_manager_t *pts_components;

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

		pts_components = pts_component_manager_create();
		pts_components->add_vendor(pts_components, PEN_TCG,
					pts_tcg_comp_func_names, PTS_TCG_QUALIFIER_TYPE_SIZE,
					pts_tcg_qualifier_flag_names, pts_tcg_qualifier_type_names);
		pts_components->add_vendor(pts_components, PEN_ITA,
					pts_ita_comp_func_names, PTS_ITA_QUALIFIER_TYPE_SIZE,
					pts_ita_qualifier_flag_names, pts_ita_qualifier_type_names);

		pts_components->add_component(pts_components, PEN_ITA,
									  PTS_ITA_COMP_FUNC_NAME_TGRUB,
									  pts_ita_comp_tgrub_create);
		pts_components->add_component(pts_components, PEN_ITA,
									  PTS_ITA_COMP_FUNC_NAME_TBOOT,
									  pts_ita_comp_tboot_create);
		pts_components->add_component(pts_components, PEN_ITA,
									  PTS_ITA_COMP_FUNC_NAME_IMA,
									  pts_ita_comp_ima_create);

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
		pts_components->remove_vendor(pts_components, PEN_TCG);
		pts_components->remove_vendor(pts_components, PEN_ITA);
		pts_components->destroy(pts_components);

		if (!imcv_pa_tnc_attributes)
		{
			return;
		}
		imcv_pa_tnc_attributes->remove_vendor(imcv_pa_tnc_attributes, PEN_TCG);
		DBG1(DBG_LIB, "libpts terminated");
	}
}

