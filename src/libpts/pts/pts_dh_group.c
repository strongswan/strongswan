/*
 * Copyright (C) 2011 Sansar Choinyambuu
 * HSR Hochschule fuer Technik Rapperswil
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

#include "pts_dh_group.h"

#include <debug.h>

/**
 * Described in header.
 */
bool pts_probe_dh_groups(pts_dh_group_t *groups)
{
	enumerator_t *enumerator;
	diffie_hellman_group_t dh_group;
	const char *plugin_name;
	char format1[] = "  %s PTS Diffie Hellman Group %N[%s] available";
	char format2[] = "  %s PTS Diffie Hellman Group %N[%s] not available";
	
	*groups = 0;

	enumerator = lib->crypto->create_dh_enumerator(lib->crypto);
	while (enumerator->enumerate(enumerator, &dh_group, &plugin_name))
	{
		if (dh_group == MODP_1024_BIT)
		{
			*groups |= PTS_DH_GROUP_IKE2;
			DBG2(DBG_PTS, format1, "optional", diffie_hellman_group_names, dh_group,
								  plugin_name);
		}
		else if (dh_group == MODP_1536_BIT)
		{
			*groups |= PTS_DH_GROUP_IKE5;
			DBG2(DBG_PTS, format1, "optional", diffie_hellman_group_names, dh_group,
								  plugin_name);
		}
		else if (dh_group == MODP_2048_BIT)
		{
			*groups |= PTS_DH_GROUP_IKE14;
			DBG2(DBG_PTS, format1, "optional", diffie_hellman_group_names, dh_group,
								  plugin_name);
		}
		else if (dh_group == ECP_256_BIT)
		{
			*groups |= PTS_DH_GROUP_IKE19;
			DBG2(DBG_PTS, format1, "mandatory", diffie_hellman_group_names, dh_group,
								  plugin_name);
		}
		else if (dh_group == ECP_384_BIT)
		{
			*groups |= PTS_DH_GROUP_IKE20;
			DBG2(DBG_PTS, format1, "optional", diffie_hellman_group_names, dh_group,
								  plugin_name);
		}
	}
	enumerator->destroy(enumerator);

	if (*groups & PTS_DH_GROUP_IKE19)
	{
		return TRUE;
	}
	else
	{
		DBG1(DBG_PTS, format2, "mandatory", diffie_hellman_group_names, ECP_256_BIT, plugin_name);
	}

	return FALSE;
}

/**
 * Described in header.
 */
bool pts_update_supported_dh_groups(char *dh_group, pts_dh_group_t *groups)
{
	if (strcaseeq(dh_group, "ike20"))
	{
		/* nothing to update, all groups are supported */
		return TRUE;
	}
	else if (strcaseeq(dh_group, "ike19"))
	{
		/* remove DH Group 20 */
		*groups = ~PTS_DH_GROUP_IKE20;
		return TRUE;
	}
	else if (strcaseeq(dh_group, "ike14"))
	{
		/* remove DH Group 19 and 20 */
		*groups = ~PTS_DH_GROUP_IKE20 | ~PTS_DH_GROUP_IKE19;
		return TRUE;
	}
	else if (strcaseeq(dh_group, "ike5"))
	{
		/* remove DH Group 14, 19 and 20 */
		*groups = ~PTS_DH_GROUP_IKE20 | ~PTS_DH_GROUP_IKE19
		| ~PTS_DH_GROUP_IKE14;
		return TRUE;
	}
	else if (strcaseeq(dh_group, "ike2"))
	{
		/* remove DH Group 5, 14, 19 and 20 */
		*groups = ~PTS_DH_GROUP_IKE20 | ~PTS_DH_GROUP_IKE19 |
		~PTS_DH_GROUP_IKE14 | ~PTS_DH_GROUP_IKE5;
		return TRUE;
	}

	DBG1(DBG_PTS, "Unknown DH Group: %s configured");
	return FALSE;
}

/**
 * Described in header.
 */
diffie_hellman_group_t pts_dh_group_to_strongswan_dh_group(pts_dh_group_t dh_group)
{
	switch (dh_group)
	{
		case PTS_DH_GROUP_IKE2:
			return MODP_1024_BIT;
		case PTS_DH_GROUP_IKE5:
			return MODP_1536_BIT;
		case PTS_DH_GROUP_IKE14:
			return MODP_2048_BIT;
		case PTS_DH_GROUP_IKE19:
			return ECP_256_BIT;
		case PTS_DH_GROUP_IKE20:
			return ECP_384_BIT;
		default:
			return MODP_NONE;
	}
}
