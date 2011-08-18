/*
 * Copyright (C) 2011 Andreas Steffen
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

#include "tcg_pts_meas_algo.h"

#include <debug.h>

/**
 * Described in header.
 */
bool tcg_pts_probe_meas_algorithms(pts_meas_algorithms_t *algorithms)
{
	enumerator_t *enumerator;
    hash_algorithm_t hash_alg;
    const char *plugin_name;
	char format1[] = "  %s PTS measurement algorithm %N[%s] available";
	char format2[] = "  %s PTS measurement algorithm %N not available";
	
	*algorithms = 0;

	enumerator = lib->crypto->create_hasher_enumerator(lib->crypto);
	while (enumerator->enumerate(enumerator, &hash_alg, &plugin_name))
	{
		if (hash_alg == HASH_SHA1)
		{
			*algorithms |= PTS_MEAS_ALGO_SHA1;
			DBG2(DBG_TNC, format1, "mandatory", hash_algorithm_names, hash_alg,
								  plugin_name);
		}
		else if (hash_alg == HASH_SHA256)
		{
			*algorithms |= PTS_MEAS_ALGO_SHA256;
			DBG2(DBG_TNC, format1, "mandatory", hash_algorithm_names, hash_alg,
								  plugin_name);
		}
		else if (hash_alg == HASH_SHA384)
		{
			*algorithms |= PTS_MEAS_ALGO_SHA384;
			DBG2(DBG_TNC, format1, "optional ", hash_algorithm_names, hash_alg,
								  plugin_name);
		}
	}
	enumerator->destroy(enumerator);

	if (!(*algorithms & PTS_MEAS_ALGO_SHA384))
	{	
		DBG1(DBG_TNC, format2, "optional ", hash_algorithm_names, HASH_SHA384);
	}
	if ((*algorithms & PTS_MEAS_ALGO_SHA1) &&
		(*algorithms & PTS_MEAS_ALGO_SHA256))
	{
		return TRUE;
	}
	if (!(*algorithms & PTS_MEAS_ALGO_SHA1))
	{	
		DBG1(DBG_TNC, format2, "mandatory", hash_algorithm_names, HASH_SHA1);
	}
	if (!(*algorithms & PTS_MEAS_ALGO_SHA256))
	{	
		DBG1(DBG_TNC, format2, "mandatory", hash_algorithm_names, HASH_SHA256);
	}
	return FALSE;
}

/**
 * Described in header.
 */
hash_algorithm_t tcg_pts_meas_to_hash_algorithm(pts_meas_algorithms_t algorithm)
{
	switch (algorithm)
	{
		case PTS_MEAS_ALGO_SHA1:
			return HASH_SHA1;
		case PTS_MEAS_ALGO_SHA256:
			return HASH_SHA256;
		case PTS_MEAS_ALGO_SHA384:
			return HASH_SHA384;
		default:
			return HASH_UNKNOWN;
	}
}
