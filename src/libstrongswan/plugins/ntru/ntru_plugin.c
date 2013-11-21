/*
 * Copyright (C) 2013 Andreas Steffen
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

#include "ntru_plugin.h"
#include "ntru_ke.h"

#include <library.h>
#include <utils/debug.h>

typedef struct private_ntru_plugin_t private_ntru_plugin_t;

rng_t *rng;

bool ntru_plugin_get_entropy(ENTROPY_CMD cmd, uint8_t *out)
{
	switch (cmd)
	{
		case INIT:
	        return TRUE;
		case GET_NUM_BYTES_PER_BYTE_OF_ENTROPY:
			/* Here we return the number of bytes needed from the entropy
			 * source to obtain 8 bits of entropy.  Maximum is 8.
			 */
			if (!out)
			{
				return FALSE;
			}
	        *out = 1;	/* this is a perfectly random source */
			return TRUE;
		case GET_BYTE_OF_ENTROPY:
			if (!out)
			{
				return FALSE;
			}
			if (!rng || !rng->get_bytes(rng, 1, out))
			{
				return FALSE;
			}
			return TRUE;
		default:
			return FALSE;
    }
}

/**
 * Create/Destroy True Random Generator
 */
static bool create_random(private_ntru_plugin_t *this,
						  plugin_feature_t *feature, bool reg, void *data)
{
	if (reg)
	{
		rng = lib->crypto->create_rng(lib->crypto, RNG_TRUE);
		if (!rng)
		{
			return FALSE;
		}
	}
	else
	{
		rng->destroy(rng);
	}
	return TRUE;
}

/**
 * private data of ntru_plugin
 */
struct private_ntru_plugin_t {

	/**
	 * public functions
	 */
	ntru_plugin_t public;
};

METHOD(plugin_t, get_name, char*,
	private_ntru_plugin_t *this)
{
	return "ntru";
}

METHOD(plugin_t, get_features, int,
	private_ntru_plugin_t *this, plugin_feature_t *features[])
{
	int count = 0;

	static plugin_feature_t f_ke[] = {
		PLUGIN_REGISTER(DH, ntru_ke_create),
			PLUGIN_PROVIDE(DH, NTRU_112_BIT),
			PLUGIN_PROVIDE(DH, NTRU_128_BIT),
			PLUGIN_PROVIDE(DH, NTRU_192_BIT),
			PLUGIN_PROVIDE(DH, NTRU_256_BIT),
	};
	static plugin_feature_t f_rng[] = {
		PLUGIN_CALLBACK((plugin_feature_callback_t)create_random, NULL),
			PLUGIN_PROVIDE(CUSTOM, "ntru-rng"),
			PLUGIN_DEPENDS(RNG, RNG_TRUE),
	};
	static plugin_feature_t f[countof(f_ke) + countof(f_rng)] = {};

	plugin_features_add(f, f_ke, countof(f_ke), &count);
	plugin_features_add(f, f_rng, countof(f_rng), &count);
	
	*features = f;
	return count;
}

METHOD(plugin_t, destroy, void,
	private_ntru_plugin_t *this)
{
	free(this);
}

/*
 * see header file
 */
plugin_t *ntru_plugin_create()
{
	private_ntru_plugin_t *this;

	INIT(this,
		.public = {
			.plugin = {
				.get_name = _get_name,
				.get_features = _get_features,
				.destroy = _destroy,
			},
		},
	);


	return &this->public.plugin;
}
