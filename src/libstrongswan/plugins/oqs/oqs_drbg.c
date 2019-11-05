/*
 * Copyright (C) 2019 Andreas Steffen
 *
 * Copyright (C) secunet Security Networks AG
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

#include "oqs_drbg.h"

#include <threading/thread_value.h>

static thread_value_t *local_drbg;

/**
 * See header.
 */
void oqs_drbg_init(void)
{
	local_drbg = thread_value_create(NULL);
}

/**
 * See header.
 */
void oqs_drbg_deinit(void)
{
	local_drbg->destroy(local_drbg);
}

/**
 * See header.
 */
void oqs_drbg_rand(uint8_t *buffer, size_t size)
{
	drbg_t *drbg = local_drbg->get(local_drbg);

	if (drbg)
	{
		drbg->generate(drbg, size, buffer);
	}
}

/**
 * See header.
 */
void oqs_drbg_set(drbg_t *drbg)
{
	if (drbg)
	{
		local_drbg->set(local_drbg, drbg);
	}
}