/*
 * Copyright (C) 2005-2008 Martin Willi
 * Copyright (C) 2005 Jan Hutter
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
 * $Id$
 */

#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include <debug.h>

#include "random_rng.h"

#ifndef DEV_RANDOM
# define DEV_RANDOM "/dev/random"
#endif

#ifndef DEV_URANDOM
# define DEV_URANDOM "/dev/urandom"
#endif

typedef struct private_random_rng_t private_random_rng_t;

/**
 * Private data of an random_rng_t object.
 */
struct private_random_rng_t {

	/**
	 * Public random_rng_t interface.
	 */
	random_rng_t public;
	
	/**
	 * random device, depends on quality
	 */
	int dev;
	
	/**
	 * file we read random bytes from
	 */
	char *file;
};

/**
 * Implementation of random_rng_t.get_bytes.
 */
static void get_bytes(private_random_rng_t *this, size_t bytes,
					  u_int8_t *buffer)
{
	size_t done, got;
	
	done = 0;
	
	while (done < bytes)
	{
		got = read(this->dev, buffer + done, bytes - done);
		if (got <= 0)
		{
			DBG1("reading from \"%s\" failed: %s, retrying...",
				 this->file, strerror(errno));
			close(this->dev);
			sleep(1);
			this->dev = open(this->file, 0);
		}
		done += got;
	}
}

/**
 * Implementation of random_rng_t.allocate_bytes.
 */
static void allocate_bytes(private_random_rng_t *this, size_t bytes,
						   chunk_t *chunk)
{
	*chunk = chunk_alloc(bytes);
	get_bytes(this, chunk->len, chunk->ptr);
}

/**
 * Implementation of random_rng_t.destroy.
 */
static void destroy(private_random_rng_t *this)
{
	close(this->dev);
	free(this);
}

/*
 * Described in header.
 */
random_rng_t *random_rng_create(rng_quality_t quality)
{
	private_random_rng_t *this = malloc_thing(private_random_rng_t);

	/* public functions */
	this->public.rng.get_bytes = (void (*) (rng_t *, size_t, u_int8_t*)) get_bytes;
	this->public.rng.allocate_bytes = (void (*) (rng_t *, size_t, chunk_t*)) allocate_bytes;
	this->public.rng.destroy = (void (*) (rng_t *))destroy;

	if (quality == RNG_REAL)
	{
		this->file = DEV_RANDOM;
	}
	else
	{
		this->file = DEV_URANDOM;
	}
	
	this->dev = open(this->file, 0);
	if (this->dev < 0)
	{
		DBG1("opening \"%s\" failed: %s", this->file, strerror(errno));
		free(this);
		return NULL;
	}
	return &this->public;
}

