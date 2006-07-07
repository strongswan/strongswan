/**
 * @file randomizer.c
 * 
 * @brief Implementation of randomizer_t.
 * 
 */

/*
 * Copyright (C) 2005-2006 Martin Willi
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
 */

#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>

#include "randomizer.h"


typedef struct private_randomizer_t private_randomizer_t;

/**
 * Private data of an randomizer_t object.
 */
struct private_randomizer_t {

	/**
	 * Public randomizer_t interface.
	 */
	randomizer_t public;
	
	/**
	 * @brief Reads a specific number of bytes from random or pseudo random device.
	 * 
	 * @param this					calling object
	 * @param pseudo_random			TRUE, if from pseudo random bytes should be read,
	 * 								FALSE for true random bytes
	 * @param bytes					number of bytes to read
	 * @param[out] buffer			pointer to buffer where to write the data in.
	 * 								Size of buffer has to be at least bytes.
	 */
	status_t (*get_bytes_from_device) (private_randomizer_t *this,bool pseudo_random, size_t bytes, u_int8_t *buffer);
};


/**
 * Implementation of private_randomizer_t.get_bytes_from_device.
 */
static status_t get_bytes_from_device(private_randomizer_t *this,bool pseudo_random, size_t bytes, u_int8_t *buffer)
{
	size_t ndone;
	int device;
	size_t got;
	char * device_name;

	device_name = pseudo_random ? DEV_URANDOM : DEV_RANDOM;

	device = open(device_name, 0);
	if (device < 0) {
		return FAILED;
	}
	ndone = 0;
	
	/* read until nbytes are read */
	while (ndone < bytes)
	{
		got = read(device, buffer + ndone, bytes - ndone);
		if (got <= 0) {
			close(device);
			return FAILED;
		}
		ndone += got;
	}
	close(device);
	return SUCCESS;
}

/**
 * Implementation of randomizer_t.get_random_bytes.
 */
static status_t get_random_bytes(private_randomizer_t *this,size_t bytes, u_int8_t *buffer)
{
	return this->get_bytes_from_device(this, FALSE, bytes, buffer);
}

/**
 * Implementation of randomizer_t.allocate_random_bytes.
 */
static status_t allocate_random_bytes(private_randomizer_t *this, size_t bytes, chunk_t *chunk)
{
	status_t status;
	chunk->len = bytes;
	chunk->ptr = malloc(bytes);
	status = this->get_bytes_from_device(this, FALSE, bytes, chunk->ptr);
	if (status != SUCCESS)
	{
		free(chunk->ptr);
	}
	return status;
}

/**
 * Implementation of randomizer_t.get_pseudo_random_bytes.
 */
static status_t get_pseudo_random_bytes(private_randomizer_t *this,size_t bytes, u_int8_t *buffer)
{
	return (this->get_bytes_from_device(this, TRUE, bytes, buffer));
}

/**
 * Implementation of randomizer_t.allocate_pseudo_random_bytes.
 */
static status_t allocate_pseudo_random_bytes(private_randomizer_t *this, size_t bytes, chunk_t *chunk)
{
	status_t status;
	chunk->len = bytes;
	chunk->ptr = malloc(bytes);
	status = this->get_bytes_from_device(this, TRUE, bytes, chunk->ptr);
	if (status != SUCCESS)
	{
		free(chunk->ptr);
	}
	return status;
}

/**
 * Implementation of randomizer_t.destroy.
 */
static void destroy(private_randomizer_t *this)
{
	free(this);
}

/*
 * Described in header.
 */
randomizer_t *randomizer_create(void)
{
	private_randomizer_t *this = malloc_thing(private_randomizer_t);

	/* public functions */
	this->public.get_random_bytes = (status_t (*) (randomizer_t *,size_t, u_int8_t *)) get_random_bytes;
	this->public.allocate_random_bytes = (status_t (*) (randomizer_t *,size_t, chunk_t *)) allocate_random_bytes;
	this->public.get_pseudo_random_bytes = (status_t (*) (randomizer_t *,size_t, u_int8_t *)) get_pseudo_random_bytes;
	this->public.allocate_pseudo_random_bytes = (status_t (*) (randomizer_t *,size_t, chunk_t *)) allocate_pseudo_random_bytes;
	this->public.destroy = (void (*) (randomizer_t *))destroy;
	
	/* private functions */
	this->get_bytes_from_device = get_bytes_from_device;
	
	return &(this->public);
}
