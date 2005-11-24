/**
 * @file randomizer.c
 * 
 * @brief Class used to get random and pseudo random values
 * 
 */

/*
 * Copyright (C) 2005 Jan Hutter, Martin Willi
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

#include <utils/allocator.h>

/**
 * Default random device used when no device is given.
 */
#define DEFAULT_RANDOM_DEVICE "/dev/random"

/**
 * Pseudo random device used when no device is given.
 */
#define DEFAULT_PSEUDO_RANDOM_DEVICE "/dev/urandom"

typedef struct private_randomizer_t private_randomizer_t;

struct private_randomizer_t {
	/**
	 * public interface
	 */
	randomizer_t public;
	
	/**
	 * @brief Reads a specific number of bytes from random or pseudo random device
	 * 
	 * @param pseudo_random			TRUE, if pseudo random bytes should be read,
	 * 								FALSE for true random bytes
	 * @param bytes					Number of bytes to read
	 * @param[out] buffer			Pointer to buffer where to write the data in.
	 * 								Size of buffer has to be at least bytes.
	 * @return
	 * 								- SUCCESS
	 * 								- FAILED
	 */
	status_t (*get_bytes_from_device) (private_randomizer_t *this,bool pseudo_random, size_t bytes, u_int8_t *buffer);
		
	/**
	 * Random device name
	 */
	char *random_dev_name;
	
	/**
	 * Pseudo random device name
	 */
	char *pseudo_random_dev_name;
};


/**
 * Implements private_randomizer_t's get_bytes_from_device function.
 * See #private_randomizer_t.get_bytes_from_device for description.
 */
static status_t get_bytes_from_device(private_randomizer_t *this,bool pseudo_random, size_t bytes, u_int8_t *buffer)
{
	/* number of bytes already done */
	size_t ndone;
	/* device file descriptor */
	int device;
	size_t got;
	char * device_name;

	device_name = (pseudo_random) ? this->pseudo_random_dev_name : this->random_dev_name;

	// open device
	device = open(device_name, 0);
	if (device < 0) {
		return FAILED;
	}
	ndone = 0;
	
	// read until nbytes are read
	while (ndone < bytes)
	{
		got = read(device, buffer + ndone, bytes - ndone);
		if (got < 0) {
			return FAILED;
		}
		if (got == 0) {
			return FAILED;
		}
		ndone += got;
	}
	// close device
	close(device);
	return SUCCESS;
}

/**
 * Implements randomizer_t's get_random_bytes function.
 * See #randomizer_t.get_random_bytes for description.
 */
static status_t get_random_bytes(private_randomizer_t *this,size_t bytes, u_int8_t *buffer)
{
	return (this->get_bytes_from_device(this, FALSE, bytes, buffer));
}
/**
 * Implements randomizer_t's allocate_random_bytes function.
 * See #randomizer_t.allocate_random_bytes for description.
 */
static status_t allocate_random_bytes(private_randomizer_t *this, size_t bytes, chunk_t *chunk)
{
	chunk->len = bytes;
	chunk->ptr = allocator_alloc(bytes);
	if (chunk->ptr == NULL)
	{
		return OUT_OF_RES;
	}	
	return (this->get_bytes_from_device(this, FALSE, bytes, chunk->ptr));
}

/**
 * Implements randomizer_t's get_pseudo_random_bytes function.
 * See #randomizer_t.get_pseudo_random_bytes for description.
 */
static status_t get_pseudo_random_bytes(private_randomizer_t *this,size_t bytes, u_int8_t *buffer)
{
	return (this->get_bytes_from_device(this, TRUE, bytes, buffer));
}


/**
 * Implements randomizer_t's allocate_random_bytes function.
 * See #randomizer_t.allocate_random_bytes for description.
 */
static status_t allocate_pseudo_random_bytes(private_randomizer_t *this, size_t bytes, chunk_t *chunk)
{
	chunk->len = bytes;
	chunk->ptr = allocator_alloc(bytes);
	if (chunk->ptr == NULL)
	{
		return OUT_OF_RES;
	}	
	return (this->get_bytes_from_device(this, TRUE, bytes, chunk->ptr));
}


/**
 * Implements randomizer_t's destroy function.
 * See #randomizer_t.destroy for description.
 */
static status_t destroy(private_randomizer_t *this)
{
	allocator_free(this->random_dev_name);
	allocator_free(this->pseudo_random_dev_name);
	allocator_free(this);
	
	return SUCCESS;
}

/*
 * Described in header.
 */
randomizer_t *randomizer_create(void)
{
	return randomizer_create_on_devices(DEFAULT_RANDOM_DEVICE,DEFAULT_PSEUDO_RANDOM_DEVICE);
}

/*
 * Described in header.
 */
randomizer_t *randomizer_create_on_devices(char * random_dev_name,char * prandom_dev_name)
{
	private_randomizer_t *this = allocator_alloc_thing(private_randomizer_t);
	if (this == NULL)
	{
		return NULL;
	}
	if ((random_dev_name == NULL) || (prandom_dev_name == NULL))
	{
		return NULL;
	}
	
	/* public functions */
	this->public.get_random_bytes = (status_t (*) (randomizer_t *,size_t, u_int8_t *)) get_random_bytes;
	this->public.allocate_random_bytes = (status_t (*) (randomizer_t *,size_t, chunk_t *)) allocate_random_bytes;
	this->public.get_pseudo_random_bytes = (status_t (*) (randomizer_t *,size_t, u_int8_t *)) get_pseudo_random_bytes;
	this->public.allocate_pseudo_random_bytes = (status_t (*) (randomizer_t *,size_t, chunk_t *)) allocate_pseudo_random_bytes;
	this->public.destroy = (status_t (*) (randomizer_t *))destroy;
	
	/* private functions */
	this->get_bytes_from_device = get_bytes_from_device;
	
	/* private fields */
	this->random_dev_name = allocator_alloc(strlen(random_dev_name) + 1);
	if (this->random_dev_name == NULL)
	{
		allocator_free(this);
		return NULL;
	}
	strcpy(this->random_dev_name,random_dev_name);
	
	this->pseudo_random_dev_name = allocator_alloc(strlen(prandom_dev_name) + 1);
	if (this->pseudo_random_dev_name == NULL)
	{
		allocator_free(this->random_dev_name);
		allocator_free(this);
		return NULL;
	}
	strcpy(this->pseudo_random_dev_name,prandom_dev_name);	
	
	return &(this->public);
}
