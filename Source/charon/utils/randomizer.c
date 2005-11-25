/**
 * @file randomizer.c
 * 
 * @brief Implementation of randomizer_t.
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

typedef struct private_randomizer_t private_randomizer_t;

/**
 * Private data of an randomizer_t object
 */
struct private_randomizer_t {
	/**
	 * Public interface.
	 */
	randomizer_t public;
	
	/**
	 * @brief Reads a specific number of bytes from random or pseudo random device.
	 * 
	 * @param this					calling object
	 * @param pseudo_random			TRUE, if pseudo random bytes should be read,
	 * 								FALSE for true random bytes
	 * @param bytes					number of bytes to read
	 * @param[out] buffer			pointer to buffer where to write the data in.
	 * 								Size of buffer has to be at least bytes.
	 * @return
	 * 								- SUCCESS
	 * 								- FAILED if random device could not be opened
	 */
	status_t (*get_bytes_from_device) (private_randomizer_t *this,bool pseudo_random, size_t bytes, u_int8_t *buffer);
		
	/**
	 * Random device name.
	 */
	char *random_dev_name;
	
	/**
	 * Pseudo random device name.
	 */
	char *pseudo_random_dev_name;
};


/**
 * Implementation of private_randomizer_t.get_bytes_from_device.
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
 * Implementation of randomizer_t.get_random_bytes.
 */
static status_t get_random_bytes(private_randomizer_t *this,size_t bytes, u_int8_t *buffer)
{
	return (this->get_bytes_from_device(this, FALSE, bytes, buffer));
}

/**
 * Implementation of randomizer_t.allocate_random_bytes.
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
	chunk->len = bytes;
	chunk->ptr = allocator_alloc(bytes);
	if (chunk->ptr == NULL)
	{
		return OUT_OF_RES;
	}	
	return (this->get_bytes_from_device(this, TRUE, bytes, chunk->ptr));
}


/**
 * Implementation of randomizer_t.destroy.
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
