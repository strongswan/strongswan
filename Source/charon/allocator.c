/**
 * @file allocator.c
 * 
 * @brief Memory allocation with LEAK_DETECTION support
 * 
 * Thread-save implementation 
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

#include <stddef.h>
#include <stdlib.h>
#include <pthread.h>
#include <string.h>
#include <assert.h>
#include <stdio.h>
 
#ifndef ALLOCATOR_C_
#define ALLOCATOR_C_ 
#endif

#include "allocator.h"

#ifdef LEAK_DETECTIVE

typedef union memory_hdr_u memory_hdr_t;

union memory_hdr_u {
    struct {
	const char *filename;
	size_t line;
	size_t size_of_memory;
	memory_hdr_t *older, *newer;
    } info;    /* info */
    unsigned long junk;	/* force maximal alignment */
};

/**
 * private allocator_t object
 */
typedef struct private_allocator_s private_allocator_t;

struct private_allocator_s
{
	/**
	 * public part of an allocator_t object
	 */
	allocator_t public;
	
	/**
	 * global list of allocations
	 * 
	 * thread-save through mutex
	 */
	memory_hdr_t *allocations;

	/**
	 * Mutex to ensure, all functions are thread-save
	 */
	pthread_mutex_t mutex;
	
};


/**
 * implements allocator_t's function allocate
 */
static void * allocate(allocator_t *allocator,size_t bytes, char * file,int line)
{
	private_allocator_t *this = (private_allocator_t *) allocator;
    memory_hdr_t *allocated_memory = malloc(sizeof(memory_hdr_t) + bytes);

    if (allocated_memory == NULL)
    {
		return allocated_memory;
    }
    
    pthread_mutex_lock( &(this->mutex));
    
    allocated_memory->info.line = line;
    allocated_memory->info.filename = file;
    allocated_memory->info.size_of_memory = bytes;
    allocated_memory->info.older = this->allocations;
    if (this->allocations != NULL)
    {
		this->allocations->info.newer = allocated_memory;
    }
    this->allocations = allocated_memory;
    allocated_memory->info.newer = NULL;

	/* fill memory with zero's */
    memset(allocated_memory+1, '\0', bytes);
    pthread_mutex_unlock(&(this->mutex));
    /* real memory starts after header */
    return (allocated_memory+1);
}

/**
 * implements allocator_t's function free_pointer
 */
static void free_pointer(allocator_t *allocator, void * pointer)
{
	private_allocator_t *this = (private_allocator_t *) allocator;
    memory_hdr_t *allocated_memory;

    if (pointer == NULL)
    {
	    	return;	
    }
	pthread_mutex_lock( &(this->mutex));
    allocated_memory = ((memory_hdr_t *)pointer) - 1;

    if (allocated_memory->info.older != NULL)
    {
		assert(allocated_memory->info.older->info.newer == allocated_memory);
		allocated_memory->info.older->info.newer = allocated_memory->info.newer;
    }
    if (allocated_memory->info.newer == NULL)
    {
		assert(allocated_memory == this->allocations);
		this->allocations = allocated_memory->info.older;
    }
    else
    {
		assert(allocated_memory->info.newer->info.older == allocated_memory);
		allocated_memory->info.newer->info.older = allocated_memory->info.older;
    }
    pthread_mutex_unlock(&(this->mutex));
    free(allocated_memory);
}

/**
 * implements allocator_t's function reallocate
 */
static void * reallocate(allocator_t *allocator, void * old, size_t bytes, char * file,int line)
{
	private_allocator_t *this = (private_allocator_t *) allocator;
    memory_hdr_t *allocated_memory;

    if (old == NULL)
    {
	    	return NULL;
    }
	pthread_mutex_lock( &(this->mutex));
    allocated_memory = ((memory_hdr_t *)old) - 1;
    
	void *new_space = this->public.allocate(&(this->public),bytes,file,line);
	if (new_space == NULL)
	{
		this->public.free_pointer(&(this->public),old);
	    pthread_mutex_unlock(&(this->mutex));
		return NULL;
	}
	
	memcpy(new_space,old,allocated_memory->info.size_of_memory);
    pthread_mutex_unlock(&(this->mutex));
	
	return new_space;
}

/**
 * implements allocator_t's function report_memory_leaks
 */
static void allocator_report_memory_leaks(allocator_t *allocator)
{
	private_allocator_t *this = (private_allocator_t *) allocator;
    memory_hdr_t *p = this->allocations;
    memory_hdr_t *pprev = NULL;
    unsigned long n = 0;

	pthread_mutex_lock(&(this->mutex));

    while (p != NULL)
    {
	assert(pprev == p->info.newer);
	pprev = p;
	p = p->info.older;
	n++;
	if (p == NULL || pprev->info.filename != p->info.filename)
	{
	    if (n != 1)
		fprintf(stderr,"LEAK: \"%lu * File %s, Line %d\"\n", n, pprev->info.filename,pprev->info.line);
	    else
		fprintf(stderr,"LEAK: \"%s, Line %d\"\n", pprev->info.filename,pprev->info.line);
	    n = 0;
	}
    }
    pthread_mutex_unlock( &(this->mutex));
}

static private_allocator_t allocator = {
	public: {allocate: allocate,
			 free_pointer: free_pointer,
			 reallocate: reallocate,
 			 report_memory_leaks: allocator_report_memory_leaks},
	allocations: NULL,
	mutex: PTHREAD_MUTEX_INITIALIZER
};

//allocator.public.allocate = (void *) (allocator_t *,size_t, char *,int) allocate;


allocator_t *global_allocator = &(allocator.public);
#endif
