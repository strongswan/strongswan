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
 * global list of allocations
 * 
 * thread-save through mutex
 */
static memory_hdr_t *allocations = NULL;

/**
 * Mutex to ensure, all functions are thread-save
 */
static pthread_mutex_t mutex = PTHREAD_MUTEX_INITIALIZER;

/*
 * described in header
 */ 
void * allocate(size_t bytes, char * file,int line)
{
    memory_hdr_t *allocated_memory = malloc(sizeof(memory_hdr_t) + bytes);

    if (allocated_memory == NULL)
    {
		return allocated_memory;
    }
    
    pthread_mutex_lock( &mutex);
    
    allocated_memory->info.line = line;
    allocated_memory->info.filename = file;
    allocated_memory->info.size_of_memory = bytes;
    allocated_memory->info.older = allocations;
    if (allocations != NULL)
    {
		allocations->info.newer = allocated_memory;
    }
    allocations = allocated_memory;
    allocated_memory->info.newer = NULL;

	/* fill memory with zero's */
    memset(allocated_memory+1, '\0', bytes);
    pthread_mutex_unlock( &mutex);
    /* real memory starts after header */
    return (allocated_memory+1);
}

/*
 * described in header
 */ 
void free_pointer(void * pointer)
{
    memory_hdr_t *allocated_memory;

    if (pointer == NULL)
    {
	    	return;	
    }
	pthread_mutex_lock( &mutex);
    allocated_memory = ((memory_hdr_t *)pointer) - 1;

    if (allocated_memory->info.older != NULL)
    {
		assert(allocated_memory->info.older->info.newer == allocated_memory);
		allocated_memory->info.older->info.newer = allocated_memory->info.newer;
    }
    if (allocated_memory->info.newer == NULL)
    {
		assert(allocated_memory == allocations);
		allocations = allocated_memory->info.older;
    }
    else
    {
		assert(allocated_memory->info.newer->info.older == allocated_memory);
		allocated_memory->info.newer->info.older = allocated_memory->info.older;
    }
    pthread_mutex_unlock( &mutex);
    free(allocated_memory);
}

/*
 * described in header
 */ 
void * reallocate(void * old, size_t bytes, char * file,int line)
{
    memory_hdr_t *allocated_memory;

    if (old == NULL)
    {
	    	return NULL;
    }
	pthread_mutex_lock( &mutex);
    allocated_memory = ((memory_hdr_t *)old) - 1;
    
	void *new_space = allocate(bytes,file,line);
	if (new_space == NULL)
	{
		free_pointer(old);
	    pthread_mutex_unlock( &mutex);
		return NULL;
	}
	
	memcpy(new_space,old,allocated_memory->info.size_of_memory);
    pthread_mutex_unlock( &mutex);
	
	return new_space;
}


/*
 * described in header
 */ 
void report_memory_leaks(void)
{
    memory_hdr_t *p = allocations,
    				 *pprev = NULL;
    unsigned long n = 0;
	pthread_mutex_lock( &mutex);

    while (p != NULL)
    {
	assert(pprev == p->info.newer);
	pprev = p;
	p = p->info.older;
	n++;
	if (p == NULL || pprev->info.filename != p->info.filename)
	{
	    if (n != 1)
		fprintf(stderr,"leak: %lu * File %s, Line %d\n", n, pprev->info.filename,pprev->info.line);
	    else
		fprintf(stderr,"leak: File %s, Line %d\n", pprev->info.filename,pprev->info.line);
	    n = 0;
	}
    }
    pthread_mutex_unlock( &mutex);
}

#endif
