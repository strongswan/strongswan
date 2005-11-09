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


union mhdr {
    struct {
	const char *file;
	size_t line;
	size_t length;
	union mhdr *older, *newer;
    } i;    /* info */
    unsigned long junk;	/* force maximal alignment */
};

static union mhdr *allocs = NULL;

static pthread_mutex_t mutex = PTHREAD_MUTEX_INITIALIZER;

/**
 * Allocates memory with LEAK_DETECTION and returns an empty data area filled with zeros
 * 
 * use this function not directly, only with assigned macros
 */ 
void * allocate(size_t bytes, char * file,int line)
{
    union mhdr *p = malloc(sizeof(union mhdr) + bytes);

    if (p == NULL)
    {
		return p;
    }
    pthread_mutex_lock( &mutex);
    p->i.line = line;
    p->i.file = file;
    p->i.length = bytes;
    p->i.older = allocs;
    if (allocs != NULL)
	allocs->i.newer = p;
    allocs = p;
    p->i.newer = NULL;

    memset(p+1, '\0', bytes);
    pthread_mutex_unlock( &mutex);
    return p+1;
}

/**
 * Frees memory with LEAK_DETECTION
 * 
 * use this function not directly, only with assigned macros
 */ 
void free_pointer(void * pointer)
{
    union mhdr *p;

    if (pointer == NULL)
    {
	    	return;	
    }
	pthread_mutex_lock( &mutex);
    p = ((union mhdr *)pointer) - 1;

    if (p->i.older != NULL)
    {
	assert(p->i.older->i.newer == p);
	p->i.older->i.newer = p->i.newer;
    }
    if (p->i.newer == NULL)
    {
	assert(p == allocs);
	allocs = p->i.older;
    }
    else
    {
	assert(p->i.newer->i.older == p);
	p->i.newer->i.older = p->i.older;
    }
    pthread_mutex_unlock( &mutex);
    free(p);
}

/**
 * Reallocates memory with LEAK_DETECTION
 * 
 * use this function not directly, only with assigned macros
 */ 
void * reallocate(void * old, size_t bytes, char * file,int line)
{
    union mhdr *p;

    if (old == NULL)
    {
	    	return NULL;
    }
	pthread_mutex_lock( &mutex);
    p = ((union mhdr *)old) - 1;
    
	void *new_space = allocate(bytes,file,line);
	if (new_space == NULL)
	{
		free_pointer(old);
	    pthread_mutex_unlock( &mutex);
		return NULL;
	}
	
	memcpy(new_space,old,p->i.length);
    pthread_mutex_unlock( &mutex);
	
	return new_space;
}


/**
 * Reports memory-leaks
 * 
 */ 
void report_memory_leaks(void)
{
    union mhdr
	*p = allocs,
	*pprev = NULL;
    unsigned long n = 0;
	pthread_mutex_lock( &mutex);

    while (p != NULL)
    {
	assert(pprev == p->i.newer);
	pprev = p;
	p = p->i.older;
	n++;
	if (p == NULL || pprev->i.file != p->i.file)
	{
	    if (n != 1)
		fprintf(stderr,"leak: %lu * File %s, Line %d\n", n, pprev->i.file,pprev->i.line);
	    else
		fprintf(stderr,"leak: File %s, Line %d\n", pprev->i.file,pprev->i.line);
	    n = 0;
	}
    }
    pthread_mutex_unlock( &mutex);
}

#endif
