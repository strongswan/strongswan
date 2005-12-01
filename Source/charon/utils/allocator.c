/**
 * @file allocator.c
 * 
 * @brief Implementation of allocator_t.
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


typedef union memory_hdr_t memory_hdr_t;

/**
 * Header of each allocated memory area.
 * 
 * Ideas stolen from pluto's defs.c.
 * 
 * Used to detect memory leaks.
 */
union memory_hdr_t {
	/**
	 * Informations
	 */
    struct {
	    	/**
	    	 * Filename withing memory was allocated
	    	 */
		const char *filename;
		/**
		 * Line number in given file
		 */
		size_t line;
		/**
		 * Allocated memory size. Needed for reallocation
		 */
		size_t size_of_memory;
		/**
		 * Link to the previous and next memory area
		 */
		memory_hdr_t *older, *newer;
    } info;
    /**
     * force maximal alignment ?
     */
    unsigned long junk;	
};

typedef struct private_allocator_t private_allocator_t;

/**
 * @brief Private allocator_t object.
 * 
 * Contains private variables of allocator_t object.
 */
struct private_allocator_t
{
	/**
	 * Public part of an allocator_t object.
	 */
	allocator_t public;
	
	/**
	 * Global list of allocations.
	 * 
	 * Thread-save through mutex.
	 */
	memory_hdr_t *allocations;

	/**
	 * Mutex used to make sure, all functions are thread-save.
	 */
	pthread_mutex_t mutex;
	
	/**
	 * Allocates memory with LEAK_DETECTION and 
	 * returns an empty data area filled with zeros.
	 *
	 * @param this 		private_allocator_t object
	 * @param bytes 		number of bytes to allocate
	 * @param file 		filename from which the memory is allocated
	 * @param line 		line number in specific file
	 * @param use_mutex if FALSE no mutex is used for allocation
	 * @return 		
	 * 					- pointer to allocated memory area
	 * 					- NULL if out of ressources
	 */ 
	void * (*allocate_special) (private_allocator_t *this,size_t bytes, char * file,int line, bool use_mutex);
};

/**
 * Implementation of private_allocator_t.allocate_special. 
 */
static void *allocate_special(private_allocator_t *this,size_t bytes, char * file,int line, bool use_mutex)
{
    memory_hdr_t *allocated_memory = malloc(sizeof(memory_hdr_t) + bytes);;
  
	if (allocated_memory == NULL)
    {
    		/* TODO LOG this case */
    		exit(-1);
    }

    if (use_mutex)
    {
	    pthread_mutex_lock( &(this->mutex));
    }
	   
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
    if (use_mutex)
    {
	    pthread_mutex_unlock(&(this->mutex));
    }
    
    /* real memory starts after header */
    return (allocated_memory+1);
}

/**
 * Implementation of allocator_t.allocate. 
 */
static void * allocate(allocator_t *allocator,size_t bytes, char * file,int line)
{
	private_allocator_t *this = (private_allocator_t *) allocator;
	return (this->allocate_special(this,bytes, file,line,TRUE));
}

/**
 * Implementation of allocator_t.allocate_as_chunk. 
 */
static chunk_t allocate_as_chunk(allocator_t *allocator,size_t bytes, char * file,int line)
{
	private_allocator_t *this = (private_allocator_t *) allocator;
	chunk_t new_chunk;
	new_chunk.ptr = this->allocate_special(this,bytes, file,line,TRUE);
	new_chunk.len = (new_chunk.ptr == NULL) ? 0 : bytes;
	return new_chunk;
}

/**
 * Implementation of allocator_t.free_pointer. 
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
 * Implementation of allocator_t.reallocate. 
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
    
	void *new_space = this->allocate_special(this,bytes,file,line,FALSE);

	if (new_space == NULL)
	{
	    pthread_mutex_unlock(&(this->mutex));
		this->public.free_pointer(&(this->public),old);
		return NULL;
	}
	
	
	/* the smaller size is copied to avoid overflows */
	memcpy(new_space,old,(allocated_memory->info.size_of_memory < bytes) ? allocated_memory->info.size_of_memory : bytes);
    pthread_mutex_unlock(&(this->mutex));
    this->public.free_pointer(&(this->public),old);
	
	return new_space;
}

/**
 * Implementation of allocator_t.clone_bytes. 
 */
static void * clone_bytes(allocator_t *allocator,void * to_clone, size_t bytes, char * file, int line)
{
	private_allocator_t *this = (private_allocator_t *) allocator;

    if (to_clone == NULL)
    {
	    	return NULL;
    }

    
	void *new_space = this->allocate_special(this,bytes,file,line,TRUE);

	if (new_space == NULL)
	{
		return NULL;
	}
	
	memcpy(new_space,to_clone,bytes);
	
	return new_space;
}


/**
 * Implementation of allocator_t.clone_chunk. 
 */
static chunk_t clone_chunk(allocator_t *allocator, chunk_t chunk, char * file, int line)
{
	private_allocator_t *this = (private_allocator_t *) allocator;
	chunk_t clone = CHUNK_INITIALIZER;
	
	if (chunk.ptr && chunk.len > 0)
	{
		clone.ptr = this->allocate_special(this,chunk.len,file,line,TRUE);
		clone.len = chunk.len;
		memcpy(clone.ptr, chunk.ptr, chunk.len);
	}
	
    return clone;
}

/**
 * Implementation of allocator_t.allocator_report_memory_leaks. 
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

/** 
 * Only Initiation of allocator object.
 * 
 * All allocation macros use this object.
 */
static private_allocator_t allocator = {
	public: {allocate: allocate,
	  		 allocate_as_chunk: allocate_as_chunk,
			 free_pointer: free_pointer,
			 reallocate: reallocate,
			 clone_bytes : clone_bytes,
			 clone_chunk : clone_chunk,
 			 report_memory_leaks: allocator_report_memory_leaks},
	allocations: NULL,
	allocate_special : allocate_special,
	mutex: PTHREAD_MUTEX_INITIALIZER
};

allocator_t *global_allocator = &(allocator.public);
#else /* !LEAK_DETECTION */


/*
 * Described in header
 */
chunk_t allocator_alloc_as_chunk(size_t bytes)
{
	chunk_t new_chunk;
	new_chunk.ptr = malloc(bytes); 
	if (new_chunk.ptr == NULL)
	{
		exit(-1);
	}
	new_chunk.len = bytes; 
	return new_chunk; 

}

/*
 * Described in header
 */
void * allocator_realloc(void * old, size_t newsize)
{
	void *data = realloc(old,newsize);
	return data;
} 

/*
 * Described in header
 */
void * allocator_clone_bytes(void * pointer, size_t size)
{
	
	void *data;
	data = malloc(size);
	
	if (data == NULL){exit(-1);}
	memmove(data,pointer,size);
	
	return (data);
}


/**
 * Described in header
 */
chunk_t allocator_clone_chunk(chunk_t chunk)
{
	chunk_t clone = CHUNK_INITIALIZER;
	
	if (chunk.ptr && chunk.len > 0)
	{
		clone.ptr = malloc(chunk.len);
		if (clone.ptr == NULL) {exit(-1);}
		clone.len = chunk.len;
		memcpy(clone.ptr, chunk.ptr, chunk.len);
	}
	
    return clone;
}

/*
 * Described in header
 */
void allocator_free_chunk(chunk_t *chunk)
{
	free(chunk->ptr);
	chunk->ptr = NULL;
	chunk->len = 0;
}


#endif /* LEAK_DETECTION */
