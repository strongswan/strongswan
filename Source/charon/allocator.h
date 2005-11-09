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

#ifndef ALLOCATOR_H_
#define ALLOCATOR_H_

#include <stddef.h>


/**
 * Function to allocate a special type
 * 
 * @param thing object on it a sizeof is performed
 */
#define allocator_alloc_thing(thing) (allocator_alloc(sizeof(thing)))

#ifdef LEAK_DETECTIVE
	/**
	 * Allocates memory with LEAK_DETECTION and 
	 * returns an empty data area filled with zeros
	 * 
	 * @warning use this function not directly, only with assigned macros 
	 * allocator_alloc and allocator_alloc_thing
	 * 
	 * @param bytes number of bytes to allocate
	 * @param file filename from which the memory is allocated
	 * @param line line number in specific file
	 * @return allocated memory area
	 */ 
	void * allocate(size_t bytes, char * file,int line);

	/**
	 * Reallocates memory with LEAK_DETECTION and 
	 * returns an empty data area filled with zeros
	 * 
	 * @warning use this function not directly, only with assigned macro 
	 * allocator_realloc
	 * 
	 * @param old pointer to the old data area
	 * @param bytes number of bytes to allocate
	 * @param file filename from which the memory is allocated
	 * @param line line number in specific file
	 * @return reallocated memory area
	 */ 
	void * reallocate(void * old, size_t bytes, char * file, int line);
	/**
	 * Frees memory with LEAK_DETECTION
	 * 
	 * @warning use this function not directly, only with assigned macro 
	 * allocator_free
	 * 
	 * @param pointer pointer to the data area to free
	 */ 
	void free_pointer(void * pointer);

	#define allocator_alloc(bytes) (allocate(bytes,__FILE__,__LINE__))
	#define allocator_realloc(old,bytes) (reallocate(old,bytes,__FILE__, __LINE__))
	#define allocator_free(pointer) (free_pointer(pointer))
	#define allocator_free_chunk(chunk){	\
		free_pointer(chunk.ptr);			\
		chunk.ptr = NULL;				\
		chunk.len = 0;					\
	}
	/**
	 * Report memory leaks to stderr
	 */
	void report_memory_leaks(void);
#else
	#define allocator_alloc(bytes) (malloc(bytes))
	#define allocator_realloc(old,bytes) (realloc(old,bytes))
	#define allocator_free(pointer) (free(pointer))
	#define allocator_free_chunk(chunk){	\
		free(chunk.ptr);					\
		chunk.ptr = NULL;				\
		chunk.len = 0;					\
	}
	#define report_memory_leaks(void) {}
#endif

#endif /*ALLOCATOR_H_*/
