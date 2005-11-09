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

#define allocator_alloc_thing(thing) (allocator_alloc(sizeof(thing)))

#ifdef LEAK_DETECTIVE
	void * allocate(size_t bytes, char * file,int line);
	void * reallocate(void * old, size_t bytes, char * file, int line);
	void free_pointer(void * pointer);

	#define allocator_alloc(bytes) (allocate(bytes,__FILE__,__LINE__))
	#define allocator_realloc(old,bytes) (reallocate(old,bytes,__FILE__, __LINE__))
	#define allocator_free(pointer) (free_pointer(pointer))
	void report_memory_leaks(void);
#else
	#define allocator_alloc(bytes) (malloc(bytes))
	#define allocator_realloc(old,bytes) (realloc(old,bytes))
	#define allocator_free(pointer) (free(pointer))
	#define report_memory_leaks(void) {}
#endif

#endif /*ALLOCATOR_H_*/
