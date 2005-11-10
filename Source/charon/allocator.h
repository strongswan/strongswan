/**
 * @file allocator.h
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
 * Macro to allocate a special type
 * 
 * @param thing 	object on which a sizeof is performed
 * @return 
 * 			- Pointer to allocated memory if successful
 * 			- NULL otherwise
 */
#define allocator_alloc_thing(thing) (allocator_alloc(sizeof(thing)))

#ifdef LEAK_DETECTIVE

	/**
	 * @brief Allocater object use to detect memory leaks.
	 * 
	 */
	typedef struct allocator_s allocator_t;

	struct allocator_s {
	
		/**
		 * Allocates memory with LEAK_DETECTION and 
		 * returns an empty data area filled with zeros.
		 * 
		 * @warning 		Use this function not directly, only with assigned macros 
		 * 				#allocator_alloc and #allocator_alloc_thing.
		 * 
		 * @param this 	allocator_t object
		 * @param bytes number of bytes to allocate
		 * @param file 	filename from which the memory is allocated
		 * @param line 	line number in specific file
		 * @return 		
		 * 				- pointer to allocated memory area if successful
		 * 				- NULL otherwise
		 */ 
		void * (*allocate) (allocator_t *this,size_t bytes, char * file,int line);
	
		/**
		 * Reallocates memory with LEAK_DETECTION and 
		 * returns an empty data area filled with zeros
		 * 
		 * @warning 		Use this function not directly, only with assigned macro 
		 * 				#allocator_realloc
		 * 
		 * @param this 	allocator_t object
		 * @param old 	pointer to the old data area
		 * @param bytes number of bytes to allocate
		 * @param file 	filename from which the memory is allocated
		 * @param line 	line number in specific file
		 * @return 		- pointer to reallocated memory area if successful
		 * 				- NULL otherwise
		 */ 
		void * (*reallocate) (allocator_t *this,void * old, size_t bytes, char * file, int line);
		/**
		 * Frees memory with LEAK_DETECTION
		 * 
		 * @warning 		Use this function not directly, only with assigned macro 
		 * 				#allocator_free
		 * 
		 * @param this 		allocator_t object
		 * @param pointer 	pointer to the data area to free
		 */ 
		void (*free_pointer) (allocator_t *this,void * pointer);
		
		/**
		 * Report memory leaks to stderr
		 *
		 * @warning 		Use this function not directly, only with assigned macro 
		 * 				#report_memory_leaks
		 * 
 		 * @param this 		allocator_t object
		 */
		void (*report_memory_leaks) (allocator_t *this);
	};

	#ifndef ALLOCATOR_C_
		
		/**
		 * @brief Global allocater_t object.
		 * 
		 * Only accessed over macros.
		 */
		extern allocator_t *global_allocator;
	#endif
	
	/**
	 * Macro to allocate some memory
	 * 
	 * @see #allocator_s.allocate for description
	 */
	#define allocator_alloc(bytes) (global_allocator->allocate(global_allocator,bytes,__FILE__,__LINE__))
	/**
	 * Macro to reallocate some memory
	 * 
	 * @see #allocator_s.reallocate for description
	 */
	#define allocator_realloc(old,bytes) (global_allocator->reallocate(global_allocator,old,bytes,__FILE__, __LINE__))
	/**
	 * Macro to free some memory
	 * 
	 * @see #allocator_s.free for description
	 */
	#define allocator_free(pointer) (global_allocator->free_pointer(global_allocator,pointer))
	/**
	 * Macro to free a chunk
	 */
	#define allocator_free_chunk(chunk){	\
		global_allocator->free_pointer(global_allocator,chunk.ptr);			\
		chunk.ptr = NULL;				\
		chunk.len = 0;					\
	}
	/**
	 * Macro to report memory leaks
	 * 
	 * @see #allocator_s.report_memory_leaks for description
	 */
	#define report_memory_leaks(void) (global_allocator->report_memory_leaks(global_allocator))
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
