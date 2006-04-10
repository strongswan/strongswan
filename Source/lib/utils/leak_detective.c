/**
 * @file leak_detective.c
 * 
 * @brief Implementation of leak_detective_t.
 */

/*
 * Copyright (C) 2006 Martin Willi
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
#include <pthread.h>
#include <string.h>
#include <stdio.h>
#include <malloc.h>
#include <execinfo.h>
#include <signal.h> 
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <dlfcn.h>

#include "leak_detective.h"

#include <types.h>

#ifdef LEAK_DETECTIVE

/**
 * Magic value which helps to detect memory corruption
 */
#define MEMORY_HEADER_MAGIC 0xF1367ADF


static void install_hooks(void);
static void uninstall_hooks(void);
static void *malloc_hook(size_t, const void *);
static void *realloc_hook(void *, size_t, const void *);
static void free_hook(void*, const void *);

typedef struct memory_header_t memory_header_t;

/**
 * Header which is prepended to each allocated memory block
 */
struct memory_header_t {
	/**
	 * Magci byte which must(!) hold MEMORY_HEADER_MAGIC
	 */
	u_int32_t magic;
	
	/**
	 * Number of bytes following after the header
	 */
	size_t bytes;
	
	/**
	 * Stack frames at the time of allocation
	 */
	void *stack_frames[STACK_FRAMES_COUNT];
	
	/**
	 * Number of stacks frames obtained in stack_frames
	 */
	int stack_frame_count;
	
	/**
	 * Pointer to previous entry in linked list
	 */
	memory_header_t *previous;
	
	/**
	 * Pointer to next entry in linked list
	 */
	memory_header_t *next;
};

/**
 * first mem header is just a dummy to chain 
 * the others on it...
 */
memory_header_t first_header = {
	magic: MEMORY_HEADER_MAGIC,
	bytes: 0,
	stack_frame_count: 0,
	previous: NULL,
	next: NULL
};

/**
 * standard hooks, used to temparily remove hooking
 */
void *old_malloc_hook, *old_realloc_hook, *old_free_hook;


pthread_mutex_t mutex = PTHREAD_MUTEX_INITIALIZER;


/**
 * log stack frames queried by backtrace()
 * TODO: Dump symbols of static functions!!!
 */
void log_stack_frames(void *stack_frames, int stack_frame_count)
{
	char **strings;
	size_t i;

	strings = backtrace_symbols (stack_frames, stack_frame_count);

	printf("  dumping %d stack frames.\n", stack_frame_count);

	for (i = 0; i < stack_frame_count; i++)
	{
		printf ("    %s\n", strings[i]);
	}
	free (strings);
}

void (*__malloc_initialize_hook) (void) = install_hooks;

/**
 * Installs the malloc hooks, enables leak detection
 */
void install_hooks()
{
	old_malloc_hook = __malloc_hook;
	old_realloc_hook = __realloc_hook;
	old_free_hook = __free_hook;
	__malloc_hook = malloc_hook;
	__realloc_hook = realloc_hook;
	__free_hook = free_hook;
}

/**
 * Uninstalls the malloc hooks, disables leak detection
 */
void uninstall_hooks()
{
	__malloc_hook = old_malloc_hook;
	__free_hook = old_free_hook;
}

/**
 * Hook function for malloc()
 */
static void *malloc_hook(size_t bytes, const void *caller)
{
	memory_header_t *hdr;
	
	pthread_mutex_lock(&mutex);
	uninstall_hooks();
	hdr = malloc(bytes + sizeof(memory_header_t));
	
	hdr->magic = MEMORY_HEADER_MAGIC;
	hdr->bytes = bytes;
	hdr->stack_frame_count = backtrace(hdr->stack_frames, STACK_FRAMES_COUNT);
	
	/* insert at the beginning of the list */
	hdr->next = first_header.next;
	if (hdr->next)
	{
		hdr->next->previous = hdr;
	}
	hdr->previous = &first_header;
	first_header.next = hdr;
	install_hooks();
	pthread_mutex_unlock(&mutex);
	return hdr + 1;
}

/**
 * Hook function for free()
 */
static void free_hook(void *ptr, const void *caller)
{
	void *stack_frames[STACK_FRAMES_COUNT];
	int stack_frame_count;
	memory_header_t *hdr = ptr - sizeof(memory_header_t);
	
	/* allow freeing of NULL */
	if (ptr == NULL)
	{
		return;
	}
	
	pthread_mutex_lock(&mutex);
	if (hdr->magic != MEMORY_HEADER_MAGIC)
	{
		pthread_mutex_unlock(&mutex);
		/* TODO: Since we get a lot of theses from the pthread lib, its deactivated for now... */
		return;
		printf("freeing of invalid memory (%p)\n", ptr);
		stack_frame_count = backtrace(stack_frames, STACK_FRAMES_COUNT);
		log_stack_frames(stack_frames, stack_frame_count);
		kill(0, SIGSEGV);
		return;
	}
	/* remove magic from hdr */
	hdr->magic = 0;
	
	/* remove item from list */
	if (hdr->next)
	{
		hdr->next->previous = hdr->previous;
	}
	hdr->previous->next = hdr->next;
	
	uninstall_hooks();
	free(hdr);
	install_hooks();
	pthread_mutex_unlock(&mutex);
}

/**
 * Hook function for realloc()
 */
static void *realloc_hook(void *old, size_t bytes, const void *caller)
{
	void *new;
	memory_header_t *hdr = old - sizeof(memory_header_t);
	void *stack_frames[STACK_FRAMES_COUNT];
	int stack_frame_count;
	
	/* allow reallocation of NULL */
	if (old == NULL)
	{
		return malloc_hook(bytes, caller);
	}
	if (hdr->magic != MEMORY_HEADER_MAGIC)
	{
		printf("reallocation of invalid memory (%p)\n", old);
		stack_frame_count = backtrace(stack_frames, STACK_FRAMES_COUNT);
		log_stack_frames(stack_frames, stack_frame_count);
		kill(0, SIGSEGV);
		return NULL;
	}
	
	/* malloc and free is done with hooks */
	new = malloc_hook(bytes, caller);
	memcpy(new, old, min(bytes, hdr->bytes));
	free_hook(old, caller);
	
	return new;
}

/**
 * Report leaks at library destruction
 */
void __attribute__ ((destructor)) report_leaks()
{
	memory_header_t *hdr;
	int leaks = 0;
	
	for (hdr = first_header.next; hdr != NULL; hdr = hdr->next)
	{
		printf("Leak (%d bytes at %p)\n", hdr->bytes, hdr + 1);
		log_stack_frames(hdr->stack_frames, hdr->stack_frame_count);
		leaks++;
	}
	switch (leaks)
	{
		case 0:
			printf("No leaks detected\n");
			break;
		case 1:
			printf("One leak detected\n");
			break;
		default:
			printf("%d leaks detected\n", leaks);
			break;
	}
}

/*
 * The following glibc functions are excluded from leak detection, since
 * they use static allocated buffers or other ugly allocation hacks.
 * The Makefile links theses function preferred to their counterparts
 * in the target lib...
 * TODO: Generic handling would be nice, with a list of blacklisted
 * functions.
 */


char *inet_ntoa(struct in_addr in)
{
	char *(*_inet_ntoa)(struct in_addr);
	void *handle;
	char *result;
	
	pthread_mutex_lock(&mutex);
	uninstall_hooks();
	
	handle = dlopen("libc.so.6", RTLD_LAZY);
	if (handle == NULL)
	{
		kill(0, SIGSEGV);
	}
	_inet_ntoa = dlsym(handle, "inet_ntoa");
	
	if (_inet_ntoa == NULL)
	{
		kill(0, SIGSEGV);
	}
	result = _inet_ntoa(in);
	dlclose(handle);
	install_hooks();
	pthread_mutex_unlock(&mutex);
	return result;
}


int pthread_create(pthread_t *__restrict __threadp, __const pthread_attr_t *__restrict __attr, 
					void *(*__start_routine) (void *), void *__restrict __arg)
{
	int (*_pthread_create) (pthread_t *__restrict __threadp,
						__const pthread_attr_t *__restrict __attr,
						void *(*__start_routine) (void *),
						void *__restrict __arg);
	void *handle;
	int result;
	
	pthread_mutex_lock(&mutex);
	uninstall_hooks();
	
	handle = dlopen("libpthread.so.0", RTLD_LAZY);
	if (handle == NULL)
	{
		kill(0, SIGSEGV);
	}
	_pthread_create = dlsym(handle, "pthread_create");
	
	if (_pthread_create == NULL)
	{
		kill(0, SIGSEGV);
	}
	result = _pthread_create(__threadp, __attr, __start_routine, __arg);
	dlclose(handle);
	install_hooks();
	pthread_mutex_unlock(&mutex);
	return result;
}


time_t mktime(struct tm *tm)
{
	time_t (*_mktime)(struct tm *tm);
	time_t result;
	void *handle;

	pthread_mutex_lock(&mutex);
	uninstall_hooks();

	handle = dlopen("libc.so.6", RTLD_LAZY);
	if (handle == NULL)
	{
		kill(0, SIGSEGV);
	}
	_mktime = dlsym(handle, "mktime");

	if (_mktime == NULL)
	{
		kill(0, SIGSEGV);
	}
	result = _mktime(tm);
	dlclose(handle);
	install_hooks();
	pthread_mutex_unlock(&mutex);
	return result;
}

#endif /* LEAK_DETECTION */
