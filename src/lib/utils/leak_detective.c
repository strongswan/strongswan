/**
 * @file leak_detective.c
 * 
 * @brief Allocation hooks to find memory leaks.
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
#include <string.h>
#include <stdio.h>
#include <malloc.h>
#include <execinfo.h>
#include <signal.h> 
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <dlfcn.h>
#include <unistd.h>
#include <syslog.h>
#include <pthread.h>

#include "leak_detective.h"

#include <types.h>
#include <utils/logger_manager.h>

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
static void load_excluded_functions();

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
static memory_header_t first_header = {
	magic: MEMORY_HEADER_MAGIC,
	bytes: 0,
	stack_frame_count: 0,
	previous: NULL,
	next: NULL
};

/**
 * logger for the leak detective
 */
static logger_t *logger;

/**
 * standard hooks, used to temparily remove hooking
 */
static void *old_malloc_hook, *old_realloc_hook, *old_free_hook;

/**
 * are the hooks currently installed? 
 */
static bool installed = FALSE;

/**
 * Mutex to exclusivly uninstall hooks, access heap list
 */
static pthread_mutex_t mutex = PTHREAD_MUTEX_INITIALIZER;


/**
 * log stack frames queried by backtrace()
 * TODO: Dump symbols of static functions!!!
 */
static void log_stack_frames(void **stack_frames, int stack_frame_count)
{
	char **strings;
	size_t i;

	strings = backtrace_symbols (stack_frames, stack_frame_count);

	logger->log(logger, ERROR, "  dumping %d stack frame addresses.", stack_frame_count);

	for (i = 0; i < stack_frame_count; i++)
	{
		logger->log(logger, ERROR, "    %s", strings[i]);
	}
	free (strings);
}

/**
 * Report leaks at library destruction
 */
void report_leaks()
{
	memory_header_t *hdr;
	int leaks = 0;
	
	/* reaquire a logger is necessary, this will force ((destructor))
	* order to work correctly */
	logger = logger_manager->get_logger(logger_manager, LEAK_DETECT);
	for (hdr = first_header.next; hdr != NULL; hdr = hdr->next)
	{
		logger->log(logger, ERROR, "Leak (%d bytes at %p)", hdr->bytes, hdr + 1);
		log_stack_frames(hdr->stack_frames, hdr->stack_frame_count);
		leaks++;
	}
		
	switch (leaks)
	{
		case 0:
			logger->log(logger, CONTROL, "No leaks detected");
			break;
		case 1:
			logger->log(logger, ERROR, "One leak detected");
			break;
		default:
			logger->log(logger, ERROR, "%d leaks detected", leaks);
			break;
	}
}

/**
 * Installs the malloc hooks, enables leak detection
 */
static void install_hooks()
{
	if (!installed)
	{
		old_malloc_hook = __malloc_hook;
		old_realloc_hook = __realloc_hook;
		old_free_hook = __free_hook;
		__malloc_hook = malloc_hook;
		__realloc_hook = realloc_hook;
		__free_hook = free_hook;
		installed = TRUE;
	}
}

/**
 * Uninstalls the malloc hooks, disables leak detection
 */
static void uninstall_hooks()
{
	if (installed)
	{
		__malloc_hook = old_malloc_hook;
		__free_hook = old_free_hook;
		__realloc_hook = old_realloc_hook;
		installed = FALSE;
	}
}

/**
 * Hook function for malloc()
 */
void *malloc_hook(size_t bytes, const void *caller)
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
void free_hook(void *ptr, const void *caller)
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
		/* TODO: since pthread_join cannot be excluded cleanly, we are not whining about bad frees */
		return;
		logger->log(logger, ERROR, "freeing of invalid memory (%p)", ptr);
		stack_frame_count = backtrace(stack_frames, STACK_FRAMES_COUNT);
		log_stack_frames(stack_frames, stack_frame_count);
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
void *realloc_hook(void *old, size_t bytes, const void *caller)
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
		logger->log(logger, ERROR, "reallocation of invalid memory (%p)", old);
		stack_frame_count = backtrace(stack_frames, STACK_FRAMES_COUNT);
		log_stack_frames(stack_frames, stack_frame_count);
		kill(getpid(), SIGKILL);
		return NULL;
	}
	
	/* malloc and free is done with hooks */
	new = malloc_hook(bytes, caller);
	memcpy(new, old, min(bytes, hdr->bytes));
	free_hook(old, caller);
	
	return new;
}


/**
 * Setup leak detective
 */
void leak_detective_init()
{
	logger = logger_manager->get_logger(logger_manager, LEAK_DETECT);
	load_excluded_functions();
	install_hooks();
}

/**
 * Clean up leak detective
 */
void leak_detective_cleanup()
{
	uninstall_hooks();
	report_leaks();
}


/**
 * The following glibc functions are excluded from leak detection, since
 * they use static allocated buffers or other ugly allocation hacks.
 * For this to work, the linker must link libstrongswan preferred to
 * the other (overriden) libs.
 */
struct excluded_function {
	char *lib_name;
	char *function_name;
	void *handle;
	void *lib_function;
} excluded_functions[] = {
	{"libc.so.6", 		"inet_ntoa", 			NULL, NULL},
	{"libpthread.so.0", "pthread_create", 		NULL, NULL},
	{"libpthread.so.0", "pthread_cancel", 		NULL, NULL},
	{"libpthread.so.0", "pthread_join", 		NULL, NULL},
	{"libpthread.so.0", "_pthread_cleanup_push",NULL, NULL},
	{"libpthread.so.0", "_pthread_cleanup_pop",	NULL, NULL},
	{"libc.so.6", 		"mktime", 				NULL, NULL},
	{"libc.so.6", 		"vsyslog", 				NULL, NULL},
	{"libc.so.6", 		"strerror", 			NULL, NULL},
};
#define INET_NTOA				0
#define PTHREAD_CREATE			1
#define PTHREAD_CANCEL			2
#define PTHREAD_JOIN			3
#define PTHREAD_CLEANUP_PUSH	4
#define PTHREAD_CLEANUP_POP		5
#define MKTIME					6
#define VSYSLOG					7
#define STRERROR				8


/**
 * Load libraries and function pointers for excluded functions
 */
static void load_excluded_functions()
{
	int i;
	
	for (i = 0; i < sizeof(excluded_functions)/sizeof(struct excluded_function); i++)
	{
		void *handle, *function;
		handle = dlopen(excluded_functions[i].lib_name, RTLD_LAZY);
		if (handle == NULL)
		{
			kill(getpid(), SIGSEGV);
		}
		
		function = dlsym(handle, excluded_functions[i].function_name);
		
		if (function  == NULL)
		{
			dlclose(handle);
			kill(getpid(), SIGSEGV);
		}
		excluded_functions[i].handle = handle;
		excluded_functions[i].lib_function = function;
	}
}

char *inet_ntoa(struct in_addr in)
{
	char *(*_inet_ntoa)(struct in_addr) = excluded_functions[INET_NTOA].lib_function;
	char *result;
	
	pthread_mutex_lock(&mutex);
	uninstall_hooks();
	
	result = _inet_ntoa(in);
	
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
						void *__restrict __arg) = excluded_functions[PTHREAD_CREATE].lib_function;
	int result;
	
	pthread_mutex_lock(&mutex);
	uninstall_hooks();
	
	result = _pthread_create(__threadp, __attr, __start_routine, __arg);
	
	install_hooks();
	pthread_mutex_unlock(&mutex);
	return result;
}


int pthread_cancel(pthread_t __th)
{
	int (*_pthread_cancel) (pthread_t) = excluded_functions[PTHREAD_CANCEL].lib_function;
	int result;
	
	pthread_mutex_lock(&mutex);
	uninstall_hooks();
	
	result = _pthread_cancel(__th);
	
	install_hooks();
	pthread_mutex_unlock(&mutex);
	return result;
}

// /* TODO: join has probs, since it dellocates memory 
//  * allocated (somewhere) with leak_detective :-(.
//  * We should exclude all pthread_ functions to fix it !? */
// int pthread_join(pthread_t __th, void **__thread_return)
// {
// 	int (*_pthread_join) (pthread_t, void **) = excluded_functions[PTHREAD_JOIN].lib_function;
// 	int result;
// 	
// 	pthread_mutex_lock(&mutex);
// 	uninstall_hooks();
// 	
// 	result = _pthread_join(__th, __thread_return);
// 	
// 	install_hooks();
// 	pthread_mutex_unlock(&mutex);
// 	return result;
// }
// 
// void _pthread_cleanup_push (struct _pthread_cleanup_buffer *__buffer,
// 								   void (*__routine) (void *),
// 								   void *__arg)
// {
// 	int (*__pthread_cleanup_push) (struct _pthread_cleanup_buffer *__buffer,
// 									void (*__routine) (void *),
// 									void *__arg) = 
// 			excluded_functions[PTHREAD_CLEANUP_PUSH].lib_function;
// 	
// 	pthread_mutex_lock(&mutex);
// 	uninstall_hooks();
// 	
// 	__pthread_cleanup_push(__buffer, __routine, __arg);
// 	
// 	install_hooks();
// 	pthread_mutex_unlock(&mutex);
// 	return;
// }
// 	
// void _pthread_cleanup_pop (struct _pthread_cleanup_buffer *__buffer, int __execute)
// {
// 	int (*__pthread_cleanup_pop) (struct _pthread_cleanup_buffer *__buffer, int __execute) = 
// 			excluded_functions[PTHREAD_CLEANUP_POP].lib_function;
// 	
// 	pthread_mutex_lock(&mutex);
// 	uninstall_hooks();
// 	
// 	__pthread_cleanup_pop(__buffer, __execute);
// 	
// 	install_hooks();
// 	pthread_mutex_unlock(&mutex);
// 	return;
// }

time_t mktime(struct tm *tm)
{
	time_t (*_mktime)(struct tm *tm) = excluded_functions[MKTIME].lib_function;
	time_t result;

	pthread_mutex_lock(&mutex);
	uninstall_hooks();
		
	result = _mktime(tm);
	
	install_hooks();
	pthread_mutex_unlock(&mutex);
	return result;
}

void vsyslog (int __pri, __const char *__fmt, __gnuc_va_list __ap)
{
	void (*_vsyslog) (int __pri, __const char *__fmt, __gnuc_va_list __ap) = excluded_functions[VSYSLOG].lib_function;

	pthread_mutex_lock(&mutex);
	uninstall_hooks();
	
	_vsyslog(__pri, __fmt, __ap);
	
	install_hooks();
	pthread_mutex_unlock(&mutex);
	return;
}



char *strerror(int errnum)
{
	char* (*_strerror) (int) = excluded_functions[STRERROR].lib_function;
	char *result;

	pthread_mutex_lock(&mutex);
	uninstall_hooks();
	
	result = _strerror(errnum);
	
	install_hooks();
	pthread_mutex_unlock(&mutex);
	return result;
}

#endif /* LEAK_DETECTION */
