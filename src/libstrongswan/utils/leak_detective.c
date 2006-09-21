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
#include <netdb.h>

#include "leak_detective.h"

#include <types.h>

#ifdef LEAK_DETECTIVE

/**
 * Magic value which helps to detect memory corruption. Yummy!
 */
#define MEMORY_HEADER_MAGIC 0x7ac0be11

/**
 * Pattern which is filled in memory before freeing it
 */
#define MEMORY_FREE_PATTERN 0xFF

/**
 * Pattern which is filled in newly allocated memory
 */
#define MEMORY_ALLOC_PATTERN 0xEE


static void install_hooks(void);
static void uninstall_hooks(void);
static void *malloc_hook(size_t, const void *);
static void *realloc_hook(void *, size_t, const void *);
static void free_hook(void*, const void *);

static u_int count_malloc = 0;
static u_int count_free = 0;
static u_int count_realloc = 0;

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

	logger->log(logger, ERROR, "  dumping %d stack frame addresses", stack_frame_count);

	for (i = 0; i < stack_frame_count; i++)
	{
		logger->log(logger, ERROR, "    %s", strings[i]);
	}
	free (strings);
}

/**
 * Whitelist, which contains address ranges in stack frames ignored when leaking.
 * 
 * This is necessary, as some function use allocation hacks (static buffers)
 * and so on, which we want to suppress on leak reports.
 */
typedef struct whitelist_t whitelist_t;

struct whitelist_t {
	void* range_start;
	size_t range_size;
};

whitelist_t whitelist[] = {
	{pthread_create, 0x500},
	{pthread_setspecific, 0xFF},
	{mktime, 0xFF},
	{inet_ntoa, 0xFF},
	{strerror, 0xFF},
	{getprotobynumber, 0xFF},
	{getservbyport, 0xFF},
};

/**
 * Check if this stack frame is whitelisted.
 */
static bool is_whitelisted(void **stack_frames, int stack_frame_count)
{
	int i, j;
	
	for (i=0; i< stack_frame_count; i++)
	{
		for (j=0; j<sizeof(whitelist)/sizeof(whitelist_t); j++)
		{
			if (stack_frames[i] >= whitelist[j].range_start &&
				stack_frames[i] <= (whitelist[j].range_start + whitelist[j].range_size))
			{
				return TRUE;
			}
		}
	}
	return FALSE;
}

/**
 * Report leaks at library destruction
 */
void report_leaks()
{
	memory_header_t *hdr;
	int leaks = 0;
	
	for (hdr = first_header.next; hdr != NULL; hdr = hdr->next)
	{
		if (!is_whitelisted(hdr->stack_frames, hdr->stack_frame_count))
		{
			logger->log(logger, ERROR, "Leak (%d bytes at %p):", hdr->bytes, hdr + 1);
			log_stack_frames(hdr->stack_frames, hdr->stack_frame_count);
			leaks++;
		}
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
	count_malloc++;
	uninstall_hooks();
	hdr = malloc(bytes + sizeof(memory_header_t));
	/* set to something which causes crashes */
	memset(hdr, MEMORY_ALLOC_PATTERN, bytes + sizeof(memory_header_t));
	
	hdr->magic = MEMORY_HEADER_MAGIC;
	hdr->bytes = bytes;
	hdr->stack_frame_count = backtrace(hdr->stack_frames, STACK_FRAMES_COUNT);
	install_hooks();
	
	/* insert at the beginning of the list */
	hdr->next = first_header.next;
	if (hdr->next)
	{
		hdr->next->previous = hdr;
	}
	hdr->previous = &first_header;
	first_header.next = hdr;
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
	count_free++;
	uninstall_hooks();
	if (hdr->magic != MEMORY_HEADER_MAGIC)
	{
		logger->log(logger, ERROR, "freeing of invalid memory (%p, MAGIC 0x%x != 0x%x):", 
					ptr, hdr->magic, MEMORY_HEADER_MAGIC);
		stack_frame_count = backtrace(stack_frames, STACK_FRAMES_COUNT);
		log_stack_frames(stack_frames, stack_frame_count);
		install_hooks();
		pthread_mutex_unlock(&mutex);
		return;
	}
	
	/* remove item from list */
	if (hdr->next)
	{
		hdr->next->previous = hdr->previous;
	}
	hdr->previous->next = hdr->next;
	
	/* clear MAGIC, set mem to something remarkable */
	memset(hdr, MEMORY_FREE_PATTERN, hdr->bytes + sizeof(memory_header_t));
	
	free(hdr);
	install_hooks();
	pthread_mutex_unlock(&mutex);
}

/**
 * Hook function for realloc()
 */
void *realloc_hook(void *old, size_t bytes, const void *caller)
{
	memory_header_t *hdr;
	void *stack_frames[STACK_FRAMES_COUNT];
	int stack_frame_count;
	
	/* allow reallocation of NULL */
	if (old == NULL)
	{
		return malloc_hook(bytes, caller);
	}
	
	hdr = old - sizeof(memory_header_t);
	
	pthread_mutex_lock(&mutex);
	count_realloc++;
	uninstall_hooks();
	if (hdr->magic != MEMORY_HEADER_MAGIC)
	{
		logger->log(logger, ERROR, "reallocation of invalid memory (%p):", old);
		stack_frame_count = backtrace(stack_frames, STACK_FRAMES_COUNT);
		log_stack_frames(stack_frames, stack_frame_count);
		install_hooks();
		pthread_mutex_unlock(&mutex);
		raise(SIGKILL);
		return NULL;
	}
	
	hdr = realloc(hdr, bytes + sizeof(memory_header_t));
	
	/* update statistics */
	hdr->bytes = bytes;
	hdr->stack_frame_count = backtrace(hdr->stack_frames, STACK_FRAMES_COUNT);
	
	/* update header of linked list neighbours */
	if (hdr->next)
	{
		hdr->next->previous = hdr;
	}
	hdr->previous->next = hdr;
	install_hooks();
	pthread_mutex_unlock(&mutex);
	return hdr + 1;
}

/**
 * Setup leak detective
 */
void leak_detective_init()
{
	logger = logger_manager->get_logger(logger_manager, LEAK_DETECT);
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
 * Log memory allocation statistics
 */
void leak_detective_status(logger_t *logger)
{
	u_int blocks = 0;
	size_t bytes = 0;
	memory_header_t *hdr = &first_header;
	
	pthread_mutex_lock(&mutex);
	while ((hdr = hdr->next))
	{
		blocks++;
		bytes += hdr->bytes;
	}
	pthread_mutex_unlock(&mutex);
	
	logger->log(logger, CONTROL|LEVEL1, "allocation statistics:");
	logger->log(logger, CONTROL|LEVEL1, "  call stats: malloc: %d, free: %d, realloc: %d",
			count_malloc, count_free, count_realloc);
	logger->log(logger, CONTROL|LEVEL1, "  allocated %d blocks, total size %d bytes (avg. %d bytes)",
			blocks, bytes, bytes/blocks);
}

#else /* !LEAK_DETECTION */

/**
 * Dummy when !using LEAK_DETECTIVE
 */
void leak_detective_status(logger_t *logger)
{

}

#endif /* LEAK_DETECTION */
