/*
 * Copyright (C) 2006-2008 Martin Willi
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
 *
 * $Id$
 */

#ifdef HAVE_DLADDR
# define _GNU_SOURCE
# include <dlfcn.h>
#endif /* HAVE_DLADDR */
	
#include <stddef.h>
#include <string.h>
#include <stdio.h>
#include <malloc.h>
#include <signal.h> 
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <dlfcn.h>
#include <unistd.h>
#include <syslog.h>
#include <pthread.h>
#include <netdb.h>
#include <printf.h>
#include <locale.h>
#ifdef HAVE_BACKTRACE
# include <execinfo.h>
#endif /* HAVE_BACKTRACE */

#include "leak_detective.h"

#include <library.h>
#include <debug.h>

typedef struct private_leak_detective_t private_leak_detective_t;

/**
 * private data of leak_detective
 */
struct private_leak_detective_t {

	/**
	 * public functions
	 */
	leak_detective_t public;
};

/**
 * Magic value which helps to detect memory corruption. Yummy!
 */
#define MEMORY_HEADER_MAGIC 0x7ac0be11

/**
 * Magic written to tail of allocation
 */
#define MEMORY_TAIL_MAGIC 0xcafebabe

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
typedef struct memory_tail_t memory_tail_t;

/**
 * Header which is prepended to each allocated memory block
 */
struct memory_header_t {
	
	/**
	 * Number of bytes following after the header
	 */
	u_int bytes;
	
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
	
	/**
	 * magic bytes to detect bad free or heap underflow, MEMORY_HEADER_MAGIC
	 */
	u_int32_t magic;
	
}__attribute__((__packed__));

/**
 * tail appended to each allocated memory block
 */
struct memory_tail_t {

	/**
	 * Magic bytes to detect heap overflow, MEMORY_TAIL_MAGIC
	 */
	u_int32_t magic;
	
}__attribute__((__packed__));

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
 * standard hooks, used to temparily remove hooking
 */
static void *old_malloc_hook, *old_realloc_hook, *old_free_hook;

/**
 * are the hooks currently installed? 
 */
static bool installed = FALSE;

/**
 * log stack frames queried by backtrace()
 * TODO: Dump symbols of static functions. This could be done with
 * the addr2line utility or the GNU BFD Library...
 */
static void log_stack_frames(void **stack_frames, int stack_frame_count)
{
#ifdef HAVE_BACKTRACE
	char **strings;
	size_t i;

	strings = backtrace_symbols(stack_frames, stack_frame_count);

	fprintf(stderr, " dumping %d stack frame addresses\n", stack_frame_count);

	for (i = 0; i < stack_frame_count; i++)
	{
#ifdef HAVE_DLADDR
		Dl_info info;
		
		/* TODO: this is quite hackish, but it works. A more proper solution
		 * would execve addr2strongline and pipe the output to DBG1() */
		if (dladdr(stack_frames[i], &info))
		{
			char cmd[1024];
			void *ptr = stack_frames[i];
			
			if (strstr(info.dli_fname, ".so"))
			{
				ptr = (void*)(stack_frames[i] - info.dli_fbase);
			}
			snprintf(cmd, sizeof(cmd), "addr2line -e %s %p", info.dli_fname, ptr);
			if (info.dli_sname)
			{
				fprintf(stderr, "  \e[33m%s\e[0m @ %p (\e[31m%s+0x%x\e[0m) [%p]\n",
						info.dli_fname, info.dli_fbase, info.dli_sname,
						stack_frames[i] - info.dli_saddr, stack_frames[i]);
			}
			else
			{
				fprintf(stderr, "  \e[33m%s\e[0m @ %p [%p]\n", info.dli_fname,
						info.dli_fbase, stack_frames[i]);
			}
			fprintf(stderr, "    -> \e[32m");
			system(cmd);
			fprintf(stderr, "\e[0m");
		}
		else
#endif /* HAVE_DLADDR */
		{
			fprintf(stderr, "    %s\n", strings[i]);
		}
	}
	free (strings);
#endif /* HAVE_BACKTRACE */
}

/**
 * Leak report white list
 *
 * List of functions using static allocation buffers or should be suppressed
 * otherwise on leak report. 
 */
char *whitelist[] = {
	/* pthread stuff */
	"pthread_create",
	"pthread_setspecific",
	/* glibc functions */
	"mktime",
	"tzset",
	"inet_ntoa",
	"strerror",
	"getprotobynumber",
	"getservbyport",
	"getservbyname",
	"register_printf_function",
	"syslog",
	"vsyslog",
	"getaddrinfo",
	"setlocale",
	/* ignore dlopen, as we do not dlclose to get proper leak reports */
	"dlopen",
	/* mysql functions */
	"mysql_init_character_set",
	"init_client_errs",
	"my_thread_init",
	/* fastcgi library */
	"FCGX_Init",
	/* libxml */
	"xmlInitCharEncodingHandlers",
	"xmlInitParser",
	"xmlInitParserCtxt",
	/* ClearSilver */
	"nerr_init",
};

/**
 * check if a stack frame contains functions listed above
 */
static bool is_whitelisted(void **stack_frames, int stack_frame_count)
{
	int i, j;
	
#ifdef HAVE_DLADDR
	for (i=0; i< stack_frame_count; i++)
	{
		Dl_info info;
		
		if (dladdr(stack_frames[i], &info) && info.dli_sname)
		{	
			for (j = 0; j < sizeof(whitelist)/sizeof(char*); j++)
			{
				if (streq(info.dli_sname, whitelist[j]))
				{
					return TRUE;
				}
			}
		}
	}
#endif /* HAVE_DLADDR */
	return FALSE;
}

/**
 * Report leaks at library destruction
 */
void report_leaks()
{
	memory_header_t *hdr;
	int leaks = 0, whitelisted = 0;
	
	for (hdr = first_header.next; hdr != NULL; hdr = hdr->next)
	{
		if (is_whitelisted(hdr->stack_frames, hdr->stack_frame_count))
		{
			whitelisted++;
		}
		else
		{
			fprintf(stderr, "Leak (%d bytes at %p):\n", hdr->bytes, hdr + 1);
			/* skip the first frame, contains leak detective logic */
			log_stack_frames(hdr->stack_frames + 1, hdr->stack_frame_count - 1);
			leaks++;
		}
	}
		
	switch (leaks)
	{
		case 0:
			fprintf(stderr, "No leaks detected");
			break;
		case 1:
			fprintf(stderr, "One leak detected");
			break;
		default:
			fprintf(stderr, "%d leaks detected", leaks);
			break;
	}
	fprintf(stderr, ", %d suppressed by whitelist\n", whitelisted);
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
	memory_tail_t *tail;
	pthread_t thread_id = pthread_self();
    int oldpolicy;
    struct sched_param oldparams, params;
    
    pthread_getschedparam(thread_id, &oldpolicy, &oldparams);
    
    params.__sched_priority = sched_get_priority_max(SCHED_FIFO);
	pthread_setschedparam(thread_id, SCHED_FIFO, &params);
	
	count_malloc++;
	uninstall_hooks();
	hdr = malloc(sizeof(memory_header_t) + bytes + sizeof(memory_tail_t));
	tail = ((void*)hdr) + bytes + sizeof(memory_header_t);
	/* set to something which causes crashes */
	memset(hdr, MEMORY_ALLOC_PATTERN,
		   sizeof(memory_header_t) + bytes + sizeof(memory_tail_t));
	
	hdr->magic = MEMORY_HEADER_MAGIC;
	hdr->bytes = bytes;
	hdr->stack_frame_count = backtrace(hdr->stack_frames, STACK_FRAMES_COUNT);
	tail->magic = MEMORY_TAIL_MAGIC;
	install_hooks();
	
	/* insert at the beginning of the list */
	hdr->next = first_header.next;
	if (hdr->next)
	{
		hdr->next->previous = hdr;
	}
	hdr->previous = &first_header;
	first_header.next = hdr;
	
	pthread_setschedparam(thread_id, oldpolicy, &oldparams);
	
	return hdr + 1;
}

/**
 * Hook function for free()
 */
void free_hook(void *ptr, const void *caller)
{
	void *stack_frames[STACK_FRAMES_COUNT];
	int stack_frame_count;
	memory_header_t *hdr;
	memory_tail_t *tail;
	pthread_t thread_id = pthread_self();
    int oldpolicy;
    struct sched_param oldparams, params;
    
	/* allow freeing of NULL */
	if (ptr == NULL)
	{
		return;
	}
	hdr = ptr - sizeof(memory_header_t);
	tail = ptr + hdr->bytes;
	
	pthread_getschedparam(thread_id, &oldpolicy, &oldparams);
	
    params.__sched_priority = sched_get_priority_max(SCHED_FIFO);
	pthread_setschedparam(thread_id, SCHED_FIFO, &params);
	
	count_free++;
	uninstall_hooks();
	if (hdr->magic != MEMORY_HEADER_MAGIC ||
		tail->magic != MEMORY_TAIL_MAGIC)
	{
		fprintf(stderr, "freeing invalid memory (%p): "
				"header magic 0x%x, tail magic 0x%x:\n",
				ptr, hdr->magic, tail->magic);
		stack_frame_count = backtrace(stack_frames, STACK_FRAMES_COUNT);
		log_stack_frames(stack_frames, stack_frame_count);
	}
	else
	{
		/* remove item from list */
		if (hdr->next)
		{
			hdr->next->previous = hdr->previous;
		}
		hdr->previous->next = hdr->next;
	
		/* clear MAGIC, set mem to something remarkable */
		memset(hdr, MEMORY_FREE_PATTERN, hdr->bytes + sizeof(memory_header_t));
	
		free(hdr);
	}
	
	install_hooks();
	pthread_setschedparam(thread_id, oldpolicy, &params);
}

/**
 * Hook function for realloc()
 */
void *realloc_hook(void *old, size_t bytes, const void *caller)
{
	memory_header_t *hdr;
	void *stack_frames[STACK_FRAMES_COUNT];
	int stack_frame_count;
	memory_tail_t *tail;
	pthread_t thread_id = pthread_self();
    int oldpolicy;
    struct sched_param oldparams, params;
    
	/* allow reallocation of NULL */
	if (old == NULL)
	{
		return malloc_hook(bytes, caller);
	}
	
	hdr = old - sizeof(memory_header_t);
	tail = old + hdr->bytes;
	
	pthread_getschedparam(thread_id, &oldpolicy, &oldparams);
	
	params.__sched_priority = sched_get_priority_max(SCHED_FIFO);
	pthread_setschedparam(thread_id, SCHED_FIFO, &params);
	
	count_realloc++;
	uninstall_hooks();
	if (hdr->magic != MEMORY_HEADER_MAGIC ||
		tail->magic != MEMORY_TAIL_MAGIC)
	{
		fprintf(stderr, "reallocating invalid memory (%p): "
				"header magic 0x%x, tail magic 0x%x:\n",
				old, hdr->magic, tail->magic);
		stack_frame_count = backtrace(stack_frames, STACK_FRAMES_COUNT);
		log_stack_frames(stack_frames, stack_frame_count);
	}
	/* clear tail magic, allocate, set tail magic */
	memset(&tail->magic, MEMORY_ALLOC_PATTERN, sizeof(tail->magic));
	hdr = realloc(hdr, sizeof(memory_header_t) + bytes + sizeof(memory_tail_t));
	tail = ((void*)hdr) + bytes + sizeof(memory_header_t);
	tail->magic = MEMORY_TAIL_MAGIC;

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
	pthread_setschedparam(thread_id, oldpolicy, &oldparams);
	return hdr + 1;
}

/**
 * Implementation of leak_detective_t.destroy
 */
static void destroy(private_leak_detective_t *this)
{
	if (installed)
	{
		uninstall_hooks();
		report_leaks();
	}
	free(this);
}

/*
 * see header file
 */
leak_detective_t *leak_detective_create()
{
	private_leak_detective_t *this = malloc_thing(private_leak_detective_t);
	
	this->public.destroy = (void(*)(leak_detective_t*))destroy;
	
	if (getenv("LEAK_DETECTIVE_DISABLE") == NULL)
	{
		install_hooks();
	}
	return &this->public;
}

