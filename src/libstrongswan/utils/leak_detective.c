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
 */

#define _GNU_SOURCE
#include <sched.h>
#include <stddef.h>
#include <string.h>
#include <stdio.h>
#include <malloc.h>
#include <signal.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <syslog.h>
#include <pthread.h>
#include <netdb.h>
#include <locale.h>

#include "leak_detective.h"

#include <library.h>
#include <utils/debug.h>
#include <utils/backtrace.h>
#include <collections/hashtable.h>

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

void *(*old_malloc_hook)(size_t, const void *);
void *(*old_realloc_hook)(void *, size_t, const void *);
void (*old_free_hook)(void*, const void *);

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
	 * Pointer to previous entry in linked list
	 */
	memory_header_t *previous;

	/**
	 * Pointer to next entry in linked list
	 */
	memory_header_t *next;

	/**
	 * backtrace taken during (re-)allocation
	 */
	backtrace_t *backtrace;

	/**
	 * Number of bytes following after the header
	 */
	u_int32_t bytes;

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
	backtrace: NULL,
	previous: NULL,
	next: NULL
};

/**
 * are the hooks currently installed?
 */
static bool installed = FALSE;

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
 * Leak report white list
 *
 * List of functions using static allocation buffers or should be suppressed
 * otherwise on leak report.
 */
char *whitelist[] = {
	/* backtraces, including own */
	"backtrace_create",
	"safe_strerror",
	/* pthread stuff */
	"pthread_create",
	"pthread_setspecific",
	"__pthread_setspecific",
	/* glibc functions */
	"mktime",
	"ctime",
	"__gmtime_r",
	"localtime_r",
	"tzset",
	"time_printf_hook",
	"inet_ntoa",
	"strerror",
	"getprotobyname",
	"getprotobynumber",
	"getservbyport",
	"getservbyname",
	"gethostbyname",
	"gethostbyname2",
	"gethostbyname_r",
	"gethostbyname2_r",
	"getnetbyname",
	"getpwnam_r",
	"getgrnam_r",
	"register_printf_function",
	"register_printf_specifier",
	"syslog",
	"vsyslog",
	"__syslog_chk",
	"__vsyslog_chk",
	"getaddrinfo",
	"setlocale",
	"getpass",
	"getpwent_r",
	"setpwent",
	"endpwent",
	"getspnam_r",
	"getpwuid_r",
	"initgroups",
	/* ignore dlopen, as we do not dlclose to get proper leak reports */
	"dlopen",
	"dlerror",
	"dlclose",
	"dlsym",
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
	/* libcurl */
	"Curl_client_write",
	/* ClearSilver */
	"nerr_init",
	/* OpenSSL */
	"RSA_new_method",
	"DH_new_method",
	"ENGINE_load_builtin_engines",
	"OPENSSL_config",
	"ecdsa_check",
	"ERR_put_error",
	/* libgcrypt */
	"gcry_control",
	"gcry_check_version",
	"gcry_randomize",
	"gcry_create_nonce",
	/* NSPR */
	"PR_CallOnce",
	/* libapr */
	"apr_pool_create_ex",
	/* glib */
	"g_type_init_with_debug_flags",
	"g_type_register_static",
	"g_type_class_ref",
	"g_type_create_instance",
	"g_type_add_interface_static",
	"g_type_interface_add_prerequisite",
	"g_socket_connection_factory_lookup_type",
	/* libgpg */
	"gpg_err_init",
	/* gnutls */
	"gnutls_global_init",
};


/**
 * Hashtable hash function
 */
static u_int hash(backtrace_t *key)
{
	enumerator_t *enumerator;
	void *addr;
	u_int hash = 0;

	enumerator = key->create_frame_enumerator(key);
	while (enumerator->enumerate(enumerator, &addr))
	{
		hash = chunk_hash_inc(chunk_from_thing(addr), hash);
	}
	enumerator->destroy(enumerator);

	return hash;
}

/**
 * Hashtable equals function
 */
static bool equals(backtrace_t *a, backtrace_t *b)
{
	return a->equals(a, b);
}

/**
 * Summarize and print backtraces
 */
static int print_traces(private_leak_detective_t *this,
						FILE *out, int thresh, bool detailed, int *whitelisted)
{
	int leaks = 0;
	memory_header_t *hdr;
	enumerator_t *enumerator;
	hashtable_t *entries;
	struct {
		/** associated backtrace */
		backtrace_t *backtrace;
		/** total size of all allocations */
		size_t bytes;
		/** number of allocations */
		u_int count;
	} *entry;

	uninstall_hooks();

	entries = hashtable_create((hashtable_hash_t)hash,
							   (hashtable_equals_t)equals, 1024);
	for (hdr = first_header.next; hdr != NULL; hdr = hdr->next)
	{
		if (whitelisted &&
			hdr->backtrace->contains_function(hdr->backtrace,
											  whitelist, countof(whitelist)))
		{
			(*whitelisted)++;
			continue;
		}
		entry = entries->get(entries, hdr->backtrace);
		if (entry)
		{
			entry->bytes += hdr->bytes;
			entry->count++;
		}
		else
		{
			INIT(entry,
				.backtrace = hdr->backtrace,
				.bytes = hdr->bytes,
				.count = 1,
			);
			entries->put(entries, hdr->backtrace, entry);
		}
		leaks++;
	}
	enumerator = entries->create_enumerator(entries);
	while (enumerator->enumerate(enumerator, NULL, &entry))
	{
		if (!thresh || entry->bytes >= thresh)
		{
			fprintf(out, "%d bytes total, %d allocations, %d bytes average:\n",
					entry->bytes, entry->count, entry->bytes / entry->count);
			entry->backtrace->log(entry->backtrace, out, detailed);
		}
		free(entry);
	}
	enumerator->destroy(enumerator);
	entries->destroy(entries);

	install_hooks();
	return leaks;
}

METHOD(leak_detective_t, report, void,
	private_leak_detective_t *this, bool detailed)
{
	if (lib->leak_detective)
	{
		int leaks = 0, whitelisted = 0;

		leaks = print_traces(this, stderr, 0, detailed, &whitelisted);
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
	else
	{
		fprintf(stderr, "Leak detective disabled\n");
	}
}

METHOD(leak_detective_t, set_state, bool,
	private_leak_detective_t *this, bool enable)
{
	static struct sched_param oldparams;
	static int oldpolicy;
	struct sched_param params;
	pthread_t thread_id;

	if (enable == installed)
	{
		return installed;
	}
	thread_id = pthread_self();
	if (enable)
	{
		install_hooks();
		pthread_setschedparam(thread_id, oldpolicy, &oldparams);
	}
	else
	{
		pthread_getschedparam(thread_id, &oldpolicy, &oldparams);
		params.__sched_priority = sched_get_priority_max(SCHED_FIFO);
		pthread_setschedparam(thread_id, SCHED_FIFO, &params);
		uninstall_hooks();
	}
	installed = enable;
	return !installed;
}

METHOD(leak_detective_t, usage, void,
	private_leak_detective_t *this, FILE *out)
{
	int oldpolicy, thresh;
	bool detailed;
	pthread_t thread_id = pthread_self();
	struct sched_param oldparams, params;

	thresh = lib->settings->get_int(lib->settings,
					"libstrongswan.leak_detective.usage_threshold", 10240);
	detailed = lib->settings->get_bool(lib->settings,
					"libstrongswan.leak_detective.detailed", TRUE);

	pthread_getschedparam(thread_id, &oldpolicy, &oldparams);
	params.__sched_priority = sched_get_priority_max(SCHED_FIFO);
	pthread_setschedparam(thread_id, SCHED_FIFO, &params);

	print_traces(this, out, thresh, detailed, NULL);

	pthread_setschedparam(thread_id, oldpolicy, &oldparams);
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
	hdr->backtrace = backtrace_create(2);
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
	memory_header_t *hdr, *current;
	memory_tail_t *tail;
	backtrace_t *backtrace;
	pthread_t thread_id = pthread_self();
	int oldpolicy;
	struct sched_param oldparams, params;
	bool found = FALSE;

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
		for (current = &first_header; current != NULL; current = current->next)
		{
			if (current == hdr)
			{
				found = TRUE;
				break;
			}
		}
		if (found)
		{
			/* memory was allocated by our hooks but is corrupted */
			fprintf(stderr, "freeing corrupted memory (%p): "
					"header magic 0x%x, tail magic 0x%x:\n",
					ptr, hdr->magic, tail->magic);
		}
		else
		{
			/* memory was not allocated by our hooks */
			fprintf(stderr, "freeing invalid memory (%p)", ptr);
		}
		backtrace = backtrace_create(2);
		backtrace->log(backtrace, stderr, TRUE);
		backtrace->destroy(backtrace);
	}
	else
	{
		/* remove item from list */
		if (hdr->next)
		{
			hdr->next->previous = hdr->previous;
		}
		hdr->previous->next = hdr->next;
		hdr->backtrace->destroy(hdr->backtrace);

		/* clear MAGIC, set mem to something remarkable */
		memset(hdr, MEMORY_FREE_PATTERN,
			   sizeof(memory_header_t) + hdr->bytes + sizeof(memory_tail_t));

		free(hdr);
	}

	install_hooks();
	pthread_setschedparam(thread_id, oldpolicy, &oldparams);
}

/**
 * Hook function for realloc()
 */
void *realloc_hook(void *old, size_t bytes, const void *caller)
{
	memory_header_t *hdr;
	memory_tail_t *tail;
	backtrace_t *backtrace;
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
		fprintf(stderr, "reallocating invalid memory (%p):\n"
				"header magic 0x%x:\n", old, hdr->magic);
		backtrace = backtrace_create(2);
		backtrace->log(backtrace, stderr, TRUE);
		backtrace->destroy(backtrace);
	}
	else
	{
		/* clear tail magic, allocate, set tail magic */
		memset(&tail->magic, MEMORY_ALLOC_PATTERN, sizeof(tail->magic));
	}
	hdr = realloc(hdr, sizeof(memory_header_t) + bytes + sizeof(memory_tail_t));
	tail = ((void*)hdr) + bytes + sizeof(memory_header_t);
	tail->magic = MEMORY_TAIL_MAGIC;

	/* update statistics */
	hdr->bytes = bytes;
	hdr->backtrace->destroy(hdr->backtrace);
	hdr->backtrace = backtrace_create(2);

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

METHOD(leak_detective_t, destroy, void,
	private_leak_detective_t *this)
{
	if (installed)
	{
		uninstall_hooks();
	}
	free(this);
}

/*
 * see header file
 */
leak_detective_t *leak_detective_create()
{
	private_leak_detective_t *this;

	INIT(this,
		.public = {
			.report = _report,
			.usage = _usage,
			.set_state = _set_state,
			.destroy = _destroy,
		},
	);

	if (getenv("LEAK_DETECTIVE_DISABLE") == NULL)
	{
		cpu_set_t mask;

		CPU_ZERO(&mask);
		CPU_SET(0, &mask);

		if (sched_setaffinity(0, sizeof(cpu_set_t), &mask) != 0)
		{
			fprintf(stderr, "setting CPU affinity failed: %m");
		}

		install_hooks();
	}
	return &this->public;
}

