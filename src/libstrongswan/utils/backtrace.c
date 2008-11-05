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

#define _GNU_SOURCE

#ifdef HAVE_DLADDR
# include <dlfcn.h>
#endif /* HAVE_DLADDR */

#ifdef HAVE_BACKTRACE
# include <execinfo.h>
#endif /* HAVE_BACKTRACE */

#include "backtrace.h"

typedef struct private_backtrace_t private_backtrace_t;

/**
 * Private data of an backtrace_t object.
 */
struct private_backtrace_t {
	
	/**
	 * Public backtrace_t interface.
	 */
	backtrace_t public;
	
	/**
	 * Number of stacks frames obtained in stack_frames
	 */
	int frame_count;
	
	/**
	 * Recorded stack frames.
	 */
	void *frames[];
};

/**
 * Implementation of backtrace_t.log
 */
static void log_(private_backtrace_t *this, FILE *file)
{
#ifdef HAVE_BACKTRACE
	size_t i;
	char **strings;
	
	strings = backtrace_symbols(this->frames, this->frame_count);

	fprintf(file, " dumping %d stack frame addresses:\n", this->frame_count);
	for (i = 0; i < this->frame_count; i++)
	{
#ifdef HAVE_DLADDR
		Dl_info info;
		
		if (dladdr(this->frames[i], &info))
		{
			char cmd[1024];
			FILE *output;
			char c;
			void *ptr = this->frames[i];
			
			if (strstr(info.dli_fname, ".so"))
			{
				ptr = (void*)(this->frames[i] - info.dli_fbase);
			}
			snprintf(cmd, sizeof(cmd), "addr2line -e %s %p", info.dli_fname, ptr);
			if (info.dli_sname)
			{
				fprintf(file, "  \e[33m%s\e[0m @ %p (\e[31m%s\e[0m+0x%x) [%p]\n",
						info.dli_fname, info.dli_fbase, info.dli_sname,
						this->frames[i] - info.dli_saddr, this->frames[i]);
			}
			else
			{
				fprintf(file, "  \e[33m%s\e[0m @ %p [%p]\n", info.dli_fname,
						info.dli_fbase, this->frames[i]);
			}
			fprintf(file, "    -> \e[32m");
			output = popen(cmd, "r");
			if (output)
			{
				while (TRUE)
				{
					c = getc(output);
					if (c == '\n' || c == EOF)
					{
						break;
					}
					fputc(c, file);
				}
			}
			else
			{
#endif /* HAVE_DLADDR */
				fprintf(file, "    %s\n", strings[i]);
#ifdef HAVE_DLADDR
			}
			fprintf(file, "\n\e[0m");
		}
		else
		{
			fprintf(file, "    %s\n", strings[i]);
		}
#endif /* HAVE_DLADDR */
	}
	free (strings);
#else /* !HAVE_BACKTRACE */
	fprintf(file, "C library does not support backtrace().\n");
#endif /* HAVE_BACKTRACE */
}

/**
 * Implementation of backtrace_t.contains_function
 */
static bool contains_function(private_backtrace_t *this, char *function)
{
#ifdef HAVE_DLADDR
	int i;

	for (i = 0; i< this->frame_count; i++)
	{
		Dl_info info;
		
		if (dladdr(this->frames[i], &info) && info.dli_sname)
		{
			if (streq(info.dli_sname, function))
			{
				return TRUE;
			}
		}
	}
#endif /* HAVE_DLADDR */
	return FALSE;
}

/**
 * Implementation of backtrace_t.destroy.
 */
static void destroy(private_backtrace_t *this)
{
	free(this);
}

/**
 * See header
 */
backtrace_t *backtrace_create(int skip)
{
	private_backtrace_t *this;
	void *frames[50];
	int frame_count;
	
	frame_count = backtrace(frames, countof(frames));
	this = malloc(sizeof(private_backtrace_t) + frame_count * sizeof(void*));
	this->frame_count = frame_count - skip;
	memcpy(this->frames, frames + skip, this->frame_count * sizeof(void*));
	
	this->public.log = (void(*)(backtrace_t*,FILE*))log_;
	this->public.contains_function = (bool(*)(backtrace_t*, char *function))contains_function;
	this->public.destroy = (void(*)(backtrace_t*))destroy;
	
	return &this->public;
}

