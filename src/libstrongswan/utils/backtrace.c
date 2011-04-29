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

#ifdef HAVE_DLADDR
# include <dlfcn.h>
#endif /* HAVE_DLADDR */

#ifdef HAVE_BACKTRACE
# include <execinfo.h>
#endif /* HAVE_BACKTRACE */

#include <string.h>

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

METHOD(backtrace_t, log_, void,
	private_backtrace_t *this, FILE *file, bool detailed)
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
			int c;
			void *ptr = this->frames[i];

			if (strstr(info.dli_fname, ".so"))
			{
				ptr = (void*)(this->frames[i] - info.dli_fbase);
			}
			if (info.dli_sname)
			{
				fprintf(file, "  \e[33m%s\e[0m @ %p (\e[31m%s\e[0m+0x%tx) [%p]\n",
						info.dli_fname, info.dli_fbase, info.dli_sname,
						this->frames[i] - info.dli_saddr, this->frames[i]);
			}
			else
			{
				fprintf(file, "  \e[33m%s\e[0m @ %p [%p]\n", info.dli_fname,
						info.dli_fbase, this->frames[i]);
			}
			if (detailed)
			{
				fprintf(file, "    -> \e[32m");
				snprintf(cmd, sizeof(cmd), "addr2line -e %s %p",
						 info.dli_fname, ptr);
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
					pclose(output);
				}
				else
				{
	#endif /* HAVE_DLADDR */
					fprintf(file, "    %s\n", strings[i]);
	#ifdef HAVE_DLADDR
				}
				fprintf(file, "\n\e[0m");
			}
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

METHOD(backtrace_t, contains_function, bool,
	private_backtrace_t *this, char *function[], int count)
{
#ifdef HAVE_DLADDR
	int i, j;

	for (i = 0; i< this->frame_count; i++)
	{
		Dl_info info;

		if (dladdr(this->frames[i], &info) && info.dli_sname)
		{
			for (j = 0; j < count; j++)
			{
				if (streq(info.dli_sname, function[j]))
				{
					return TRUE;
				}
			}
		}
	}
#endif /* HAVE_DLADDR */
	return FALSE;
}

METHOD(backtrace_t, equals, bool,
	private_backtrace_t *this, backtrace_t *other_public)
{
	private_backtrace_t *other = (private_backtrace_t*)other_public;
	int i;

	if (this == other)
	{
		return TRUE;
	}
	if (this->frame_count != other->frame_count)
	{
		return FALSE;
	}
	for (i = 0; i < this->frame_count; i++)
	{
		if (this->frames[i] != other->frames[i])
		{
			return FALSE;
		}
	}
	return TRUE;
}

/**
 * Frame enumerator
 */
typedef struct {
	/** implements enumerator_t */
	enumerator_t public;
	/** reference to backtrace */
	private_backtrace_t *bt;
	/** current position */
	int i;
} frame_enumerator_t;

METHOD(enumerator_t, frame_enumerate, bool,
	frame_enumerator_t *this, void **addr)
{
	if (this->i < this->bt->frame_count)
	{
		*addr = this->bt->frames[this->i++];
		return TRUE;
	}
	return FALSE;
}

METHOD(backtrace_t, create_frame_enumerator, enumerator_t*,
	private_backtrace_t *this)
{
	frame_enumerator_t *enumerator;

	INIT(enumerator,
		.public = {
			.enumerate = (void*)_frame_enumerate,
			.destroy = (void*)free,
		},
		.bt = this,
	);
	return &enumerator->public;
}

METHOD(backtrace_t, destroy, void,
	private_backtrace_t *this)
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
	int frame_count = 0;

#ifdef HAVE_BACKTRACE
	frame_count = backtrace(frames, countof(frames));
#endif /* HAVE_BACKTRACE */
	frame_count = max(frame_count - skip, 0);
	this = malloc(sizeof(private_backtrace_t) + frame_count * sizeof(void*));
	memcpy(this->frames, frames + skip, frame_count * sizeof(void*));
	this->frame_count = frame_count;

	this->public = (backtrace_t) {
		.log = _log_,
		.contains_function = _contains_function,
		.equals = _equals,
		.create_frame_enumerator = _create_frame_enumerator,
		.destroy = _destroy,
	};

	return &this->public;
}

