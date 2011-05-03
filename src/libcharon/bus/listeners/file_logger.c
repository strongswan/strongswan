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

#include <stdio.h>
#include <string.h>
#include <time.h>

#include "file_logger.h"


typedef struct private_file_logger_t private_file_logger_t;

/**
 * Private data of a file_logger_t object
 */
struct private_file_logger_t {

	/**
	 * Public data.
	 */
	file_logger_t public;

	/**
	 * output file
	 */
	FILE *out;

	/**
	 * Maximum level to log, for each group
	 */
	level_t levels[DBG_MAX];

	/**
	 * strftime() format of time prefix, if any
	 */
	char *time_format;

	/**
	 * Print the name/# of the IKE_SA?
	 */
	bool ike_name;
};

METHOD(listener_t, log_, bool,
	   private_file_logger_t *this, debug_t group, level_t level, int thread,
	   ike_sa_t* ike_sa, char *format, va_list args)
{
	if (level <= this->levels[group])
	{
		char buffer[8192], timestr[128], namestr[128] = "";
		char *current = buffer, *next;
		struct tm tm;
		time_t t;

		if (this->time_format)
		{
			t = time(NULL);
			localtime_r(&t, &tm);
			strftime(timestr, sizeof(timestr), this->time_format, &tm);
		}
		if (this->ike_name && ike_sa)
		{
			if (ike_sa->get_peer_cfg(ike_sa))
			{
				snprintf(namestr, sizeof(namestr), " <%s|%d>",
					ike_sa->get_name(ike_sa), ike_sa->get_unique_id(ike_sa));
			}
			else
			{
				snprintf(namestr, sizeof(namestr), " <%d>",
					ike_sa->get_unique_id(ike_sa));
			}
		}
		else
		{
			namestr[0] = '\0';
		}

		/* write in memory buffer first */
		vsnprintf(buffer, sizeof(buffer), format, args);

		/* prepend a prefix in front of every line */
		while (current)
		{
			next = strchr(current, '\n');
			if (next)
			{
				*(next++) = '\0';
			}
			if (this->time_format)
			{
				fprintf(this->out, "%s %.2d[%N]%s %s\n",
						timestr, thread, debug_names, group, namestr, current);
			}
			else
			{
				fprintf(this->out, "%.2d[%N]%s %s\n",
						thread, debug_names, group, namestr, current);
			}
			current = next;
		}
	}
	/* always stay registered */
	return TRUE;
}

METHOD(file_logger_t, set_level, void,
	   private_file_logger_t *this, debug_t group, level_t level)
{
	if (group < DBG_ANY)
	{
		this->levels[group] = level;
	}
	else
	{
		for (group = 0; group < DBG_MAX; group++)
		{
			this->levels[group] = level;
		}
	}
}

METHOD(file_logger_t, destroy, void,
	   private_file_logger_t *this)
{
	if (this->out != stdout && this->out != stderr)
	{
		fclose(this->out);
	}
	free(this);
}

/*
 * Described in header.
 */
file_logger_t *file_logger_create(FILE *out, char *time_format, bool ike_name)
{
	private_file_logger_t *this;

	INIT(this,
		.public = {
			.listener = {
				.log = _log_,
			},
			.set_level = _set_level,
			.destroy = _destroy,
		},
		.out = out,
		.time_format = time_format,
		.ike_name = ike_name,
	);

	set_level(this, DBG_ANY, LEVEL_SILENT);

	return &this->public;
}

