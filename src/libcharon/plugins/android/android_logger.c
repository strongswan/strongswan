/*
 * Copyright (C) 2010 Tobias Brunner
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

#include <string.h>
#include <android/log.h>

#include "android_logger.h"

#include <library.h>
#include <daemon.h>

typedef struct private_android_logger_t private_android_logger_t;

/**
 * Private data of an android_logger_t object
 */
struct private_android_logger_t {

	/**
	 * Public interface
	 */
	android_logger_t public;

	/**
	 * logging level
	 */
	int level;

};


METHOD(listener_t, log_, bool,
	   private_android_logger_t *this, debug_t group, level_t level,
	   int thread, ike_sa_t* ike_sa, char *format, va_list args)
{
	if (level <= this->level)
	{
		int prio = level > 1 ? ANDROID_LOG_DEBUG : ANDROID_LOG_INFO;
		char sgroup[16], buffer[8192];
		char *current = buffer, *next;
		snprintf(sgroup, sizeof(sgroup), "%N", debug_names, group);
		vsnprintf(buffer, sizeof(buffer), format, args);
		while (current)
		{	/* log each line separately */
			next = strchr(current, '\n');
			if (next)
			{
				*(next++) = '\0';
			}
			__android_log_print(prio, "charon", "%.2d[%s] %s\n",
								thread, sgroup, current);
			current = next;
		}
	}
	/* always stay registered */
	return TRUE;
}

METHOD(android_logger_t, destroy, void,
	   private_android_logger_t *this)
{
	free(this);
}

/**
 * Described in header.
 */
android_logger_t *android_logger_create()
{
	private_android_logger_t *this;

	INIT(this,
		.public = {
			.listener = {
				.log = _log_,
			},
			.destroy = _destroy,
		},
		.level = lib->settings->get_int(lib->settings,
										"charon.plugins.android.loglevel", 1),
	);

	return &this->public;
}

