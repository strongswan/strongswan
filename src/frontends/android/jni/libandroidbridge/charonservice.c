/*
 * Copyright (C) 2012 Giuliano Grassi
 * Copyright (C) 2012 Ralf Sager
 * Copyright (C) 2012 Tobias Brunner
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

#include "charonservice.h"
#include "android_jni.h"

#include <daemon.h>
#include <hydra.h>
#include <ipsec.h>
#include <library.h>

#define ANDROID_DEBUG_LEVEL 1

typedef struct private_charonservice_t private_charonservice_t;

/**
 * private data of charonservice
 */
struct private_charonservice_t {

	/**
	 * public interface
	 */
	charonservice_t public;
};

/**
 * Single instance of charonservice_t.
 */
charonservice_t *charonservice;

/**
 * hook in library for debugging messages
 */
extern void (*dbg)(debug_t group, level_t level, char *fmt, ...);

/**
 * Logging hook for library logs, using android specific logging
 */
static void dbg_android(debug_t group, level_t level, char *fmt, ...)
{
	va_list args;

	if (level <= ANDROID_DEBUG_LEVEL)
	{
		char sgroup[16], buffer[8192];
		char *current = buffer, *next;

		snprintf(sgroup, sizeof(sgroup), "%N", debug_names, group);
		va_start(args, fmt);
		vsnprintf(buffer, sizeof(buffer), fmt, args);
		va_end(args);
		while (current)
		{	/* log each line separately */
			next = strchr(current, '\n');
			if (next)
			{
				*(next++) = '\0';
			}
			__android_log_print(ANDROID_LOG_INFO, "charon", "00[%s] %s\n",
								sgroup, current);
			current = next;
		}
	}
}

/**
 * Initialize the charonservice object
 */
static void charonservice_init()
{
	private_charonservice_t *this;

	INIT(this,
		.public = {
		},
	);
	charonservice = &this->public;

	lib->settings->set_int(lib->settings,
					"charon.plugins.android_log.loglevel", ANDROID_DEBUG_LEVEL);
}

/**
 * Deinitialize the charonservice object
 */
static void charonservice_deinit()
{
	private_charonservice_t *this = (private_charonservice_t*)charonservice;

	free(this);
	charonservice = NULL;
}

/**
 * Initialize charon and the libraries via JNI
 */
JNI_METHOD(CharonVpnService, initializeCharon, void)
{
	/* logging for library during initialization, as we have no bus yet */
	dbg = dbg_android;

	/* initialize library */
	if (!library_init(NULL))
	{
		library_deinit();
		return;
	}

	if (!libhydra_init("charon"))
	{
		libhydra_deinit();
		library_deinit();
		return;
	}

	if (!libipsec_init())
	{
		libipsec_deinit();
		libhydra_deinit();
		library_deinit();
		return;
	}

	charonservice_init();

	if (!libcharon_init("charon") ||
		!charon->initialize(charon, PLUGINS))
	{
		libcharon_deinit();
		charonservice_deinit();
		libipsec_deinit();
		libhydra_deinit();
		library_deinit();
		return;
	}

	/* start daemon (i.e. the threads in the thread-pool) */
	charon->start(charon);
}

/**
 * Deinitialize charon and all libraries
 */
JNI_METHOD(CharonVpnService, deinitializeCharon, void)
{
	libcharon_deinit();
	charonservice_deinit();
	libipsec_deinit();
	libhydra_deinit();
	library_deinit();
}

