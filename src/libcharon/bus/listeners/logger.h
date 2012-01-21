/*
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

/**
 * @defgroup logger logger
 * @{ @ingroup listeners
 */

#ifndef LOGGER_H_
#define LOGGER_H_

typedef struct logger_t logger_t;

#include <bus/bus.h>

/**
 * Logger interface, listens for log events on the bus.
 */
struct logger_t {

	/**
	 * Log a debugging message.
	 *
	 * @note Calls to bus_t.log() are handled seperately from calls to
	 * other functions. This callback may be called concurrently by
	 * multiple threads.  Also recurisve calls are not prevented, logger that
	 * may cause recursive calls are responsible to avoid infinite loops.
	 *
	 * @param group		kind of the signal (up, down, rekeyed, ...)
	 * @param level		verbosity level of the signal
	 * @param thread	ID of the thread raised this signal
	 * @param ike_sa	IKE_SA associated to the event
	 * @param format	printf() style format string
	 * @param args		vprintf() style argument list
	 */
	void (*log)(logger_t *this, debug_t group, level_t level, int thread,
				ike_sa_t *ike_sa, char* format, va_list args);

};

#endif /** LOGGER_H_ @}*/
