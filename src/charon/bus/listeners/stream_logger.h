/**
 * @file stream_logger.h
 *
 * @brief Interface of stream_logger_t.
 *
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

#ifndef STREAM_LOGGER_H_
#define STREAM_LOGGER_H_

#include <stdio.h>

#include <types.h>
#include <bus/bus.h>

typedef struct stream_logger_t stream_logger_t;

/**
 * @brief Logger for a file stream which implements bus_listener_t.
 * 
 * @b Constructors:
 *  - stream_logger_create()
 * 
 * @ingroup listeners
 */
struct stream_logger_t {
	
	/**
	 * Implements the bus_listener_t interface.
	 */
	bus_listener_t listener;
	
	/**
	 * @brief Set the loglevel for a signal type.
	 *
	 * @param this		stream_logger_t object
	 * @param singal	type of signal
	 * @param level		max level to log
	 */
	void (*set_level) (stream_logger_t *this, signal_t signal, level_t level);
	
	/**
	 * @brief Destroys a stream_logger_t object.
	 *
	 * @param this		stream_logger_t object
	 */
	void (*destroy) (stream_logger_t *this);
};

/**
 * @brief Constructor to create a stream_logger_t object.
 *
 * @param out	output stream to log to
 * @return 		stream_logger_t object
 * 
 * @ingroup utils
 */
stream_logger_t *stream_logger_create(FILE *out);

#endif /* STREAM_LOGGER_H_ */
