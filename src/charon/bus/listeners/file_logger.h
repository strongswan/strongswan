/**
 * @file file_logger.h
 *
 * @brief Interface of file_logger_t.
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

#ifndef FILE_LOGGER_H_
#define FILE_LOGGER_H_

#include <bus/bus.h>


typedef struct file_logger_t file_logger_t;

/**
 * @brief Logger to files which implements bus_listener_t.
 * 
 * @b Constructors:
 *  - file_logger_create()
 * 
 * @ingroup listeners
 */
struct file_logger_t {
	
	/**
	 * Implements the bus_listener_t interface.
	 */
	bus_listener_t listener;
	
	/**
	 * @brief Set the loglevel for a signal type.
	 *
	 * @param this		stream_logger_t object
	 * @param singal	type of signal
	 * @param level		max level to log (0..4)
	 */
	void (*set_level) (file_logger_t *this, signal_t signal, level_t level);
	
	/**
	 * @brief Destroys a file_logger_t object.
	 *
	 * @param this		file_logger_t object
	 */
	void (*destroy) (file_logger_t *this);
};

/**
 * @brief Constructor to create a file_logger_t object.
 *
 * @param out		FILE to write to
 * @return			file_logger_t object
 *
 * @ingroup listeners
 */
file_logger_t *file_logger_create(FILE *out);


#endif /* FILE_LOGGER_H_ */
