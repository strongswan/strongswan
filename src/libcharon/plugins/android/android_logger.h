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

/**
 * @defgroup android_logger android_logger
 * @{ @ingroup android
 */

#ifndef ANDROID_LOGGER_H_
#define ANDROID_LOGGER_H_

#include <bus/bus.h>

typedef struct android_logger_t android_logger_t;

/**
 * Android specific logger.
 */
struct android_logger_t {

	/**
	 * Implements bus_listener_t interface
	 */
	listener_t listener;

	/**
	 * Destroy the logger.
	 */
	void (*destroy)(android_logger_t *this);

};

/**
 * Create an Android specific logger instance.
 *
 * @return			logger instance
 */
android_logger_t *android_logger_create();

#endif /** ANDROID_LOGGER_H_ @}*/
