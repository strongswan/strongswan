/**
 * @file leak_detective.h
 * 
 * @brief malloc/free hooks to detect leaks.
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

#ifndef LEAK_DETECTIVE_H_
#define LEAK_DETECTIVE_H_


#include <utils/logger_manager.h>

/**
 * Log status information about allocation
 */
void leak_detective_status(logger_t *logger);

#ifdef LEAK_DETECTIVE

/**
 * Max number of stack frames to include in a backtrace.
 */
#define STACK_FRAMES_COUNT 30

/**
 * Initialize leak detective, activates it
 */
void leak_detective_init();

/**
 * Cleanup leak detective, deactivates it
 */
void leak_detective_cleanup();

#else /* !LEAK_DETECTIVE */

#define leak_detective_init() {}
#define leak_detective_cleanup() {}

#endif /* LEAK_DETECTIVE */

#endif /* LEAK_DETECTIVE_H_ */
