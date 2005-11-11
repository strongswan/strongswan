/**
 * @file globals.h
 * 
 * @brief Global used objects
 * 
 */

/*
 * Copyright (C) 2005 Jan Hutter, Martin Willi
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

#ifndef GLOBALS_H_
#define GLOBALS_H_

#include "send_queue.h"
#include "job_queue.h"
#include "event_queue.h"
#include "socket.h"
#include "logger_manager.h"


extern send_queue_t *global_send_queue;
extern job_queue_t *global_job_queue;
extern event_queue_t *global_event_queue;
extern socket_t *global_socket;
extern logger_manager_t *global_logger_manager;

#endif /*GLOBALS_H_*/
