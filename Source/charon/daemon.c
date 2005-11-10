/**
 * @file daemon.c
 * 
 * @brief Main of IKEv2-Daemon
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
 
#include <stdio.h>
 
#include "types.h"
#include "tester.h"
#include "job_queue.h"


job_queue_t *job_queue;

 
int main()
{
 	
 	job_queue = job_queue_create();
 	
	job_queue->destroy(job_queue);
	
#ifdef LEAK_DETECTIVE
	/* Leaks are reported in log file */
	report_leaks();
#endif
	
	return 0;
}
 
