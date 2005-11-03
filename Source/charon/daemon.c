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
#include <freeswan.h>
#include <pluto/constants.h>
#include <pluto/defs.h>
 
#include "types.h"
#include "tester.h"

/* output for test messages */
extern FILE * stderr;
 
int main()
{
 	FILE * test_output = stderr;
 	
 	tester_t *tester = tester_create(test_output);

 	tester->test_all(tester);
 	
	tester->destroy(tester);
	
#ifdef LEAK_DETECTIVE
	/* Leaks are reported in log file */
	report_leaks();
#endif
	
	return 0;
}
 
