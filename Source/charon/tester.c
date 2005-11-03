/**
 * @file tester.c
 * 
 * @brief Test module for automatic testing
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


#include <stdlib.h>
#include <freeswan.h>
#include <pluto/constants.h>
#include <pluto/defs.h>
 
#include "tester.h"
 
typedef struct {
 	tester_t tester;
 	
 	FILE* output;
} private_tester_t;
 
 
static status_t test_all(tester_t *this) 
{
	
	return SUCCESS;
}
 
static status_t destroy(tester_t *this) 
{
	pfree(this);
	return SUCCESS;
}


tester_t *tester_create(FILE *output) 
{
	private_tester_t *this = alloc_thing(private_tester_t, "private_tester_t");
	
	this->tester.destroy = destroy;
	this->tester.test_all = test_all;
	
	this->output = output;
	
	return SUCCESS;
}
