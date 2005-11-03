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
#include "linked_list.h"
 
typedef struct {
 	tester_t tester;
 	
 	FILE* output;
} private_tester_t;
 
/**
 * @brief Test function to test the linked list class
 */
static status_t	test_linked_list(private_tester_t * this){
	fprintf(this->output,"Test linked list class...\n");
	linked_list_t * linked_list_create();
	
	return FAILED;
}
 
static status_t test_all(tester_t *tester) 
{
	private_tester_t *this =(private_tester_t*) tester;
	int tests_failed = 0;
	int test_count = 0;

	fprintf(this->output,"Start testing\n");
	
	if (test_linked_list(this) != SUCCESS){	tests_failed++; } test_count++;
	
	fprintf(this->output,"End testing. %d tests failed of %d tests\n",tests_failed,test_count);
	//report_leaks();
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
	
	return &(this->tester);
}
