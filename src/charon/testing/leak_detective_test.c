/**
 * @file leak_detective_test.h
 * 
 * @brief Tests for the leak_detective_test.
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

#include "leak_detective_test.h"


void *mem_a, *mem_b, *mem_c;

void a()
{
	mem_a = malloc(4);
}

void b()
{
	a();
	mem_b = malloc(5);
}

void c()
{
	b();
	mem_c = malloc(6);
}

void recursive(int depth)
{
	void *tiny = malloc(1);
	if (--depth > 0)
	{
		recursive(depth);
	}
	free(tiny);
}


/* 
 * described in Header-File
 */
void test_leak_detective(protected_tester_t *tester)
{
	void *m1, *m2, *m3;
	
	
	m1 = malloc(1);
	m2 = calloc(1, 2);
	m3 = malloc(3);
	
	m3 = realloc(m3, 4);
	
	free(m2);
	free(m3);
	free(m1);
	
	c();
	free(mem_a);
	free(mem_c);
	free(mem_b);
	recursive(10000);
}
