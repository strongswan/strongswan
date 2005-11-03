/**
 * @file tester.h
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

#ifndef TESTER_H_
#define TESTER_H_ 

#include <stdio.h>

#include "types.h"



typedef struct tester_s tester_t;

struct tester_s {
	status_t (*test_all) (tester_t *tester);
	status_t (*destroy) (tester_t *tester);
};

tester_t *tester_create(FILE *output);

#endif /*TESTER_H_*/
