/**
 * @file types.c
 * 
 * @brief Generic type definitions
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
 
#include "types.h"



mapping_t status_m[] = {
	{SUCCESS, "SUCCESS"},
	{FAILED, "FAILED"},
	{OUT_OF_RES, "OUT_OF_RES"},
	{ALREADY_DONE, "ALREADY_DONE"},
	{NOT_SUPPORTED, "NOT_SUPPORTED"},
	{INVALID_ARG, "INVALID_ARG"},
	{NOT_FOUND, "NOT_FOUND"},
	{PARSE_ERROR, "PARSE_ERROR"},
	{VERIFY_ERROR, "VERIFY_ERROR"},
	{INVALID_STATE, "INVALID_STATE"},
	{DELETE_ME, "DELETE_ME"},
	{MAPPING_END, NULL}
};

chunk_t CHUNK_INITIALIZER = {NULL,0};
