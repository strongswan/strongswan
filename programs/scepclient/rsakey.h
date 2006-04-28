/**
 * @file rsakey.h
 * @brief Functions for RSA key generation 
 */

/* 
 * Copyright (C) 1999, 2000, 2001  Henry Spencer.
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
 *
 * $Id: rsakey.h,v 1.2 2005/08/11 21:52:56 as Exp $
 */
 
#ifndef RSAKEY_H_
#define RSAKEY_H_

#include "../pluto/pkcs1.h"

extern err_t generate_rsa_private_key(int nbits, RSA_private_key_t *key);

#endif // RSAKEY_H_
