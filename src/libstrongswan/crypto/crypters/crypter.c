/*
 * Copyright (C) 2005-2006 Martin Willi
 * Copyright (C) 2005 Jan Hutter
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
 * $Id$
 */

#include "crypter.h"

ENUM_BEGIN(encryption_algorithm_names, ENCR_UNDEFINED, ENCR_UNDEFINED,
	"UNDEFINED");
ENUM_NEXT(encryption_algorithm_names, ENCR_DES_IV64, ENCR_DES_IV32, ENCR_UNDEFINED,
	"DES_IV64",
	"DES",
	"3DES",
	"RC5",
	"IDEA",
	"CAST",
	"BLOWFISH",
	"3IDEA",
	"DES_IV32");
ENUM_NEXT(encryption_algorithm_names, ENCR_NULL, ENCR_AES_CTR, ENCR_DES_IV32,
	"NULL",
	"AES_CBC",
	"AES_CTR");
ENUM_END(encryption_algorithm_names, ENCR_AES_CTR);

