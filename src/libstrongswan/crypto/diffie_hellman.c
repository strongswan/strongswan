/*
 * Copyright (C) 2005-2008 Martin Willi
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
 */

#include "diffie_hellman.h"

ENUM_BEGIN(diffie_hellman_group_names, MODP_NONE, MODP_1024_BIT,
	"MODP_NONE",
	"MODP_768",
	"MODP_1024");
ENUM_NEXT(diffie_hellman_group_names, MODP_1536_BIT, MODP_1536_BIT, MODP_1024_BIT,
	"MODP_1536");
ENUM_NEXT(diffie_hellman_group_names, MODP_2048_BIT, ECP_521_BIT, MODP_1536_BIT,
	"MODP_2048",
	"MODP_3072",
	"MODP_4096",
	"MODP_6144",
	"MODP_8192",
	"ECP_256",
	"ECP_384",
	"ECP_521");
ENUM_NEXT(diffie_hellman_group_names, ECP_192_BIT, ECP_224_BIT, ECP_521_BIT,
	"ECP_192",
	"ECP_224");
ENUM_NEXT(diffie_hellman_group_names, MODP_NULL, MODP_NULL, ECP_224_BIT,
	"MODP_NULL");
ENUM_END(diffie_hellman_group_names, MODP_NULL);

