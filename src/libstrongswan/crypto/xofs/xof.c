/*
 * Copyright (C) 2016 Andreas Steffen
 * HSR Hochschule fuer Technik Rapperswil
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

#include "xof.h"

ENUM(ext_out_function_names, XOF_UNDEFINED, XOF_CHACHA20,
	"XOF_UNDEFINED",
	"XOF_MGF1_SHA1",
	"XOF_MGF1_SHA256",
	"XOF_MGF1_SHA512",
	"XOF_SHAKE128",
	"XOF_SHAKE256",
	"XOF_CHACHA20"
);

