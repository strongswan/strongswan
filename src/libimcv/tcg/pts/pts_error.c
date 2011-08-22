/*
 * Copyright (C) 2011 Sansar Choinyambuu
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

#include "pts_error.h"

ENUM(pts_error_code_names, TCG_PTS_RESERVED_ERROR, TCG_PTS_UNABLE_DET_PCR,
	"Reserved Error",
	"Hash Algorithm Not Supported",
	"Invalid Path",
	"File Not Found",
	"Registry Not Supported",
	"Registry Key Not Found",
	"D-H Group Not Supported",
	"DH-PN Nonce Not Acceptable",
	"Invalid Functional Name Family",
	"TPM Version Information Unavailable",
	"Invalid File Pathname Delimiter",
	"PTS Operation Not Supported",
	"Unable To Update Reference Manifest",
	"Unable To Perform Local Validation",
	"Unable To Collect Current Evidence",
	"Unable To Determine Transitive Trust Chain",
	"Unable To Determine PCR"
);
