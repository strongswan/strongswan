/*
 * Copyright (C) 2010 Sansar Choinynambuu
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

#include "tnccs_20_types.h"

ENUM(pb_tnc_remed_param_type_names, PB_REMEDIATION_URI, PB_REMEDIATION_STRING,
	"Remediation-URI",
	"Remediation-String"
);

ENUM(pa_tnc_subtype_names, PA_SUBTYPE_TESTING, PA_SUBTYPE_NEA_CLIENT,
	"Testing",
	"Operating System",
	"Anti-Virus",
	"Anti-Spyware",
	"Anti-Malware",
	"Firewall",
	"IDPS",
	"VPN",
	"NEA Client"
);
