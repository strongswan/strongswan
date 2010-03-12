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

#include "eap_method.h"

ENUM_BEGIN(eap_type_names, EAP_IDENTITY, EAP_GTC,
	"EAP_IDENTITY",
	"EAP_NOTIFICATION",
	"EAP_NAK",
	"EAP_MD5",
	"EAP_OTP",
	"EAP_GTC");
ENUM_NEXT(eap_type_names, EAP_SIM, EAP_SIM, EAP_GTC,
	"EAP_SIM");
ENUM_NEXT(eap_type_names, EAP_AKA, EAP_AKA, EAP_SIM,
	"EAP_AKA");
ENUM_NEXT(eap_type_names, EAP_MSCHAPV2, EAP_MSCHAPV2, EAP_AKA,
	"EAP_MSCHAPV2");
ENUM_NEXT(eap_type_names, EAP_RADIUS, EAP_EXPERIMENTAL, EAP_MSCHAPV2,
	"EAP_RADIUS",
	"EAP_EXPANDED",
	"EAP_EXPERIMENTAL");
ENUM_END(eap_type_names, EAP_EXPERIMENTAL);

ENUM_BEGIN(eap_type_short_names, EAP_IDENTITY, EAP_GTC,
	"ID",
	"NTF",
	"NAK",
	"MD5",
	"OTP",
	"GTC");
ENUM_NEXT(eap_type_short_names, EAP_SIM, EAP_SIM, EAP_GTC,
	"SIM");
ENUM_NEXT(eap_type_short_names, EAP_AKA, EAP_AKA, EAP_SIM,
	"AKA");
ENUM_NEXT(eap_type_short_names, EAP_MSCHAPV2, EAP_MSCHAPV2, EAP_AKA,
	"MSCHAPV2");
ENUM_NEXT(eap_type_short_names, EAP_RADIUS, EAP_EXPERIMENTAL, EAP_MSCHAPV2,
	"RAD",
	"EXP",
	"XP");
ENUM_END(eap_type_short_names, EAP_EXPERIMENTAL);

/*
 * See header
 */
eap_type_t eap_type_from_string(char *name)
{
	int i;
	static struct {
		char *name;
		eap_type_t type;
	} types[] = {
		{"identity",	EAP_IDENTITY},
		{"md5",			EAP_MD5},
		{"otp",			EAP_OTP},
		{"gtc",			EAP_GTC},
		{"sim",			EAP_SIM},
		{"aka",			EAP_AKA},
		{"mschapv2",	EAP_MSCHAPV2},
		{"radius",		EAP_RADIUS},
	};

	for (i = 0; i < countof(types); i++)
	{
		if (strcaseeq(name, types[i].name))
		{
			return types[i].type;
		}
	}
	return 0;
}

ENUM(eap_code_names, EAP_REQUEST, EAP_FAILURE,
	"EAP_REQUEST",
	"EAP_RESPONSE",
	"EAP_SUCCESS",
	"EAP_FAILURE",
);

ENUM(eap_code_short_names, EAP_REQUEST, EAP_FAILURE,
	"REQ",
	"RES",
	"SUCC",
	"FAIL",
);

ENUM(eap_role_names, EAP_SERVER, EAP_PEER,
	"EAP_SERVER",
	"EAP_PEER",
);




