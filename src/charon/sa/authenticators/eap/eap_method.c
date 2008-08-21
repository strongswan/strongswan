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
 *
 * $Id$
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
ENUM_NEXT(eap_type_names, EAP_EXPANDED, EAP_EXPERIMENTAL, EAP_AKA,
	"EAP_EXPANDED",
	"EAP_EXPERIMENTAL");
ENUM_END(eap_type_names, EAP_EXPERIMENTAL);

ENUM(eap_code_names, EAP_REQUEST, EAP_FAILURE,
	"EAP_REQUEST",
	"EAP_RESPONSE",
	"EAP_SUCCESS",
	"EAP_FAILURE",
);

ENUM(eap_role_names, EAP_SERVER, EAP_PEER,
	"EAP_SERVER",
	"EAP_PEER",
);

