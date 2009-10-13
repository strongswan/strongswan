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
 */


#include "attributes.h"

ENUM_BEGIN(configuration_attribute_type_names, INTERNAL_IP4_ADDRESS, INTERNAL_IP6_SUBNET,
	"INTERNAL_IP4_ADDRESS",
	"INTERNAL_IP4_NETMASK",
	"INTERNAL_IP4_DNS",
	"INTERNAL_IP4_NBNS",
	"INTERNAL_ADDRESS_EXPIRY",
	"INTERNAL_IP4_DHCP",
	"APPLICATION_VERSION",
	"INTERNAL_IP6_ADDRESS",
	"INTERNAL_IP6_NETMASK",
	"INTERNAL_IP6_DNS",
	"INTERNAL_IP6_NBNS",
	"INTERNAL_IP6_DHCP",
	"INTERNAL_IP4_SUBNET",
	"SUPPORTED_ATTRIBUTES",
	"INTERNAL_IP6_SUBNET");
ENUM_NEXT(configuration_attribute_type_names, INTERNAL_IP4_SERVER, INTERNAL_IP6_SERVER, INTERNAL_IP6_SUBNET,
	"INTERNAL_IP4_SERVER",
	"INTERNAL_IP6_SERVER");
ENUM_END(configuration_attribute_type_names, INTERNAL_IP6_SERVER);

