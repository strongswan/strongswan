/*
 * Copyright (C) 2011 Andreas Steffen, HSR Hochschule fuer Technik Rapperswil
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

#include "ietf_attr.h"

ENUM(ietf_attr_names, IETF_ATTR_TESTING, IETF_ATTR_FACTORY_DEFAULT_PWD_ENABLED,
	"Testing",
	"Attribute Request",
	"Product Information",
	"Numeric Version",
	"String Version",
	"Operational Status",
	"Port Filter",
	"Installed Packages",
	"PA-TNC error",
	"Assessment Result",
	"Remediation Instructions",
	"Forwarding Enabled",
	"Factory Default Password Enabled",
);

