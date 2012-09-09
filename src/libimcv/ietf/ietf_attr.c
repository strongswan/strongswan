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
#include "ietf/ietf_attr_pa_tnc_error.h"
#include "ietf/ietf_attr_port_filter.h"
#include "ietf/ietf_attr_product_info.h"
#include "ietf/ietf_attr_attr_request.h"
#include "ietf/ietf_attr_assess_result.h"

ENUM(ietf_attr_names, IETF_ATTR_TESTING, IETF_ATTR_FACTORY_DEFAULT_PWD_ENABLED,
	"Testing",
	"Attribute Request",
	"Product Information",
	"Numeric Version",
	"String Version",
	"Operational Status",
	"Port Filter",
	"Installed Packages",
	"PA-TNC Error",
	"Assessment Result",
	"Remediation Instructions",
	"Forwarding Enabled",
	"Factory Default Password Enabled",
);

/**
 * See header
 */
pa_tnc_attr_t* ietf_attr_create_from_data(u_int32_t type, chunk_t value)
{
	switch (type)
	{
		case IETF_ATTR_ATTRIBUTE_REQUEST:
			return ietf_attr_attr_request_create_from_data(value);
		case IETF_ATTR_PRODUCT_INFORMATION:
			return ietf_attr_product_info_create_from_data(value);
		case IETF_ATTR_PORT_FILTER:
			return ietf_attr_port_filter_create_from_data(value);
		case IETF_ATTR_PA_TNC_ERROR:
			return ietf_attr_pa_tnc_error_create_from_data(value);
		case IETF_ATTR_ASSESSMENT_RESULT:
			return ietf_attr_assess_result_create_from_data(value);
		case IETF_ATTR_TESTING:
		case IETF_ATTR_NUMERIC_VERSION:
		case IETF_ATTR_STRING_VERSION:
		case IETF_ATTR_OPERATIONAL_STATUS:
		case IETF_ATTR_INSTALLED_PACKAGES:
		case IETF_ATTR_REMEDIATION_INSTRUCTIONS:
		case IETF_ATTR_FORWARDING_ENABLED:
		case IETF_ATTR_FACTORY_DEFAULT_PWD_ENABLED:
		case IETF_ATTR_RESERVED:
		default:
			return NULL;
	}
}
