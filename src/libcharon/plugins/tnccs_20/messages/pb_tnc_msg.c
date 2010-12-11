/*
 * Copyright (C) 2010 Andreas Steffen
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

#include "pb_tnc_msg.h"
#include "pb_experimental_msg.h"
#include "pb_pa_msg.h"
#include "pb_error_msg.h"
#include "pb_language_preference_msg.h"
#include "pb_assessment_result_msg.h"
#include "pb_access_recommendation_msg.h"
#include "pb_remediation_parameters_msg.h"
#include "pb_reason_string_msg.h"

#include <library.h>

ENUM(pb_tnc_msg_type_names, PB_MSG_EXPERIMENTAL, PB_MSG_REASON_STRING,
	"PB-Experimental",
	"PB-PA",
	"PB-Assessment-Result",
	"PB-Access-Recommendation",
	"PB-Remediation-Parameters",
	"PB-Error",
	"PB-Language-Preference",
	"PB-Reason-String"
);

pb_tnc_msg_info_t pb_tnc_msg_infos[] = {
	{ 12, FALSE, FALSE, TRUE_OR_FALSE },
	{ 24, FALSE, FALSE, TRUE  },
	{ 16, TRUE,  TRUE,  TRUE  },
	{ 16, TRUE,  TRUE,  FALSE },
	{ 20, FALSE, TRUE,  FALSE },
	{ 20, FALSE, FALSE, TRUE  },
	{ 12, FALSE, FALSE, FALSE },
	{ 17, FALSE, TRUE,  FALSE },
};

/**
 * See header
 */
pb_tnc_msg_t* pb_tnc_msg_create_from_data(pb_tnc_msg_type_t type, chunk_t value)
{
	switch (type)
	{
		case PB_MSG_PA:
			return pb_pa_msg_create_from_data(value);
		case PB_MSG_ERROR:
			return pb_error_msg_create_from_data(value);
		case PB_MSG_EXPERIMENTAL:
			return pb_experimental_msg_create_from_data(value);
		case PB_MSG_LANGUAGE_PREFERENCE:
			return pb_language_preference_msg_create_from_data(value);
		case PB_MSG_ASSESSMENT_RESULT:
			return pb_assessment_result_msg_create_from_data(value);
		case PB_MSG_ACCESS_RECOMMENDATION:
			return pb_access_recommendation_msg_create_from_data(value);
		case PB_MSG_REMEDIATION_PARAMETERS:
			return pb_remediation_parameters_msg_create_from_data(value);
		case PB_MSG_REASON_STRING:
			return pb_reason_string_msg_create_from_data(value);
	}
	return NULL;
}
