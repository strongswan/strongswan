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

#include "pb_tnc_message.h"
#include "pb_pa_message.h"
#include "pb_error_message.h"
#include "pb_language_preference_message.h"
#include "pb_assessment_result_message.h"
#include "pb_access_recommendation_message.h"
#include "pb_reason_string_message.h"

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

/**
 * See header
 */
pb_tnc_message_t* pb_tnc_message_create(pb_tnc_msg_type_t type, chunk_t value)
{
	switch (type)
	{
		case PB_MSG_PA:
			return pb_pa_message_create_from_data(value);
		case PB_MSG_ERROR:
			return pb_error_message_create_from_data(value);
		case PB_MSG_EXPERIMENTAL:
			return NULL;
		case PB_MSG_LANGUAGE_PREFERENCE:
			return pb_language_preference_message_create_from_data(value);
		case PB_MSG_ASSESSMENT_RESULT:
			return pb_assessment_result_message_create_from_data(value);
		case PB_MSG_ACCESS_RECOMMENDATION:
			return pb_access_recommendation_message_create_from_data(value);
		case PB_MSG_REMEDIATION_PARAMETERS:
			return NULL;
		case PB_MSG_REASON_STRING:
			return pb_reason_string_message_create_from_data(value);
	}
	return NULL;
}
