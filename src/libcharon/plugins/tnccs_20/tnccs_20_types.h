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

/**
 * @defgroup tnccs_20_types_h tnccs_20
 * @{ @ingroup tnccs_20
 */

#ifndef TNCCS_20_TYPES_H_
#define TNCCS_20_TYPES_H_

#include <library.h>

typedef enum pb_tnc_batch_type_t pb_tnc_batch_type_t;
typedef enum pb_tnc_msg_type_t pb_tnc_msg_type_t;
typedef enum pb_tnc_remed_param_type_t pb_tnc_remed_param_type_t;
typedef enum pb_tnc_error_code_t pb_tnc_error_code_t;
typedef enum pa_tnc_subtype_t pa_tnc_subtype_t;

/**
  * PB-TNC Batch Types as defined in section 4.1 of RFC 5793
 */
enum pb_tnc_batch_type_t {
	PB_BATCH_CDATA =	1,
	PB_BATCH_SDATA =	2,
	PB_BATCH_RESULT =	3,
	PB_BATCH_CRETRY =	4,
	PB_BATCH_SRETRY =	5,
	PB_BATCH_CLOSE =	6
};

/**
 * enum name for pb_tnc_batch_type_t.
 */
extern enum_name_t *pb_tnc_batch_type_names;

/**
 * PB-TNC Message Types as defined in section 4.3 of RFC 5793
 */
enum pb_tnc_msg_type_t {
	PB_MSG_EXPERIMENTAL =				0,
	PB_MSG_PA =							1,
	PB_MSG_ASSESSMENT_RESULT =			2,
	PB_MSG_ACCESS_RECOMMENDATION =		3,
	PB_MSG_REMEDIATION_PARAMETERS =		4,
	PB_MSG_ERROR =						5,
	PB_MSG_LANGUAGE_PREFERENCE =		6,
	PB_MSG_REASON_STRING =				7,
	PB_MSG_ROOF =						7
};

/**
 * enum name for pb_tnc_msg_type_t.
 */
extern enum_name_t *pb_tnc_msg_type_names;

/**
 * PB-TNC Remediation Parameter Types as defined in section 4.8.1 of RFC 5793
 */
enum pb_tnc_remed_param_type_t {
	PB_REMEDIATION_URI =			1,
	PB_REMEDIATION_STRING =			2,
};

/**
 * enum name for pb_tnc_remed_param_type_t.
 */
extern enum_name_t *pb_tnc_remed_param_type_names;

/**
 * PB-TNC Error Codes as defined in section 4.9.1 of RFC 5793
 */
enum  pb_tnc_error_code_t {
	PB_ERROR_UNEXPECTED_BATCH_TYPE =			0,
	PB_ERROR_INVALID_PARAMETER =				1,
	PB_ERROR_LOCAL_ERROR =						2,
	PB_ERROR_UNSUPPORTED_MANDATORY_MESSAGE =	3,
	PB_ERROR_VERSION_NOT_SUPPORTED =			4
};

/**
 * enum name for pb_tnc_error_code_t.
 */
extern enum_name_t *pb_tnc_error_code_names;

/**
 * PA-TNC Subtypes as defined in section 3.5 of RFC 5792
 */
 enum pa_tnc_subtype_t {
	PA_SUBTYPE_TESTING =			0,
	PA_SUBTYPE_OPERATING_SYSTEM =	1,
	PA_SUBTYPE_ANTI_VIRUS =			2,
	PA_SUBTYPE_ANTI_SPYWARE =		3,
	PA_SUBTYPE_ANTI_MALWARE =		4,
	PA_SUBTYPE_FIREWALL =			5,
	PA_SUBTYPE_IDPS =				6,
	PA_SUBTYPE_VPN =				7,
	PA_SUBTYPE_NEA_CLIENT =			8
};

/**
 * enum name for pa_tnc_subtype_t.
 */
extern enum_name_t *pa_tnc_subtype_names;

#endif /** TNCCS_20_TYPES_H_ @}*/
