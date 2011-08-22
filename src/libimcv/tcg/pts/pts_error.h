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

/**
 * @defgroup pts_error pts_error
 * @{ @ingroup pts
 */

#ifndef PTS_ERROR_H_
#define PTS_ERROR_H_

typedef enum pts_error_code_t pts_error_code_t;

#include <library.h>

/**
 * PTS Attestation Error Codes
 * see section 3.14.2 of PTS Protocol: Binding to TNC IF-M Specification
 */
enum pts_error_code_t {
	TCG_PTS_RESERVED_ERROR =           0,
	TCG_PTS_HASH_ALG_NOT_SUPPORTED =   1,
	TCG_PTS_INVALID_PATH =             2,
	TCG_PTS_FILE_NOT_FOUND =           3,
	TCG_PTS_REG_NOT_SUPPORTED =        4,
	TCG_PTS_REG_KEY_NOT_FOUND =        5,
	TCG_PTS_DH_GRPS_NOT_SUPPORTED =    6,
	TCG_PTS_BAD_NONCE_LENGTH =         7,
	TCG_PTS_INVALID_NAME_FAM =         8,
	TCG_PTS_TPM_VERS_NOT_SUPPORTED =   9,
	TCG_PTS_INVALID_DELIMITER =	      10,
	TCG_PTS_OPERATION_NOT_SUPPORTED = 11,
	TCG_PTS_RM_ERROR =                12,
	TCG_PTS_UNABLE_LOCAL_VAL =        13,
	TCG_PTS_UNABLE_CUR_EVID =         14,
	TCG_PTS_UNABLE_DET_TTC =          15,
	TCG_PTS_UNABLE_DET_PCR =          16,
};

/**
 * enum name for pts_error_code_t.
 */
extern enum_name_t *pts_error_code_names;

#endif /** PTS_ERROR_H_ @}*/
