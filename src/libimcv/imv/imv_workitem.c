/*
 * Copyright (C) 2013 Andreas Steffen
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

#include "imv_workitem.h"

#include <utils/debug.h>
#include <tncif_names.h>

typedef struct private_imv_workitem_t private_imv_workitem_t;

ENUM(imv_workitem_type_names, IMV_WORKITEM_START, IMV_WORKITEM_UDP_SCAN,
	"START",
	"PCKGS",
	"UNSRC",
	"FWDEN",
	"PWDEN",
	"FMEAS",
	"DMEAS",
	"TCPSC",
	"UDPSC"
);

/**
 * Private data of a imv_workitem_t object.
 *
 */
struct private_imv_workitem_t {

	/**
	 * Public imv_workitem_t interface.
	 */
	imv_workitem_t public;

	/**
	 * Session ID
	 */
	int session_id;

	/**
	 * Workitem type
	 */
	imv_workitem_type_t type;

	/**
	 * Argument string
	 */
	char *argument;

	/**
	 * Result string
	 */
	char *result;

	/**
	 * IMV action recommendation
	 */
	TNC_IMV_Action_Recommendation rec_fail;

	/**
	 * IMV action recommendation
	 */
	TNC_IMV_Action_Recommendation rec_noresult;

	/**
	 * IMV action recommendation
	 */
	TNC_IMV_Action_Recommendation rec_final;

};

METHOD(imv_workitem_t, get_session_id, int,
	private_imv_workitem_t *this)
{
	return this->session_id;
}

METHOD(imv_workitem_t, get_type, imv_workitem_type_t,
	private_imv_workitem_t *this)
{
	return this->type;
}

METHOD(imv_workitem_t, get_argument, char*,
	private_imv_workitem_t *this)
{
	return this->argument;
}

METHOD(imv_workitem_t, set_result, TNC_IMV_Action_Recommendation,
	private_imv_workitem_t *this, char *result, TNC_IMV_Evaluation_Result eval)
{
	this->result = strdup(result);
	switch (eval)
	{
		case TNC_IMV_EVALUATION_RESULT_COMPLIANT:
			this->rec_final = TNC_IMV_ACTION_RECOMMENDATION_ALLOW;
			break;
		case TNC_IMV_EVALUATION_RESULT_NONCOMPLIANT_MINOR:
		case TNC_IMV_EVALUATION_RESULT_NONCOMPLIANT_MAJOR:
			this->rec_final = this->rec_fail;
			break;
		case TNC_IMV_EVALUATION_RESULT_ERROR:
		case TNC_IMV_EVALUATION_RESULT_DONT_KNOW:
		default:
			this->rec_final = this->rec_noresult;
			break;
	}
	DBG2(DBG_IMV, "workitem %N: %N%s%s", imv_workitem_type_names, this->type,
				   TNC_IMV_Action_Recommendation_names, this->rec_final, 
				   strlen(result) ? " - " : "", result);

	return this->rec_final;	
}

METHOD(imv_workitem_t, destroy, void,
	private_imv_workitem_t *this)
{
	free(this->argument);
	free(this->result);
	free(this);
}

/**
 * See header
 */
imv_workitem_t *imv_workitem_create(int session_id, imv_workitem_type_t type,
									char *argument,
									TNC_IMV_Action_Recommendation rec_fail,
									TNC_IMV_Action_Recommendation rec_noresult)
{
	private_imv_workitem_t *this;

	INIT(this,
		.public = {
			.get_session_id = _get_session_id,
			.get_type = _get_type,
			.get_argument = _get_argument,
			.set_result = _set_result,
			.destroy = _destroy,
		},
		.session_id = session_id,
		.type = type,
		.argument = strdup(argument),
		.rec_fail = rec_fail,
		.rec_noresult = rec_noresult,
		.rec_final = TNC_IMV_ACTION_RECOMMENDATION_NO_RECOMMENDATION,
	);

	return &this->public;
}

