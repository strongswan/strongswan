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

#include "imv_os_batch_ending.h"
#include "imv_os_state.h"
#include "imv_os_database.h"

#include <imcv.h>
#include <imv/imv_msg.h>
#include <ietf/ietf_attr_attr_request.h>
#include <ita/ita_attr.h>
#include <ita/ita_attr_get_settings.h>

#include <utils/debug.h>

/**
 * Build an IETF Attribute Request attribute for missing attributes
 */
static pa_tnc_attr_t* build_attr_request(u_int received)
{
	pa_tnc_attr_t *attr;
	ietf_attr_attr_request_t *attr_cast;

	attr = ietf_attr_attr_request_create(PEN_RESERVED, 0);
	attr_cast = (ietf_attr_attr_request_t*)attr;

	if (!(received & IMV_OS_ATTR_PRODUCT_INFORMATION) ||
		!(received & IMV_OS_ATTR_STRING_VERSION))
	{
		attr_cast->add(attr_cast, PEN_IETF, IETF_ATTR_PRODUCT_INFORMATION);
		attr_cast->add(attr_cast, PEN_IETF, IETF_ATTR_STRING_VERSION);
	}
	if (!(received & IMV_OS_ATTR_NUMERIC_VERSION))
	{
		attr_cast->add(attr_cast, PEN_IETF, IETF_ATTR_NUMERIC_VERSION);
	}
	if (!(received & IMV_OS_ATTR_OPERATIONAL_STATUS))
	{
		attr_cast->add(attr_cast, PEN_IETF, IETF_ATTR_OPERATIONAL_STATUS);
	}
	if (!(received & IMV_OS_ATTR_FORWARDING_ENABLED))
	{
		attr_cast->add(attr_cast, PEN_IETF, IETF_ATTR_FORWARDING_ENABLED);
	}
	if (!(received & IMV_OS_ATTR_FACTORY_DEFAULT_PWD_ENABLED))
	{
		attr_cast->add(attr_cast, PEN_IETF,
								  IETF_ATTR_FACTORY_DEFAULT_PWD_ENABLED);
	}
	if (!(received & IMV_OS_ATTR_DEVICE_ID))
	{
		attr_cast->add(attr_cast, PEN_ITA,  ITA_ATTR_DEVICE_ID);
	}

	return attr;
}

/**
 * See header
 */
TNC_Result imv_os_batch_ending(imv_agent_t *imv_os, imv_state_t *state,
							   TNC_IMVID imv_id, pen_type_t msg_type)
{
	imv_msg_t *out_msg;
	imv_session_t *session;
	imv_workitem_t *workitem;
	imv_os_state_t *os_state;
	imv_os_handshake_state_t handshake_state;
	pa_tnc_attr_t *attr;
	TNC_ConnectionID connection_id;
	TNC_Result result = TNC_RESULT_SUCCESS;
	bool no_workitems = TRUE;
	enumerator_t *enumerator;
	u_int received;

	os_state = (imv_os_state_t*)state;
	handshake_state = os_state->get_handshake_state(os_state);
	received = os_state->get_received(os_state);
	connection_id = state->get_connection_id(state);
	session = state->get_session(state);

	/* create an empty out message - we might need it */
	out_msg = imv_msg_create(imv_os, state, connection_id, imv_id,
							 TNC_IMCID_ANY, msg_type);

	if (handshake_state == IMV_OS_STATE_INIT)
	{
		if ((received & IMV_OS_ATTR_MUST) != IMV_OS_ATTR_MUST)
		{
			/* create attribute request for missing mandatory attributes */
			out_msg->add_attribute(out_msg, build_attr_request(received));
		}
	}

	if (handshake_state < IMV_OS_STATE_POLICY_START)
	{
		if (((received & IMV_OS_ATTR_PRODUCT_INFORMATION) &&
			 (received & IMV_OS_ATTR_STRING_VERSION)) &&
			((received & IMV_OS_ATTR_DEVICE_ID) ||
			 (handshake_state == IMV_OS_STATE_ATTR_REQ)))
		{
			if (imcv_db)
			{
				/* trigger the policy manager */
				imcv_db->policy_script(imcv_db, session, TRUE);
			}
			else
			{
				DBG2(DBG_IMV, "no workitems available - no evaluation possible");
				state->set_recommendation(state,
								TNC_IMV_ACTION_RECOMMENDATION_ALLOW,
								TNC_IMV_EVALUATION_RESULT_DONT_KNOW);
			}
			handshake_state = IMV_OS_STATE_POLICY_START;
		}
		else if (handshake_state == IMV_OS_STATE_ATTR_REQ)
		{
			/**
			 * both the IETF Product Information and IETF String Version
			 * attribute should have been present
			 */
			state->set_recommendation(state,
								TNC_IMV_ACTION_RECOMMENDATION_NO_RECOMMENDATION,
								TNC_IMV_EVALUATION_RESULT_ERROR);

			/* send assessment */
			result = out_msg->send_assessment(out_msg);
			out_msg->destroy(out_msg);

			if (result != TNC_RESULT_SUCCESS)
			{
				return result;
			}  
			return imv_os->provide_recommendation(imv_os, state);
		}
		else
		{
			handshake_state = IMV_OS_STATE_ATTR_REQ;
		}
		os_state->set_handshake_state(os_state, handshake_state);
	}

	if (handshake_state == IMV_OS_STATE_POLICY_START && session)
	{
		enumerator = session->create_workitem_enumerator(session);
		if (enumerator)
		{
			while (enumerator->enumerate(enumerator, &workitem))
			{
				if (workitem->get_imv_id(workitem) != TNC_IMVID_ANY)
				{
					continue;
				}
				no_workitems = FALSE;

				switch (workitem->get_type(workitem))
				{
					case IMV_WORKITEM_PACKAGES:
						attr = ietf_attr_attr_request_create(PEN_IETF,
										IETF_ATTR_INSTALLED_PACKAGES);
						out_msg->add_attribute(out_msg, attr);
						break;
					case IMV_WORKITEM_UNKNOWN_SOURCE:
						attr = ita_attr_get_settings_create(
									"install_non_market_apps");
						out_msg->add_attribute(out_msg, attr);
						break;
					case IMV_WORKITEM_FORWARDING:
					case IMV_WORKITEM_DEFAULT_PWD:
						break;
					default:
						continue;
				}
				workitem->set_imv_id(workitem, imv_id);
			}
			enumerator->destroy(enumerator);

			if (no_workitems)
			{
				DBG2(DBG_IMV, "no workitems generated - no evaluation requested");
				state->set_recommendation(state,
								TNC_IMV_ACTION_RECOMMENDATION_ALLOW,
								TNC_IMV_EVALUATION_RESULT_DONT_KNOW);
			}
			handshake_state = IMV_OS_STATE_WORKITEMS;
			os_state->set_handshake_state(os_state, handshake_state);
		}
	}

	if (handshake_state == IMV_OS_STATE_WORKITEMS && session)
	{
		TNC_IMV_Evaluation_Result eval;
		TNC_IMV_Action_Recommendation rec;
		char buf[BUF_LEN], *result_str;
		bool fail;

		enumerator = session->create_workitem_enumerator(session);
		while (enumerator->enumerate(enumerator, &workitem))
		{
			if (workitem->get_imv_id(workitem) != imv_id)
			{
				continue;
			}
			eval = TNC_IMV_EVALUATION_RESULT_DONT_KNOW;

			switch (workitem->get_type(workitem))
			{
				case IMV_WORKITEM_PACKAGES:
				{
					int count, count_update, count_blacklist, count_ok;

					if (!(received & IMV_OS_ATTR_INSTALLED_PACKAGES) ||
						os_state->get_angel_count(os_state))
					{
						continue;
					}
					os_state->get_count(os_state, &count, &count_update,
										&count_blacklist, &count_ok);
					fail = count_update || count_blacklist;
					eval = fail ? TNC_IMV_EVALUATION_RESULT_NONCOMPLIANT_MINOR :
								  TNC_IMV_EVALUATION_RESULT_COMPLIANT;
					snprintf(buf, BUF_LEN, "processed %d packages: "
							"%d not updated, %d blacklisted, %d ok, "
							"%d not found",
							count, count_update, count_blacklist, count_ok,
							count - count_update - count_blacklist - count_ok);
					result_str = buf;
					break;
				}
				case IMV_WORKITEM_UNKNOWN_SOURCE:
					if (!(received & IMV_OS_ATTR_SETTINGS))
					{
						continue;
					}
					fail = os_state->get_os_settings(os_state) &
								OS_SETTINGS_UNKNOWN_SOURCE;
					eval = fail ? TNC_IMV_EVALUATION_RESULT_NONCOMPLIANT_MINOR :
								  TNC_IMV_EVALUATION_RESULT_COMPLIANT;
					result_str = fail ? "unknown sources enabled" : "";
					break;					
				case IMV_WORKITEM_FORWARDING:
					if (!(received & IMV_OS_ATTR_FORWARDING_ENABLED))
					{
						continue;
					}
					fail = os_state->get_os_settings(os_state) &
								OS_SETTINGS_FWD_ENABLED;
					eval = fail ? TNC_IMV_EVALUATION_RESULT_NONCOMPLIANT_MAJOR :
								  TNC_IMV_EVALUATION_RESULT_COMPLIANT;
					result_str = fail ? "forwarding enabled" : "";
					break;
				case IMV_WORKITEM_DEFAULT_PWD:
					if (!(received & IMV_OS_ATTR_FACTORY_DEFAULT_PWD_ENABLED))
					{
						continue;
					}
					fail = os_state->get_os_settings(os_state) &
								OS_SETTINGS_DEFAULT_PWD_ENABLED;
					eval = fail ? TNC_IMV_EVALUATION_RESULT_NONCOMPLIANT_MAJOR :
								  TNC_IMV_EVALUATION_RESULT_COMPLIANT;
					result_str = fail ? "default password enabled" : "";
					break;
				default:
					continue;
			}
			if (eval != TNC_IMV_EVALUATION_RESULT_DONT_KNOW)
			{
				session->remove_workitem(session, enumerator);
				rec = workitem->set_result(workitem, result_str, eval);
				state->update_recommendation(state, rec, eval);
				imcv_db->finalize_workitem(imcv_db, workitem);
				workitem->destroy(workitem);
			}
		}
		enumerator->destroy(enumerator);

		/* finalized all workitems ? */
		if (session->get_workitem_count(session, imv_id) == 0)
		{
			result = out_msg->send_assessment(out_msg);
			out_msg->destroy(out_msg);
			if (result != TNC_RESULT_SUCCESS)
			{
				return result;
			}
			return imv_os->provide_recommendation(imv_os, state);
		}		
	}

	/* send non-empty PA-TNC message with excl flag not set */
	if (out_msg->get_attribute_count(out_msg))
	{
		result = out_msg->send(out_msg, FALSE);
	}
	out_msg->destroy(out_msg);

	return result;
}

