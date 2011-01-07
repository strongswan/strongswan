/*
 * Copyright (C) 2006 Mike McCauley (mikem@open.com.au)
 * Copyright (C) 2010 Andreas Steffen, HSR Hochschule fuer Technik Rapperswil
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

#include "tnccs_recommendation_msg.h"

#include <debug.h>

typedef struct private_tnccs_recommendation_msg_t private_tnccs_recommendation_msg_t;

/**
 * Private data of a tnccs_recommendation_msg_t object.
 *
 */
struct private_tnccs_recommendation_msg_t {
	/**
	 * Public tnccs_recommendation_msg_t interface.
	 */
	tnccs_recommendation_msg_t public;

	/**
	 * TNCCS message type
	 */
	tnccs_msg_type_t type;

	/**
	 * XML-encoded message node
	 */
	xmlNodePtr node;

	/**
	 * Action Recommendation
	 */
	TNC_IMV_Action_Recommendation rec;
};

METHOD(tnccs_msg_t, get_type, tnccs_msg_type_t,
	private_tnccs_recommendation_msg_t *this)
{
	return this->type;
}

METHOD(tnccs_msg_t, get_node, xmlNodePtr,
	private_tnccs_recommendation_msg_t *this)
{
	return this->node;
}

METHOD(tnccs_msg_t, destroy, void,
	private_tnccs_recommendation_msg_t *this)
{
	free(this);
}

METHOD(tnccs_recommendation_msg_t, get_recommendation, TNC_IMV_Action_Recommendation,
	private_tnccs_recommendation_msg_t *this)
{
	return this->rec;
}

/**
 * See header
 */
tnccs_msg_t *tnccs_recommendation_msg_create_from_node(xmlNodePtr node)
{
	private_tnccs_recommendation_msg_t *this;

	INIT(this,
		.public = {
			.tnccs_msg_interface = {
				.get_type = _get_type,
				.get_node = _get_node,
				.destroy = _destroy,
			},
			.get_recommendation = _get_recommendation,
		},
		.type = TNCCS_MSG_RECOMMENDATION,
		.node = node,
	);

	return &this->public.tnccs_msg_interface;
}

/**
 * See header
 */
tnccs_msg_t *tnccs_recommendation_msg_create(TNC_IMV_Action_Recommendation rec)
{
	private_tnccs_recommendation_msg_t *this;
	xmlNodePtr n, n2;
	char *recommendation_string;

	INIT(this,
		.public = {
			.tnccs_msg_interface = {
				.get_type = _get_type,
				.get_node = _get_node,
				.destroy = _destroy,
			},
			.get_recommendation = _get_recommendation,
		},
		.type = TNCCS_MSG_RECOMMENDATION,
		.node =  xmlNewNode(NULL, BAD_CAST "TNCC-TNCS-Message"),
		.rec = rec,
	);

	/* add the message type number in hex */
	n = xmlNewNode(NULL, BAD_CAST "Type");
	xmlNodeSetContent(n, BAD_CAST "00000001");
	xmlAddChild(this->node, n);

	n = xmlNewNode(NULL, BAD_CAST "XML");
	xmlAddChild(this->node, n);

	switch (rec)
	{
		case TNC_IMV_ACTION_RECOMMENDATION_ALLOW:
			recommendation_string = "allow";
			break;
		case TNC_IMV_ACTION_RECOMMENDATION_ISOLATE:
			recommendation_string = "isolate";
			break;
		case TNC_IMV_ACTION_RECOMMENDATION_NO_ACCESS:
		case TNC_IMV_ACTION_RECOMMENDATION_NO_RECOMMENDATION:
		default:
			recommendation_string = "none";
	}

	n2 = xmlNewNode(NULL, BAD_CAST enum_to_name(tnccs_msg_type_names, this->type));
	xmlNodeSetContent(n2, BAD_CAST recommendation_string);
	xmlAddChild(n, n2);

	return &this->public.tnccs_msg_interface;
}
