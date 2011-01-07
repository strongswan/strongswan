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

#include "tnccs_msg.h"
#include "imc_imv_msg.h"
#include "tnccs_preferred_language_msg.h"

#include <library.h>
#include <debug.h>

ENUM(tnccs_msg_type_names, IMC_IMV_MSG, TNCCS_MSG_ROOF,
	"IMC-IMV",
	"TNCCS-Recommendation",
	"TNCCS-Error",
	"TNCCS-PreferredLanguage",
	"TNCCS-ReasonStrings",
	"TNCCS-TNCSContactInfo"
);

/**
 * See header
 */
tnccs_msg_t* tnccs_msg_create_from_node(xmlNodePtr node)
{
	tnccs_msg_type_t type = IMC_IMV_MSG;

	if (streq((char*)node->name, "IMC-IMV-Message"))
	{
		return imc_imv_msg_create_from_node(node);
	}
	else if (streq((char*)node->name, "TNCC-TNCS-Message"))
	{
		bool found = FALSE;
		xmlNsPtr ns = node->ns;
		xmlNodePtr cur = node->xmlChildrenNode;

		while (cur)
		{
			if (streq((char*)cur->name, "Type") && cur->ns == ns)
			{
		    	xmlChar *content = xmlNodeGetContent(cur);

			    type = strtol((char*)content, NULL, 16);
		    	xmlFree(content);
				found = TRUE;
				break;
			}
		}
		if (!found)
		{
			DBG1(DBG_TNC, "ignoring TNCC-TNCS-Messsage without type");
			return NULL;
		}
		switch (type)
		{
			case TNCCS_MSG_RECOMMENDATION:
				return tnccs_recommendation_msg_create_from_node(node);
			case TNCCS_MSG_ERROR:
				return tnccs_error_msg_create_from_node(node);
			case TNCCS_MSG_PREFERRED_LANGUAGE:
				return tnccs_preferred_language_msg_create_from_node(node);
			case TNCCS_MSG_REASON_STRINGS:
				return tnccs_reason_strings_msg_create_from_node(node);
			case TNCCS_MSG_TNCS_CONTACT_INFO:
				return tnccs_tncs_contact_info_msg_create_from_node(node);
			default:
				DBG1(DBG_TNC, "ignoring TNCC-TNCS-Message with type %d", type);
				return NULL;
		}
	}
	DBG1(DBG_TNC, "ignoring unknown message node '%s'", (char*)node->name);
	return NULL;
}

