/*
 * Copyright (C) 2011-2012 Andreas Steffen
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

#include "imv_scanner_state.h"

#include <utils/lexparser.h>
#include <utils/debug.h>

typedef struct private_imv_scanner_state_t private_imv_scanner_state_t;

/**
 * Private data of an imv_scanner_state_t object.
 */
struct private_imv_scanner_state_t {

	/**
	 * Public members of imv_scanner_state_t
	 */
	imv_scanner_state_t public;

	/**
	 * TNCCS connection ID
	 */
	TNC_ConnectionID connection_id;

	/**
	 * TNCCS connection state
	 */
	TNC_ConnectionState state;

	/**
	 * Does the TNCCS connection support long message types?
	 */
	bool has_long;

	/**
	 * Does the TNCCS connection support exclusive delivery?
	 */
	bool has_excl;

	/**
	 * Maximum PA-TNC message size for this TNCCS connection
	 */
	u_int32_t max_msg_len;

	/**
	 * IMV action recommendation
	 */
	TNC_IMV_Action_Recommendation rec;

	/**
	 * IMV evaluation result
	 */
	TNC_IMV_Evaluation_Result eval;

	/**
	 * String with list of ports that should be closed
	 */
	char *violating_ports;

	/**
	 * Local copy of the remediation instruction string
	 */
	char *instructions;
};

typedef struct entry_t entry_t;

/**
 * Define an internal reason string entry
 */
struct entry_t {
	char *lang;
	char *string;
};

/**
 * Table of multi-lingual reason string entries
 */
static entry_t reasons[] = {
	{ "en", "Open server ports were detected" },
	{ "de", "Offene Serverports wurden festgestellt" },
	{ "fr", "Il y a des ports du serveur ouverts" },
	{ "pl", "Są otwarte porty serwera" }
};

/**
 * Table of multi-lingual remediation instruction string entries
 */
static entry_t instructions [] = {
	{ "en", "Please close the following server ports:" },
	{ "de", "Bitte schliessen Sie die folgenden Serverports:" },
	{ "fr", "Fermez les ports du serveur suivants s'il vous plait:" },
	{ "pl", "Proszę zamknąć następujące porty serwera:" }
};

METHOD(imv_state_t, get_connection_id, TNC_ConnectionID,
	private_imv_scanner_state_t *this)
{
	return this->connection_id;
}

METHOD(imv_state_t, has_long, bool,
	private_imv_scanner_state_t *this)
{
	return this->has_long;
}

METHOD(imv_state_t, has_excl, bool,
	private_imv_scanner_state_t *this)
{
	return this->has_excl;
}

METHOD(imv_state_t, set_flags, void,
	private_imv_scanner_state_t *this, bool has_long, bool has_excl)
{
	this->has_long = has_long;
	this->has_excl = has_excl;
}

METHOD(imv_state_t, set_max_msg_len, void,
	private_imv_scanner_state_t *this, u_int32_t max_msg_len)
{
	this->max_msg_len = max_msg_len;
}

METHOD(imv_state_t, get_max_msg_len, u_int32_t,
	private_imv_scanner_state_t *this)
{
	return this->max_msg_len;
}

METHOD(imv_state_t, change_state, void,
	private_imv_scanner_state_t *this, TNC_ConnectionState new_state)
{
	this->state = new_state;
}

METHOD(imv_state_t, get_recommendation, void,
	private_imv_scanner_state_t *this, TNC_IMV_Action_Recommendation *rec,
									TNC_IMV_Evaluation_Result *eval)
{
	*rec = this->rec;
	*eval = this->eval;
}

METHOD(imv_state_t, set_recommendation, void,
	private_imv_scanner_state_t *this, TNC_IMV_Action_Recommendation rec,
									TNC_IMV_Evaluation_Result eval)
{
	this->rec = rec;
	this->eval = eval;
}

METHOD(imv_state_t, get_reason_string, bool,
	private_imv_scanner_state_t *this, enumerator_t *language_enumerator,
	char **reason_string, char **reason_language)
{
	bool match = FALSE;
	char *lang;
	int i;

	if (!this->violating_ports)
	{
		return FALSE;
	}

	/* set the default language */
	*reason_language = reasons[0].lang;
	*reason_string   = reasons[0].string;

	while (language_enumerator->enumerate(language_enumerator, &lang))
	{
		for (i = 0; i < countof(reasons); i++)
		{
			if (streq(lang, reasons[i].lang))
			{
				match = TRUE;
				*reason_language = reasons[i].lang;
				*reason_string   = reasons[i].string;
				break;
			}
		}
		if (match)
		{
			break;
		}
	}

	return TRUE;
}

METHOD(imv_state_t, get_remediation_instructions, bool,
	private_imv_scanner_state_t *this, enumerator_t *language_enumerator,
	char **string, char **lang_code)
{
	bool match = FALSE;
	char *lang;
	int i;

	if (!this->violating_ports)
	{
		return FALSE;
	}

	/* set the default language */
	*lang_code = instructions[0].lang;
	*string    = instructions[0].string;

	while (language_enumerator->enumerate(language_enumerator, &lang))
	{
		for (i = 0; i < countof(instructions); i++)
		{
			if (streq(lang, instructions[i].lang))
			{
				match = TRUE;
				*lang_code = instructions[i].lang;
				*string    = instructions[i].string;
				break;
			}
		}
		if (match)
		{
			break;
		}
	}
	this->instructions = malloc(strlen(*string) +
								strlen(this->violating_ports) + 1);
	sprintf(this->instructions, "%s%s", *string, this->violating_ports);
	*string = this->instructions;

	return TRUE;
}

METHOD(imv_state_t, destroy, void,
	private_imv_scanner_state_t *this)
{
	free(this->violating_ports);
	free(this->instructions);
	free(this);
}

METHOD(imv_scanner_state_t, set_violating_ports, void,
	private_imv_scanner_state_t *this, char *ports)
{
	this->violating_ports = strdup(ports);
}

/**
 * Described in header.
 */
imv_state_t *imv_scanner_state_create(TNC_ConnectionID connection_id)
{
	private_imv_scanner_state_t *this;

	INIT(this,
		.public = {
			.interface = {
				.get_connection_id = _get_connection_id,
				.has_long = _has_long,
				.has_excl = _has_excl,
				.set_flags = _set_flags,
				.set_max_msg_len = _set_max_msg_len,
				.get_max_msg_len = _get_max_msg_len,
				.change_state = _change_state,
				.get_recommendation = _get_recommendation,
				.set_recommendation = _set_recommendation,
				.get_reason_string = _get_reason_string,
				.get_remediation_instructions = _get_remediation_instructions,
				.destroy = _destroy,
			},
			.set_violating_ports = _set_violating_ports,
		},
		.state = TNC_CONNECTION_STATE_CREATE,
		.rec = TNC_IMV_ACTION_RECOMMENDATION_NO_RECOMMENDATION,
		.eval = TNC_IMV_EVALUATION_RESULT_DONT_KNOW,
		.connection_id = connection_id,
	);

	return &this->public.interface;
}


