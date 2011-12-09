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

#include "imv_scanner_state.h"

#include <utils/lexparser.h>
#include <debug.h>

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
	 * Local copy of the reason string
	 */
	chunk_t reason_string;
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
	{ "en", "The following ports are open:" },
	{ "de", "Die folgenden Ports sind offen" },
	{ "fr", "Les ports suivants sont ouverts:" },
	{ "pl", "Następujące porty sa otwarte:" }
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
	private_imv_scanner_state_t *this, chunk_t preferred_language,
	chunk_t *reason_string, chunk_t *reason_language)
{
	chunk_t pref_lang, lang;
	u_char *pos;
	int i;

	if (!this->violating_ports)
	{
		return FALSE;
	}

	while (eat_whitespace(&preferred_language))
	{
		if (!extract_token(&pref_lang, ',', &preferred_language))
		{
			/* last entry in a comma-separated list or single entry */
			pref_lang = preferred_language;
		}

		/* eat trailing whitespace */
		pos = pref_lang.ptr + pref_lang.len - 1;
		while (pref_lang.len && *pos-- == ' ')
		{
			pref_lang.len--;
		}

		for (i = 0 ; i < countof(reasons); i++)
		{
			lang = chunk_create(reasons[i].lang, strlen(reasons[i].lang));
			if (chunk_equals(lang, pref_lang))
			{
				this->reason_string = chunk_cat("cc",
									chunk_create(reasons[i].string, 
												 strlen(reasons[i].string)),
									chunk_create(this->violating_ports,
												 strlen(this->violating_ports)));
				*reason_string = this->reason_string;
				*reason_language = lang;
				return TRUE;
			}
		}
	}

	/* no preferred language match found - use the default language */

	this->reason_string =   chunk_cat("cc",
									chunk_create(reasons[0].string,
												 strlen(reasons[0].string)),
									chunk_create(this->violating_ports,
												 strlen(this->violating_ports)));
	*reason_string = this->reason_string;
	*reason_language = chunk_create(reasons[0].lang, 
									strlen(reasons[0].lang));
	return TRUE;
}

METHOD(imv_state_t, destroy, void,
	private_imv_scanner_state_t *this)
{
	free(this->violating_ports);
	free(this->reason_string.ptr);
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
				.change_state = _change_state,
				.get_recommendation = _get_recommendation,
				.set_recommendation = _set_recommendation,
				.get_reason_string = _get_reason_string,
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


