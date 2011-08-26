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

#include "imv_attestation_state.h"

#include <utils/lexparser.h>
#include <debug.h>

typedef struct private_imv_attestation_state_t private_imv_attestation_state_t;

/**
 * Private data of an imv_attestation_state_t object.
 */
struct private_imv_attestation_state_t {

	/**
	 * Public members of imv_attestation_state_t
	 */
	imv_attestation_state_t public;

	/**
	 * TNCCS connection ID
	 */
	TNC_ConnectionID connection_id;

	/**
	 * TNCCS connection state
	 */
	TNC_ConnectionState state;
	
	/**
	 * IMV Attestation handshake state
	 */
	imv_attestation_handshake_state_t handshake_state;

	/**
	 * IMV action recommendation
	 */
	TNC_IMV_Action_Recommendation rec;

	/**
	 * IMV evaluation result
	 */
	TNC_IMV_Evaluation_Result eval;

	/**
	 * PTS object
	 */
	pts_t *pts;

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
	{ "en", "IMC Attestation Measurement/s of requested file didn't match" },
	{ "mn", "IMC Attestation Шалгахаар тохируулсан файлуудын хэмжилтүүд таарсангүй" },
	{ "de", "IMC Attestation Messung/en von angefordeten Datein stimmt nicht überein" },
};

METHOD(imv_state_t, get_connection_id, TNC_ConnectionID,
	private_imv_attestation_state_t *this)
{
	return this->connection_id;
}

METHOD(imv_state_t, change_state, void,
	private_imv_attestation_state_t *this, TNC_ConnectionState new_state)
{
	this->state = new_state;
}

METHOD(imv_state_t, get_recommendation, void,
	private_imv_attestation_state_t *this, TNC_IMV_Action_Recommendation *rec,
									TNC_IMV_Evaluation_Result *eval)
{
	*rec = this->rec;
	*eval = this->eval;
}

METHOD(imv_state_t, set_recommendation, void,
	private_imv_attestation_state_t *this, TNC_IMV_Action_Recommendation rec,
									TNC_IMV_Evaluation_Result eval)
{
	this->rec = rec;
	this->eval = eval;
}

METHOD(imv_state_t, get_reason_string, bool,
	private_imv_attestation_state_t *this, chunk_t preferred_language,
	chunk_t *reason_string, chunk_t *reason_language)
{
	chunk_t pref_lang, lang;
	u_char *pos;
	int i;

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
				*reason_language = lang;
				*reason_string = chunk_create(reasons[i].string, 
										strlen(reasons[i].string));
				return TRUE;
			}
		}
	}

	/* no preferred language match found - use the default language */
	*reason_string =   chunk_create(reasons[0].string,
									strlen(reasons[0].string));
	*reason_language = chunk_create(reasons[0].lang, 
									strlen(reasons[0].lang));
	return TRUE;
}

METHOD(imv_state_t, destroy, void,
	private_imv_attestation_state_t *this)
{
	this->pts->destroy(this->pts);
	free(this);
}

METHOD(imv_attestation_state_t, get_handshake_state, imv_attestation_handshake_state_t,
	private_imv_attestation_state_t *this)
{
	return this->handshake_state;
}

METHOD(imv_attestation_state_t, set_handshake_state, void,
	private_imv_attestation_state_t *this, imv_attestation_handshake_state_t new_state)
{
	this->handshake_state = new_state;
}

METHOD(imv_attestation_state_t, get_pts, pts_t*,
	private_imv_attestation_state_t *this)
{
	return this->pts;
}

/**
 * Described in header.
 */
imv_state_t *imv_attestation_state_create(TNC_ConnectionID connection_id)
{
	private_imv_attestation_state_t *this;

	INIT(this,
		.public = {
			.interface = {
				.get_connection_id = _get_connection_id,
				.change_state = _change_state,
				.get_recommendation = _get_recommendation,
				.set_recommendation = _set_recommendation,
				.get_reason_string = _get_reason_string,
				.destroy = _destroy,
			},
			.get_handshake_state = _get_handshake_state,
			.set_handshake_state = _set_handshake_state,
			.get_pts = _get_pts,
		},
		.connection_id = connection_id,
		.state = TNC_CONNECTION_STATE_CREATE,
		.handshake_state = IMV_ATTESTATION_STATE_INIT,
		.rec = TNC_IMV_ACTION_RECOMMENDATION_NO_RECOMMENDATION,
		.eval = TNC_IMV_EVALUATION_RESULT_DONT_KNOW,
		.pts = pts_create(FALSE),
	);
	
	return &this->public.interface;
}
