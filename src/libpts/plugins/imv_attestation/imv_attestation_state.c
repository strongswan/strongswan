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
#include <utils/linked_list.h>
#include <debug.h>

typedef struct private_imv_attestation_state_t private_imv_attestation_state_t;
typedef struct file_meas_request_t file_meas_request_t;

/**
 * PTS File/Directory Measurement request entry
 */
struct file_meas_request_t {
	u_int16_t id;
	int file_id;
	bool is_dir;
};

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
	 * Does the TNCCS connection support long message types?
	 */
	bool has_long;

	/**
	 * Does the TNCCS connection support exclusive delivery?
	 */
	bool has_excl;

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
	 * File Measurement Request counter
	 */
	u_int16_t file_meas_request_counter;

	/**
	 * List of PTS File/Directory Measurement requests
	 */
	linked_list_t *file_meas_requests;

	/**
	 * List of Functional Components
	 */
	linked_list_t *components;

	/**
	 * PTS object
	 */
	pts_t *pts;

	/**
	 * Measurement error
	 */
	bool measurement_error;

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
	{ "en", "IMV Attestation: Incorrect/pending file measurement/component"
			" evidence or invalid TPM Quote signature received" },
	{ "mn", "IMV Attestation:  Буруу/хүлээгдэж байгаа файл/компонент хэмжилт "
			"эсвэл буруу TPM Quote гарын үсэг" },
	{ "de", "IMV Attestation: Falsche/Fehlende Dateimessung/Komponenten Beweis "
			"oder ungültige TPM Quote Unterschrift ist erhalten" },
};

METHOD(imv_state_t, get_connection_id, TNC_ConnectionID,
	private_imv_attestation_state_t *this)
{
	return this->connection_id;
}

METHOD(imv_state_t, has_long, bool,
	private_imv_attestation_state_t *this)
{
	return this->has_long;
}

METHOD(imv_state_t, has_excl, bool,
	private_imv_attestation_state_t *this)
{
	return this->has_excl;
}

METHOD(imv_state_t, set_flags, void,
	private_imv_attestation_state_t *this, bool has_long, bool has_excl)
{
	this->has_long = has_long;
	this->has_excl = has_excl;
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
	this->file_meas_requests->destroy_function(this->file_meas_requests, free);
	this->components->destroy_offset(this->components,
									 offsetof(pts_component_t, destroy));
	this->pts->destroy(this->pts);
	free(this);
}

METHOD(imv_attestation_state_t, get_handshake_state,
	   imv_attestation_handshake_state_t, private_imv_attestation_state_t *this)
{
	return this->handshake_state;
}

METHOD(imv_attestation_state_t, set_handshake_state, void,
	private_imv_attestation_state_t *this,
	imv_attestation_handshake_state_t new_state)
{
	this->handshake_state = new_state;
}

METHOD(imv_attestation_state_t, get_pts, pts_t*,
	private_imv_attestation_state_t *this)
{
	return this->pts;
}

METHOD(imv_attestation_state_t, add_file_meas_request, u_int16_t,
	private_imv_attestation_state_t *this, int file_id, bool is_dir)
{
	file_meas_request_t *request;

	request = malloc_thing(file_meas_request_t);
	request->id = ++this->file_meas_request_counter;
	request->file_id = file_id;
	request->is_dir = is_dir;
	this->file_meas_requests->insert_last(this->file_meas_requests, request);

	return this->file_meas_request_counter;
}

METHOD(imv_attestation_state_t, check_off_file_meas_request, bool,
	private_imv_attestation_state_t *this, u_int16_t id, int *file_id,
	bool* is_dir)
{
	enumerator_t *enumerator;
	file_meas_request_t *request;
	bool found = FALSE;
	
	enumerator = this->file_meas_requests->create_enumerator(this->file_meas_requests);
	while (enumerator->enumerate(enumerator, &request))
	{
		if (request->id == id)
		{
			found = TRUE;
			*file_id = request->file_id;
			*is_dir = request->is_dir;
			this->file_meas_requests->remove_at(this->file_meas_requests, enumerator);
			free(request);
			break;
		}
	}
	enumerator->destroy(enumerator);
	return found;
}

METHOD(imv_attestation_state_t, get_file_meas_request_count, int,
	private_imv_attestation_state_t *this)
{
	return this->file_meas_requests->get_count(this->file_meas_requests);
}

METHOD(imv_attestation_state_t, add_component, void,
	private_imv_attestation_state_t *this, pts_component_t *entry)
{
	this->components->insert_last(this->components, entry);
}

METHOD(imv_attestation_state_t, check_off_component, pts_component_t*,
	private_imv_attestation_state_t *this, pts_comp_func_name_t *name)
{
	enumerator_t *enumerator;
	pts_component_t *entry, *found = NULL;

	enumerator = this->components->create_enumerator(this->components);
	while (enumerator->enumerate(enumerator, &entry))
	{
		if (name->equals(name, entry->get_comp_func_name(entry)))
		{
			found = entry;
			this->components->remove_at(this->components, enumerator);
			break;
		}
	}
	enumerator->destroy(enumerator);
	return found;
}

METHOD(imv_attestation_state_t, check_off_registrations, void,
	private_imv_attestation_state_t *this)
{
	enumerator_t *enumerator;
	pts_component_t *entry;

	enumerator = this->components->create_enumerator(this->components);
	while (enumerator->enumerate(enumerator, &entry))
	{
		if (entry->check_off_registrations(entry))
		{
			this->components->remove_at(this->components, enumerator);
			entry->destroy(entry);
		}
	}
	enumerator->destroy(enumerator);
}

METHOD(imv_attestation_state_t, get_component_count, int,
	private_imv_attestation_state_t *this)
{
	return this->components->get_count(this->components);
}

METHOD(imv_attestation_state_t, get_measurement_error, bool,
	private_imv_attestation_state_t *this)
{
	return this->measurement_error;
}

METHOD(imv_attestation_state_t, set_measurement_error, void,
	private_imv_attestation_state_t *this)
{
	this->measurement_error = TRUE;
}

/**
 * Described in header.
 */
imv_state_t *imv_attestation_state_create(TNC_ConnectionID connection_id)
{
	private_imv_attestation_state_t *this;
	char *platform_info;

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
			.get_handshake_state = _get_handshake_state,
			.set_handshake_state = _set_handshake_state,
			.get_pts = _get_pts,
			.add_file_meas_request = _add_file_meas_request,
			.check_off_file_meas_request = _check_off_file_meas_request,
			.get_file_meas_request_count = _get_file_meas_request_count,
			.add_component = _add_component,
			.check_off_component = _check_off_component,
			.check_off_registrations = _check_off_registrations,
			.get_component_count = _get_component_count,
			.get_measurement_error = _get_measurement_error,
			.set_measurement_error = _set_measurement_error,
		},
		.connection_id = connection_id,
		.state = TNC_CONNECTION_STATE_CREATE,
		.handshake_state = IMV_ATTESTATION_STATE_INIT,
		.rec = TNC_IMV_ACTION_RECOMMENDATION_NO_RECOMMENDATION,
		.eval = TNC_IMV_EVALUATION_RESULT_DONT_KNOW,
		.file_meas_requests = linked_list_create(),
		.components = linked_list_create(),
		.pts = pts_create(FALSE),
	);

	platform_info = lib->settings->get_str(lib->settings,
						 "libimcv.plugins.imv-attestation.platform_info", NULL);
	if (platform_info)
	{
		this->pts->set_platform_info(this->pts, platform_info);
	}
	
	return &this->public.interface;
}
