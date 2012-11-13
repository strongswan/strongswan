/*
 * Copyright (C) 2012 Andreas Steffen
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

#include "imv_os_state.h"

#include <utils/debug.h>
#include <collections/linked_list.h>

typedef struct private_imv_os_state_t private_imv_os_state_t;

/**
 * Private data of an imv_os_state_t object.
 */
struct private_imv_os_state_t {

	/**
	 * Public members of imv_os_state_t
	 */
	imv_os_state_t public;

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
	 * OS Product Information (concatenation of OS Name and Version)
	 */
	char *info;

	/**
	 * OS Type
	 */
	os_type_t type;

	/**
	 * OS Name
	 */
	chunk_t name;

	/**
	 * OS Version
	 */
	chunk_t version;

	/**
	 * List of vulnerable or blacklisted packages
	 */
	linked_list_t *bad_packages;

	/**
	 * Local copy of the remediation instruction string
	 */
	char *instructions;

	/**
	 * Number of processed packages
	 */
	int count;

	/**
	 * Number of blacklisted or not updated packages
	 */
	int count_bad;

	/**
	 * Number of whitelisted packages
	 */
	int count_ok;

	/**
	 * OS Installed Package request sent - mandatory response expected
	 */
	bool package_request;

	/**
	 * Angel count
	 */
	int angel_count;

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
	{ "en", "Vulnerable or blacklisted software packages were found" },
	{ "de", "Schwachstellenbehaftete oder gesperrte Softwarepakete wurden gefunden" },
};

/**
 * Table of multi-lingual remediation instruction string entries
 */
static entry_t instructions [] = {
	{ "en", "Please update the following software packages:\n" },
	{ "de", "Bitte updaten Sie die folgenden Softwarepakete\n" },
	{ "pl", "Proszę zaktualizować następujące pakiety:\n" }
};

METHOD(imv_state_t, get_connection_id, TNC_ConnectionID,
	private_imv_os_state_t *this)
{
	return this->connection_id;
}

METHOD(imv_state_t, has_long, bool,
	private_imv_os_state_t *this)
{
	return this->has_long;
}

METHOD(imv_state_t, has_excl, bool,
	private_imv_os_state_t *this)
{
	return this->has_excl;
}

METHOD(imv_state_t, set_flags, void,
	private_imv_os_state_t *this, bool has_long, bool has_excl)
{
	this->has_long = has_long;
	this->has_excl = has_excl;
}

METHOD(imv_state_t, set_max_msg_len, void,
	private_imv_os_state_t *this, u_int32_t max_msg_len)
{
	this->max_msg_len = max_msg_len;
}

METHOD(imv_state_t, get_max_msg_len, u_int32_t,
	private_imv_os_state_t *this)
{
	return this->max_msg_len;
}

METHOD(imv_state_t, change_state, void,
	private_imv_os_state_t *this, TNC_ConnectionState new_state)
{
	this->state = new_state;
}

METHOD(imv_state_t, get_recommendation, void,
	private_imv_os_state_t *this, TNC_IMV_Action_Recommendation *rec,
									TNC_IMV_Evaluation_Result *eval)
{
	*rec = this->rec;
	*eval = this->eval;
}

METHOD(imv_state_t, set_recommendation, void,
	private_imv_os_state_t *this, TNC_IMV_Action_Recommendation rec,
									TNC_IMV_Evaluation_Result eval)
{
	this->rec = rec;
	this->eval = eval;
}

METHOD(imv_state_t, get_reason_string, bool,
	private_imv_os_state_t *this, enumerator_t *language_enumerator,
	char **reason_string, char **reason_language)
{
	bool match = FALSE;
	char *lang;
	int i;

	if (!this->count_bad)
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
	private_imv_os_state_t *this, enumerator_t *language_enumerator,
	char **string, char **lang_code, char **uri)
{
	bool match = FALSE;
	char *lang, *package, *pos;
	enumerator_t *enumerator;
	int i, len;

	if (!this->count_bad)
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

	/* Compute the size of the remediation string */
	len = strlen(*string);

	enumerator = this->bad_packages->create_enumerator(this->bad_packages);
	while (enumerator->enumerate(enumerator, &package))
	{
		len += strlen(package) + 1;
	}
	enumerator->destroy(enumerator);

	pos = this->instructions = malloc(len + 1);
	strcpy(pos, *string);
	pos += strlen(*string);

	enumerator = this->bad_packages->create_enumerator(this->bad_packages);
	while (enumerator->enumerate(enumerator, &package))
	{
		strcpy(pos, package);
		pos += strlen(package);
		*pos++ = '\n';
	}
	enumerator->destroy(enumerator);
	*pos = '\0';

	*string = this->instructions;
	*uri = lib->settings->get_str(lib->settings,
				"libimcv.plugins.imv-os.remediation_uri", NULL);

	return TRUE;
}

METHOD(imv_state_t, destroy, void,
	private_imv_os_state_t *this)
{
	this->bad_packages->destroy_function(this->bad_packages, free);
	free(this->instructions);
	free(this->info);
	free(this->name.ptr);
	free(this->version.ptr);
	free(this);
}

METHOD(imv_os_state_t, set_info, void,
	private_imv_os_state_t *this, os_type_t type, chunk_t name, chunk_t version)
{
	int len = name.len + 1 + version.len + 1;

	/* OS info is a concatenation of OS name and OS version */
	free(this->info);
	this->info = malloc(len);
	snprintf(this->info, len, "%.*s %.*s", name.len, name.ptr,
										   version.len, version.ptr);
	this->type = type;
	this->name = chunk_clone(name);
	this->version = chunk_clone(version);
}

METHOD(imv_os_state_t, get_info, char*,
	private_imv_os_state_t *this, os_type_t *type, chunk_t *name,
	chunk_t *version)
{
	if (type)
	{
		*type = this->type;
	}
	if (name)
	{
		*name = this->name;
	}
	if (version)
	{
		*version = this->version;
	}
	return this->info;
}

METHOD(imv_os_state_t, set_count, void,
	private_imv_os_state_t *this, int count, int count_bad, int count_ok)
{
	this->count     += count;
	this->count_bad += count_bad;
	this->count_ok  += count_ok;
}

METHOD(imv_os_state_t, get_count, void,
	private_imv_os_state_t *this, int *count, int *count_bad, int *count_ok)
{
	if (count)
	{
		*count = this->count;
	}
	if (count_bad)
	{
		*count_bad = this->count_bad;
	}
	if (count_ok)
	{
		*count_ok = this->count_ok;
	}
}

METHOD(imv_os_state_t, set_package_request, void,
	private_imv_os_state_t *this, bool set)
{
	this->package_request = set;
}

METHOD(imv_os_state_t, get_package_request, bool,
	private_imv_os_state_t *this)
{
	return this->package_request;
}

METHOD(imv_os_state_t, set_angel_count, void,
	private_imv_os_state_t *this, bool start)
{
	this->angel_count += start ? 1 : -1;
}

METHOD(imv_os_state_t, get_angel_count, int,
	private_imv_os_state_t *this)
{
	return this->angel_count;
}

METHOD(imv_os_state_t, add_bad_package, void,
	private_imv_os_state_t *this, char *package)
{
	this->bad_packages->insert_last(this->bad_packages, strdup(package));
}

/**
 * Described in header.
 */
imv_state_t *imv_os_state_create(TNC_ConnectionID connection_id)
{
	private_imv_os_state_t *this;

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
			.set_info = _set_info,
			.get_info = _get_info,
			.set_count = _set_count,
			.get_count = _get_count,
			.set_package_request = _set_package_request,
			.get_package_request = _get_package_request,
			.set_angel_count = _set_angel_count,
			.get_angel_count = _get_angel_count,
			.add_bad_package = _add_bad_package,
		},
		.state = TNC_CONNECTION_STATE_CREATE,
		.rec = TNC_IMV_ACTION_RECOMMENDATION_NO_RECOMMENDATION,
		.eval = TNC_IMV_EVALUATION_RESULT_DONT_KNOW,
		.connection_id = connection_id,
		.bad_packages = linked_list_create(),
	);

	return &this->public.interface;
}


