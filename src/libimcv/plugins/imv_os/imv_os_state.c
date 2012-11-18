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
typedef struct package_entry_t package_entry_t;
typedef struct entry_t entry_t;
typedef struct instruction_entry_t instruction_entry_t;

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
	 * Local copy of the reason string
	 */
	char *reasons;

	/**
	 * Local copy of the remediation instruction string
	 */
	char *instructions;

	/**
	 * Number of processed packages
	 */
	int count;

	/**
	 * Number of not updated packages
	 */
	int count_update;

	/**
	 * Number of blacklisted packages
	 */
	int count_blacklist;

	/**
	 * Number of whitelisted packages
	 */
	int count_ok;

	/**
	 * OS Installed Package request sent - mandatory response expected
	 */
	bool package_request;

	/**
	 * OS Settings
	 */
	u_int os_settings;

	/**
	 * Angel count
	 */
	int angel_count;

};

/**
 * Store a bad package entry
 */
struct package_entry_t {
	char *name;
	os_package_state_t state;
};

/**
 * Free a bad package entry
 */
static void free_package_entry(package_entry_t *this)
{
	free(this->name);
	free(this);
}

/**
 * Define a language string entry
 */
struct entry_t {
	char *lang;
	char *string;
};

/**
 * Table of multi-lingual improper settings reason string entries
 */
static entry_t settings_reasons[] = {
	{ "en", "Improper OS settings were detected" },
	{ "de", "Unzulässige OS Einstellungen wurden festgestellt" }
};

/**
 * Table of multi-lingual reason string entries
 */
static entry_t reasons[] = {
	{ "en", "Vulnerable or blacklisted software packages were found" },
	{ "de", "Schwachstellenbehaftete oder gesperrte Softwarepakete wurden gefunden" }
};

/**
 * Table of multi-lingual forwarding enable string entries
 */
static entry_t instruction_fwd_enabled[] = {
	{ "en", "Please disable IP forwarding" },
	{ "de", "Bitte deaktivieren Sie das IP Forwarding" }
};

/**
 * Table of multi-lingual default password enabled string entries
 */
static entry_t instruction_default_pwd_enabled[] = {
	{ "en", "Please change the default password" },
	{ "de", "Bitte ändern Sie das default Passwort" }
};

/**
 * Table of multi-lingual defaul install non market apps string entries
 */
static entry_t instruction_non_market_apps[] = {
	{ "en", "Do not allow the installation of apps from unknown sources" },
	{ "de", "Erlauben Sie nicht die Installation von Apps von unbekannten Quellen" }
};

/**
 * Define a remediation instruction string entry
 */
struct instruction_entry_t {
	char *lang;
	char *update_string;
	char *removal_string;
};

/**
 * Tables of multi-lingual remediation instruction string entries
 */
static instruction_entry_t instructions [] = {
	{ "en", "Please update the following software packages:\n",
			"Please remove the following software packages:\n" },
	{ "de", "Bitte updaten Sie die folgenden Softwarepakete\n",
			"Bitte entfernen Sie die folgenden Softwarepakete\n" },
	{ "pl", "Proszę zaktualizować następujące pakiety:\n",
			"Proszę usunąć następujące pakiety:\n" }
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
	char *lang, *pos;
	int i, i_chosen = 0, len = 0, nr_of_reasons = 0;

	if (!this->count_update && !this->count_blacklist & !this->os_settings)
	{
		return FALSE;
	}

	while (language_enumerator->enumerate(language_enumerator, &lang))
	{
		for (i = 0; i < countof(reasons); i++)
		{
			if (streq(lang, reasons[i].lang))
			{
				match = TRUE;
				i_chosen = i;
				break;
			}
		}
		if (match)
		{
			break;
		}
	}
	*reason_language = reasons[i_chosen].lang;

	if (this->count_update ||  this->count_blacklist)
	{
		len += strlen(reasons[i_chosen].string);
		nr_of_reasons++;
	}
	if (this->os_settings)
	{
		len += strlen(settings_reasons[i_chosen].string);
		nr_of_reasons++;
	}

	/* Allocate memory for the reason string */
	pos = this->reasons = malloc(len + nr_of_reasons);

	if (this->count_update ||  this->count_blacklist)
	{
		strcpy(pos, reasons[i_chosen].string);
		pos += strlen(reasons[i_chosen].string);
		if (--nr_of_reasons)
		{
			*pos++ = '\n';
		}
	}
	if (this->os_settings)
	{
		strcpy(pos, settings_reasons[i_chosen].string);
		pos += strlen(settings_reasons[i_chosen].string);
	}
	*pos = '\0';
	*reason_string = this->reasons;

	return TRUE;
}

METHOD(imv_state_t, get_remediation_instructions, bool,
	private_imv_os_state_t *this, enumerator_t *language_enumerator,
	char **string, char **lang_code, char **uri)
{
	bool match = FALSE;
	char *lang, *pos;
	enumerator_t *enumerator;
	package_entry_t *entry;
	int i, i_chosen = 0, len = 0, nr_of_instructions = 0;

	if (!this->count_update && !this->count_blacklist & !this->os_settings)
	{
		return FALSE;
	}

	while (language_enumerator->enumerate(language_enumerator, &lang))
	{
		for (i = 0; i < countof(instructions); i++)
		{
			if (streq(lang, instructions[i].lang))
			{
				match = TRUE;
				i_chosen = i;
				break;
			}
		}
		if (match)
		{
			break;
		}
	}
	*lang_code = instructions[i_chosen].lang;

	/* Compute the size of the remediation string */
	if (this->count_update)
	{
		len += strlen(instructions[i_chosen].update_string);
	}
	if (this->count_blacklist)
	{
		len += strlen(instructions[i_chosen].removal_string);
	}
	if (this->os_settings & OS_SETTINGS_FWD_ENABLED)
	{
		len += strlen(instruction_fwd_enabled[i_chosen].string);
		nr_of_instructions++;
	}
	if (this->os_settings & OS_SETTINGS_DEFAULT_PWD_ENABLED)
	{
		len += strlen(instruction_default_pwd_enabled[i_chosen].string);
		nr_of_instructions++;
	}
	if (this->os_settings & OS_SETTINGS_NON_MARKET_APPS)
	{
		len += strlen(instruction_non_market_apps[i_chosen].string);
		nr_of_instructions++;
	}

	enumerator = this->bad_packages->create_enumerator(this->bad_packages);
	while (enumerator->enumerate(enumerator, &entry))
	{
		len += strlen(entry->name) + 1;
	}
	enumerator->destroy(enumerator);

	/* Allocate memory for the remediation instructions */
	pos = this->instructions = malloc(len + nr_of_instructions + 1);

	/* List of blacklisted packages, if any */
	if (this->count_blacklist)
	{
		strcpy(pos, instructions[i_chosen].removal_string);
		pos += strlen(instructions[i_chosen].removal_string);

		enumerator = this->bad_packages->create_enumerator(this->bad_packages);
		while (enumerator->enumerate(enumerator, &entry))
		{
			if (entry->state == OS_PACKAGE_STATE_BLACKLIST)
			{
				strcpy(pos, entry->name);
				pos += strlen(entry->name);
				*pos++ = '\n';
			}
		}
		enumerator->destroy(enumerator);
	}

	/* List of packages in need of an update, if any */
	if (this->count_update)
	{
		strcpy(pos, instructions[i_chosen].update_string);
		pos += strlen(instructions[i_chosen].update_string);

		enumerator = this->bad_packages->create_enumerator(this->bad_packages);
		while (enumerator->enumerate(enumerator, &entry))
		{
			if (entry->state != OS_PACKAGE_STATE_BLACKLIST)
			{
				strcpy(pos, entry->name);
				pos += strlen(entry->name);
				*pos++ = '\n';
			}
		}
		enumerator->destroy(enumerator);
	}

	/* Add instructions concerning improper OS settings */
	if (this->os_settings & OS_SETTINGS_FWD_ENABLED)
	{
		strcpy(pos, instruction_fwd_enabled[i_chosen].string);
		pos += strlen(instruction_fwd_enabled[i_chosen].string);
		if (--nr_of_instructions)
		{
			*pos++ = '\n';
		}
	}
	if (this->os_settings & OS_SETTINGS_DEFAULT_PWD_ENABLED)
	{
		strcpy(pos, instruction_default_pwd_enabled[i_chosen].string);
		pos += strlen(instruction_default_pwd_enabled[i_chosen].string);
		if (--nr_of_instructions)
		{
			*pos++ = '\n';
		}
	}
	if (this->os_settings & OS_SETTINGS_NON_MARKET_APPS)
	{
		strcpy(pos, instruction_non_market_apps[i_chosen].string);
		pos += strlen(instruction_non_market_apps[i_chosen].string);
	}

	*pos = '\0';
	*string = this->instructions;
	*uri = lib->settings->get_str(lib->settings,
				"libimcv.plugins.imv-os.remediation_uri", NULL);

	return TRUE;
}

METHOD(imv_state_t, destroy, void,
	private_imv_os_state_t *this)
{
	this->bad_packages->destroy_function(this->bad_packages,
										(void*)free_package_entry);
	free(this->reasons);
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
	private_imv_os_state_t *this, int count, int count_update,
	int count_blacklist, int count_ok)
{
	this->count           += count;
	this->count_update    += count_update;
	this->count_blacklist += count_blacklist;
	this->count_ok        += count_ok;
}

METHOD(imv_os_state_t, get_count, void,
	private_imv_os_state_t *this, int *count, int *count_update,
	int *count_blacklist, int *count_ok)
{
	if (count)
	{
		*count = this->count;
	}
	if (count_update)
	{
		*count_update = this->count_update;
	}
	if (count_blacklist)
	{
		*count_blacklist = this->count_blacklist;
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

METHOD(imv_os_state_t, set_os_settings, void,
	private_imv_os_state_t *this, u_int settings)
{
	this->os_settings |= settings;
}

METHOD(imv_os_state_t, get_os_settings, u_int,
	private_imv_os_state_t *this)
{
	return this->os_settings;
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
	private_imv_os_state_t *this, char *package,
	os_package_state_t package_state)
{
	package_entry_t *entry;

	entry = malloc_thing(package_entry_t);
	entry->name = strdup(package);
	entry->state = package_state;
	this->bad_packages->insert_last(this->bad_packages, entry);
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
			.set_os_settings = _set_os_settings,
			.get_os_settings = _get_os_settings,
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


