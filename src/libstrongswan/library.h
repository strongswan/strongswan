/*
 * Copyright (C) 2008 Martin Willi
 * Hochschule fuer Technik Rapperswil
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

/**
 * @defgroup libstrongswan libstrongswan
 *
 * @defgroup asn1 asn1
 * @ingroup libstrongswan
 *
 * @defgroup credentials credentials
 * @ingroup libstrongswan
 *
 * @defgroup keys keys
 * @ingroup credentials
 *
 * @defgroup certificates certificates
 * @ingroup credentials
 *
 * @defgroup crypto crypto
 * @ingroup libstrongswan
 *
 * @defgroup database database
 * @ingroup libstrongswan
 *
 * @defgroup fetcher fetcher
 * @ingroup libstrongswan
 *
 * @defgroup plugins plugins
 * @ingroup libstrongswan
 *
 * @defgroup utils utils
 * @ingroup libstrongswan
 */

/**
 * @defgroup library library
 * @{ @ingroup libstrongswan
 */

#ifndef LIBRARY_H_
#define LIBRARY_H_

#include <printf_hook.h>
#include <utils.h>
#include <chunk.h>
#include <settings.h>
#include <integrity_checker.h>
#include <plugins/plugin_loader.h>
#include <crypto/crypto_factory.h>
#include <fetcher/fetcher_manager.h>
#include <database/database_factory.h>
#include <credentials/credential_factory.h>
#include <credentials/keys/key_encoding.h>

typedef struct library_t library_t;

/**
 * Libstrongswan library context, contains library relevant globals.
 */
struct library_t {

	/**
	 * Printf hook registering facility
	 */
	printf_hook_t *printf_hook;
	
	/**
	 * crypto algorithm registry and factory
	 */
	crypto_factory_t *crypto;
	
	/**
	 * credential constructor registry and factory
	 */
	credential_factory_t *creds;
	
	/**
	 * key encoding registry and factory
	 */
	key_encoding_t *encoding;
	
	/**
	 * URL fetching facility
	 */
	fetcher_manager_t *fetcher;
	
	/**
	 * database construction factory
	 */
	database_factory_t *db;
	
	/**
	 * plugin loading facility
	 */
	plugin_loader_t *plugins;
	
	/**
	 * various settings loaded from settings file
	 */
	settings_t *settings;
	
	/**
	 * integrity checker to verify code integrity
	 */
	integrity_checker_t *integrity;
	
	/**
	 * is leak detective running?
	 */
	bool leak_detective;
};

/**
 * Initialize library, creates "lib" instance.
 *
 * @param settings		file to read settings from, may be NULL for none
 * @return				FALSE if integrity check failed
 */
bool library_init(char *settings);

/**
 * Deinitialize library, destroys "lib" instance.
 */
void library_deinit();

/**
 * Library instance, set after between library_init() and library_deinit() calls.
 */
extern library_t *lib;

#endif /** LIBRARY_H_ @}*/
