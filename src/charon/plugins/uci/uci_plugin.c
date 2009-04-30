/*
 * Copyright (C) 2008 Thomas Kallenberg
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

#include "uci_plugin.h"
#include "uci_config.h"
#include "uci_creds.h"
#include "uci_control.h"

#include <daemon.h>

/**
 * UCI package name to use for lookups
 */
#define UCI_PACKAGE "strongswan"

typedef struct private_uci_plugin_t private_uci_plugin_t;

/**
 * private data of uci plugin
 */
struct private_uci_plugin_t {

	/**
	 * implements plugin interface
	 */
	uci_plugin_t public;
	
	/**
	 * UCI configuration backend
	 */
	uci_config_t *config;
	
	/**
	 * UCI credential set implementation
	 */
	uci_creds_t *creds;
	
	/**
	 * UCI parser wrapper
	 */
	uci_parser_t *parser;

	/**
	 * UCI control interface
	 */
	uci_control_t *control;
};

/**
 * Implementation of plugin_t.destroy
 */
static void destroy(private_uci_plugin_t *this)
{
	charon->backends->remove_backend(charon->backends, &this->config->backend);
	charon->credentials->remove_set(charon->credentials, &this->creds->credential_set);
	this->config->destroy(this->config);
	this->creds->destroy(this->creds);
	this->parser->destroy(this->parser);
	this->control->destroy(this->control);
	free(this);
}

/*
 * see header file
 */
plugin_t *plugin_create()
{
	private_uci_plugin_t *this = malloc_thing(private_uci_plugin_t);
	
	this->public.plugin.destroy = (void(*)(plugin_t*))destroy;
	
	this->parser = uci_parser_create(UCI_PACKAGE);
	this->config = uci_config_create(this->parser);
	this->creds = uci_creds_create(this->parser);
	this->control = uci_control_create();
	charon->backends->add_backend(charon->backends, &this->config->backend);
	charon->credentials->add_set(charon->credentials, &this->creds->credential_set);
	
	return &this->public.plugin;
}

