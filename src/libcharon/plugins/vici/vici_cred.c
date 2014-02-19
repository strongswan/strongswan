/*
 * Copyright (C) 2014 Martin Willi
 * Copyright (C) 2014 revosec AG
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

#include "vici_cred.h"
#include "vici_builder.h"

#include <credentials/sets/mem_cred.h>
#include <credentials/certificates/ac.h>
#include <credentials/certificates/crl.h>
#include <credentials/certificates/x509.h>

typedef struct private_vici_cred_t private_vici_cred_t;

/**
 * Private data of an vici_cred_t object.
 */
struct private_vici_cred_t {

	/**
	 * Public vici_cred_t interface.
	 */
	vici_cred_t public;

	/**
	 * Dispatcher
	 */
	vici_dispatcher_t *dispatcher;

	/**
	 * credentials
	 */
	mem_cred_t *creds;
};

CALLBACK(clear_creds, vici_message_t*,
	private_vici_cred_t *this, char *name, u_int id, vici_message_t *message)
{
	vici_builder_t *builder;

	this->creds->clear(this->creds);

	builder = vici_builder_create();
	return builder->finalize(builder);
}

static void manage_command(private_vici_cred_t *this,
						   char *name, vici_command_cb_t cb, bool reg)
{
	this->dispatcher->manage_command(this->dispatcher, name,
									 reg ? cb : NULL, this);
}

/**
 * (Un-)register dispatcher functions
 */
static void manage_commands(private_vici_cred_t *this, bool reg)
{
	manage_command(this, "clear-creds", clear_creds, reg);
}

METHOD(vici_cred_t, destroy, void,
	private_vici_cred_t *this)
{
	manage_commands(this, FALSE);

	lib->credmgr->remove_set(lib->credmgr, &this->creds->set);
	this->creds->destroy(this->creds);
	free(this);
}

/**
 * See header
 */
vici_cred_t *vici_cred_create(vici_dispatcher_t *dispatcher)
{
	private_vici_cred_t *this;

	INIT(this,
		.public = {
			.destroy = _destroy,
		},
		.dispatcher = dispatcher,
		.creds = mem_cred_create(),
	);

	lib->credmgr->add_set(lib->credmgr, &this->creds->set);

	manage_commands(this, TRUE);

	return &this->public;
}
