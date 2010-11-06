/*
 * Copyright (C) 2006 Mike McCauley
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

#include "tnc_imc_manager.h"

#include <tnc/imc/imc_manager.h>
#include <tnc/tncifimc.h>

#include <debug.h>
#include <library.h>
#include <utils/linked_list.h>

typedef struct private_tnc_imc_manager_t private_tnc_imc_manager_t;

struct private_tnc_imc_manager_t {

	/**
	 * Public members of imc_manager_t.
	 */
	imc_manager_t public;

	/**
	 * Linked list of IMCs
	 */
	linked_list_t *imcs;

	/**
	 * Next IMC ID to be assigned
	 */
	TNC_IMCID next_imc_id;
};

METHOD(imc_manager_t, add, bool,
	private_tnc_imc_manager_t *this, imc_t *imc)
{
	TNC_Version version;

	/* Initialize the module */
	imc->set_id(imc, this->next_imc_id);
	if (imc->initialize(imc->get_id(imc), TNC_IFIMC_VERSION_1,
			TNC_IFIMC_VERSION_1, &version) != TNC_RESULT_SUCCESS)
	{
		DBG1(DBG_TNC, "could not initialize IMC '%s'",
					   imc->get_name(imc));
		return FALSE;
	}
    if (imc->provide_bind_function(imc->get_id(imc), TNC_TNCC_BindFunction)
			!= TNC_RESULT_SUCCESS)
	{
		DBG1(DBG_TNC, "could not provide bind function for IMC '%s'",
					   imc->get_name(imc));
		return FALSE;
	}
	this->imcs->insert_last(this->imcs, imc);
	this->next_imc_id++;

	return TRUE;
}

METHOD(imc_manager_t, notify_connection_change, void,
	private_tnc_imc_manager_t *this, TNC_ConnectionID id,
	TNC_ConnectionState state)
{
	enumerator_t *enumerator;
	imc_t *imc;

	enumerator = this->imcs->create_enumerator(this->imcs);
	while (enumerator->enumerate(enumerator, &imc))
	{
		if (imc->notify_connection_change)
		{
			imc->notify_connection_change(imc->get_id(imc), id, state);
		}
	}
	enumerator->destroy(enumerator);
}

METHOD(imc_manager_t, begin_handshake, void,
	private_tnc_imc_manager_t *this, TNC_ConnectionID id)
{
	enumerator_t *enumerator;
	imc_t *imc;

	enumerator = this->imcs->create_enumerator(this->imcs);
	while (enumerator->enumerate(enumerator, &imc))
	{
		imc->begin_handshake(imc->get_id(imc), id);
	}
	enumerator->destroy(enumerator);
}

METHOD(imc_manager_t, set_message_types, TNC_Result,
	private_tnc_imc_manager_t *this, TNC_IMCID id,
									 TNC_MessageTypeList supported_types,
									 TNC_UInt32 type_count)
{
	enumerator_t *enumerator;
	imc_t *imc;
	TNC_Result result = TNC_RESULT_FATAL;

	enumerator = this->imcs->create_enumerator(this->imcs);
	while (enumerator->enumerate(enumerator, &imc))
	{
		if (id == imc->get_id(imc))
		{
			imc->set_message_types(imc, supported_types, type_count);
			result = TNC_RESULT_SUCCESS;
			break;
		}
	}
	enumerator->destroy(enumerator);
	return result;
}


METHOD(imc_manager_t, destroy, void,
	private_tnc_imc_manager_t *this)
{
	imc_t *imc;

	while (this->imcs->remove_last(this->imcs, (void**)&imc) == SUCCESS)
	{
		if (imc->terminate &&
			imc->terminate(imc->get_id(imc)) != TNC_RESULT_SUCCESS)
		{
			DBG1(DBG_TNC, "IMC '%s' not terminated successfully",
						   imc->get_name(imc));
		}
		imc->destroy(imc);
	}
	this->imcs->destroy(this->imcs);
	free(this);
}

/**
 * Described in header.
 */
imc_manager_t* tnc_imc_manager_create(void)
{
	private_tnc_imc_manager_t *this;

	INIT(this,
		.public = {
			.add = _add,
			.notify_connection_change = _notify_connection_change,
			.begin_handshake = _begin_handshake,
			.set_message_types = _set_message_types,
			.destroy = _destroy,
        },
		.imcs = linked_list_create(),
		.next_imc_id = 1,
	);


	return &this->public;
}


