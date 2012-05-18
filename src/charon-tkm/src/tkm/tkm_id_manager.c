/*
 * Copyright (C) 2012 Reto Buerki
 * Copyright (C) 2012 Adrian-Ken Rueegsegger
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

#include "tkm_id_manager.h"

#include <utils/debug.h>
#include <collections/linked_list.h>
#include <threading/rwlock.h>

ENUM_BEGIN(tkm_context_kind_names, TKM_CTX_NONCE, TKM_CTX_NONCE,
	"NONCE_CONTEXT");
ENUM_END(tkm_context_kind_names, TKM_CTX_NONCE);

typedef struct private_tkm_id_manager_t private_tkm_id_manager_t;

/**
 * private data of tkm_id_manager
 */
struct private_tkm_id_manager_t {

	/**
	 * public functions
	 */
	tkm_id_manager_t public;

	/**
	 * Next free context id values.
	 */
	int nextids[TKM_CTX_MAX];

	/**
	 * Per-kind list of acquired context ids
	 */
	linked_list_t *ctxids[TKM_CTX_MAX];

	/**
	 * rwlocks for context id lists
	 */
	rwlock_t *locks[TKM_CTX_MAX];

};

/**
 * Check if given kind is a valid context kind value.
 *
 * @param kind			context kind to check
 * @return				TRUE if given kind is a valid context kind,
 *						FALSE otherwise
 */
static bool is_valid_kind(const tkm_context_kind_t kind)
{
	return (int)kind >= 0 && kind < TKM_CTX_MAX;
};

METHOD(tkm_id_manager_t, acquire_id, int,
	private_tkm_id_manager_t * const this, const tkm_context_kind_t kind)
{
	int *current;
	int id = 0;

	if (!is_valid_kind(kind))
	{
		DBG1(DBG_LIB, "tried to acquire id for invalid context kind '%d'",
					  kind);
		return 0;
	}

	this->locks[kind]->write_lock(this->locks[kind]);

	id = this->nextids[kind];
	current = malloc(sizeof(int));
	*current = id;
	this->ctxids[kind]->insert_last(this->ctxids[kind], current);
	this->nextids[kind]++;

	this->locks[kind]->unlock(this->locks[kind]);

	if (!id)
	{
		DBG1(DBG_LIB, "acquiring %N context id failed",
					  tkm_context_kind_names, kind);
	}

	return id;
}

METHOD(tkm_id_manager_t, release_id, bool,
	private_tkm_id_manager_t * const this, const tkm_context_kind_t kind,
	const int id)
{
	enumerator_t *enumerator;
	int *current;
	bool found = FALSE;

	if (!is_valid_kind(kind))
	{
		DBG1(DBG_LIB, "tried to release id %d for invalid context kind '%d'",
					  id, kind);
		return FALSE;
	}

	this->locks[kind]->write_lock(this->locks[kind]);
	enumerator = this->ctxids[kind]->create_enumerator(this->ctxids[kind]);
	while (enumerator->enumerate(enumerator, &current))
	{
		if (*current == id)
		{
			this->ctxids[kind]->remove_at(this->ctxids[kind], enumerator);
			found = TRUE;
			break;
		}
	}
	enumerator->destroy(enumerator);
	this->locks[kind]->unlock(this->locks[kind]);

	if (!found)
	{
		DBG3(DBG_LIB, "releasing non-existent %N context id %d, nothing to do",
					  tkm_context_kind_names, kind, id);
	}

	return TRUE;
}


METHOD(tkm_id_manager_t, destroy, void,
	private_tkm_id_manager_t *this)
{
	int i;

	for (i = 0; i < TKM_CTX_MAX; i++)
	{
		this->ctxids[i]->destroy(this->ctxids[i]);
		this->locks[i]->destroy(this->locks[i]);
	}
	free(this);
}

/*
 * see header file
 */
tkm_id_manager_t *tkm_id_manager_create()
{
	private_tkm_id_manager_t *this;
	int i;

	INIT(this,
		.public = {
			.acquire_id = _acquire_id,
			.release_id = _release_id,
			.destroy = _destroy,
		},
	);

	for (i = 0; i < TKM_CTX_MAX; i++)
	{
		this->nextids[i] = 1;
		this->ctxids[i] = linked_list_create();
		this->locks[i] = rwlock_create(RWLOCK_TYPE_DEFAULT);
	}

	return &this->public;
}
