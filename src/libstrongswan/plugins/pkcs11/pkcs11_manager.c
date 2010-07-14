/*
 * Copyright (C) 2010 Martin Willi
 * Copyright (C) 2010 revosec AG
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

#include "pkcs11_manager.h"

#include <debug.h>
#include <utils/linked_list.h>
#include <threading/thread.h>

#include "pkcs11_library.h"

#include <daemon.h>
#include <processing/jobs/callback_job.h>

typedef struct private_pkcs11_manager_t private_pkcs11_manager_t;

/**
 * Private data of an pkcs11_manager_t object.
 */
struct private_pkcs11_manager_t {

	/**
	 * Public pkcs11_manager_t interface.
	 */
	pkcs11_manager_t public;

	/**
	 * List of loaded libraries, as lib_entry_t
	 */
	linked_list_t *libs;

	/**
	 * Slot event callback function
	 */
	pkcs11_manager_token_event_t cb;

	/**
	 * Slot event user data
	 */
	void *data;
};

/**
 * Entry for a loaded library
 */
typedef struct {
	/* back reference to this */
	private_pkcs11_manager_t *this;
	/* friendly name */
	char *name;
	/* associated library path */
	char *path;
	/* loaded library */
	pkcs11_library_t *lib;
	/* event dispatcher job */
	callback_job_t *job;
} lib_entry_t;

/**
 * Destroy a lib_entry_t
 */
static void lib_entry_destroy(lib_entry_t *entry)
{
	if (entry->job)
	{
		entry->job->cancel(entry->job);
	}
	entry->lib->destroy(entry->lib);
	free(entry);
}

/**
 * Print supported mechanisms of a token in a slot
 */
static void print_mechs(lib_entry_t *entry, CK_SLOT_ID slot)
{
	CK_MECHANISM_TYPE_PTR mechs;
	CK_MECHANISM_INFO info;
	CK_ULONG count;
	CK_RV rv;
	int i;

	rv = entry->lib->f->C_GetMechanismList(slot, NULL, &count);
	if (rv != CKR_OK)
	{
		DBG1(DBG_CFG, "C_GetMechanismList() failed: %N", ck_rv_names, rv);
		return;
	}
	mechs = malloc(sizeof(CK_MECHANISM_TYPE) * count);
	entry->lib->f->C_GetMechanismList(slot, mechs, &count);
	if (rv != CKR_OK)
	{
		DBG1(DBG_CFG, "C_GetMechanismList() failed: %N", ck_rv_names, rv);
		return;
	}
	for (i = 0; i < count; i++)
	{
		rv = entry->lib->f->C_GetMechanismInfo(slot, mechs[i], &info);
		if (rv == CKR_OK)
		{
			DBG2(DBG_CFG, "      %N %lu-%lu [ %s%s%s%s%s%s%s%s%s%s%s%s%s]",
				ck_mech_names, mechs[i],
				info.ulMinKeySize, info.ulMaxKeySize,
				info.flags & CKF_HW ? "HW " : "",
				info.flags & CKF_ENCRYPT ? "ENCR " : "",
				info.flags & CKF_DECRYPT ? "DECR " : "",
				info.flags & CKF_DIGEST ? "DGST " : "",
				info.flags & CKF_SIGN ? "SIGN " : "",
				info.flags & CKF_SIGN_RECOVER ? "SIGN_RCVR " : "",
				info.flags & CKF_VERIFY ? "VRFY " : "",
				info.flags & CKF_VERIFY_RECOVER ? "VRFY_RCVR " : "",
				info.flags & CKF_GENERATE ? "GEN " : "",
				info.flags & CKF_GENERATE_KEY_PAIR ? "GEN_KEY_PAIR " : "",
				info.flags & CKF_WRAP ? "WRAP " : "",
				info.flags & CKF_UNWRAP ? "UNWRAP " : "",
				info.flags & CKF_DERIVE ? "DERIVE " : "");
		}
		else
		{
			DBG1(DBG_CFG, "C_GetMechanismList(%N) failed: %N",
				 ck_mech_names, mechs[i], ck_rv_names, rv);
		}
	}
	free(mechs);
}

/**
 * Handle a token
 */
static void handle_token(lib_entry_t *entry, CK_SLOT_ID slot)
{
	CK_TOKEN_INFO info;
	CK_RV rv;

	rv = entry->lib->f->C_GetTokenInfo(slot, &info);
	if (rv != CKR_OK)
	{
		DBG1(DBG_CFG, "C_GetTokenInfo failed: %N", ck_rv_names, rv);
		return;
	}
	pkcs11_library_trim(info.label, sizeof(info.label));
	pkcs11_library_trim(info.manufacturerID, sizeof(info.manufacturerID));
	pkcs11_library_trim(info.model, sizeof(info.model));
	DBG1(DBG_CFG, "    %s (%s: %s)",
		 info.label, info.manufacturerID, info.model);

	print_mechs(entry, slot);
}

/**
 * Handle slot changes
 */
static void handle_slot(lib_entry_t *entry, CK_SLOT_ID slot)
{
	CK_SLOT_INFO info;
	CK_RV rv;

	rv = entry->lib->f->C_GetSlotInfo(slot, &info);
	if (rv != CKR_OK)
	{
		DBG1(DBG_CFG, "C_GetSlotInfo failed: %N", ck_rv_names, rv);
		return;
	}

	pkcs11_library_trim(info.slotDescription, sizeof(info.slotDescription));
	if (info.flags & CKF_TOKEN_PRESENT)
	{
		DBG1(DBG_CFG, "  found token in slot '%s':%lu (%s)",
			 entry->name, slot, info.slotDescription);
		handle_token(entry, slot);
		entry->this->cb(entry->this->data, entry->lib, slot, TRUE);
	}
	else
	{
		DBG1(DBG_CFG, "token removed from slot '%s':%lu (%s)",
			 entry->name, slot, info.slotDescription);
		entry->this->cb(entry->this->data, entry->lib, slot, FALSE);
	}
}

/**
 * Dispatch slot events
 */
static job_requeue_t dispatch_slot_events(lib_entry_t *entry)
{
	CK_SLOT_ID slot;
	CK_RV rv;
	bool old;

	old = thread_cancelability(TRUE);
	rv = entry->lib->f->C_WaitForSlotEvent(0, &slot, NULL);
	thread_cancelability(old);
	if (rv == CKR_NO_EVENT)
	{
		DBG1(DBG_CFG, "module '%s' does not support hot-plugging, cancelled",
			 entry->name);
		return JOB_REQUEUE_NONE;
	}
	if (rv == CKR_CRYPTOKI_NOT_INITIALIZED)
	{	/* C_Finalize called, abort */
		return JOB_REQUEUE_NONE;
	}
	if (rv != CKR_OK)
	{
		DBG1(DBG_CFG, "error in C_WaitForSlotEvent: %N", ck_rv_names, rv);
	}
	handle_slot(entry, slot);

	return JOB_REQUEUE_DIRECT;
}

/**
 * End dispatching, unset job
 */
static void end_dispatch(lib_entry_t *entry)
{
	entry->job = NULL;
}

/**
 * Query the slots for tokens
 */
static void query_slots(lib_entry_t *entry)
{
	CK_ULONG token_count;
	CK_SLOT_ID_PTR slots;
	int i;

	if (entry->lib->f->C_GetSlotList(TRUE, NULL, &token_count) == CKR_OK)
	{
		slots = malloc(sizeof(CK_SLOT_ID) * token_count);
		if (entry->lib->f->C_GetSlotList(TRUE, slots, &token_count) == CKR_OK)
		{
			for (i = 0; i < token_count; i++)
			{
				handle_slot(entry, slots[i]);
			}
		}
		free(slots);
	}
}

METHOD(pkcs11_manager_t, destroy, void,
	private_pkcs11_manager_t *this)
{
	this->libs->destroy_function(this->libs, (void*)lib_entry_destroy);
	free(this);
}

/**
 * See header
 */
pkcs11_manager_t *pkcs11_manager_create(pkcs11_manager_token_event_t cb,
										void *data)
{
	private_pkcs11_manager_t *this;
	enumerator_t *enumerator;
	lib_entry_t *entry;
	char *module;

	INIT(this,
		.public = {
			.destroy = _destroy,
		},
		.libs = linked_list_create(),
		.cb = cb,
		.data = data,
	);

	enumerator = lib->settings->create_section_enumerator(lib->settings,
										"libstrongswan.plugins.pkcs11.modules");
	while (enumerator->enumerate(enumerator, &module))
	{
		INIT(entry,
			.this = this,
			.name = module,
		);

		entry->path = lib->settings->get_str(lib->settings,
				"libstrongswan.plugins.pkcs11.modules.%s.path", NULL, module);
		if (!entry->path)
		{
			DBG1(DBG_CFG, "PKCS11 module '%s' misses library path", module);
			free(entry);
			continue;
		}
		entry->lib = pkcs11_library_create(module, entry->path);
		if (!entry->lib)
		{
			free(entry);
			continue;
		}

		query_slots(entry);
		this->libs->insert_last(this->libs, entry);
		entry->job = callback_job_create((void*)dispatch_slot_events,
										 entry, (void*)end_dispatch, NULL);
		charon->processor->queue_job(charon->processor, (job_t*)entry->job);
	}
	enumerator->destroy(enumerator);
	return &this->public;
}
