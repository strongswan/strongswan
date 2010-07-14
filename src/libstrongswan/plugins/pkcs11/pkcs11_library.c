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

#include "pkcs11_library.h"

#include <dlfcn.h>

#include <library.h>
#include <debug.h>
#include <threading/mutex.h>

typedef struct private_pkcs11_library_t private_pkcs11_library_t;


ENUM_BEGIN(ck_rv_names, CKR_OK, CKR_CANT_LOCK,
	"OK",
	"CANCEL",
	"HOST_MEMORY",
	"SLOT_ID_INVALID",
	"(0x04)",
	"GENERAL_ERROR",
	"FUNCTION_FAILED",
	"ARGUMENTS_BAD",
	"NO_EVENT",
	"NEED_TO_CREATE_THREADS",
	"CANT_LOCK");
ENUM_NEXT(ck_rv_names, CKR_ATTRIBUTE_READ_ONLY, CKR_ATTRIBUTE_VALUE_INVALID,
		CKR_CANT_LOCK,
	"ATTRIBUTE_READ_ONLY",
	"ATTRIBUTE_SENSITIVE",
	"ATTRIBUTE_TYPE_INVALID",
	"ATTRIBUTE_VALUE_INVALID");
ENUM_NEXT(ck_rv_names, CKR_DATA_INVALID, CKR_DATA_LEN_RANGE,
		CKR_ATTRIBUTE_VALUE_INVALID,
	"DATA_INVALID"
	"DATA_LEN_RANGE");
ENUM_NEXT(ck_rv_names, CKR_DEVICE_ERROR, CKR_DEVICE_REMOVED,
		CKR_DATA_LEN_RANGE,
	"DEVICE_ERROR",
	"DEVICE_MEMORY",
	"DEVICE_REMOVED");
ENUM_NEXT(ck_rv_names, CKR_ENCRYPTED_DATA_INVALID, CKR_ENCRYPTED_DATA_LEN_RANGE,
		CKR_DEVICE_REMOVED,
	"ENCRYPTED_DATA_INVALID",
	"ENCRYPTED_DATA_LEN_RANGE");
ENUM_NEXT(ck_rv_names, CKR_FUNCTION_CANCELED, CKR_FUNCTION_NOT_SUPPORTED,
		CKR_ENCRYPTED_DATA_LEN_RANGE,
	"FUNCTION_CANCELED",
	"FUNCTION_NOT_PARALLEL",
	"(0x52)",
	"(0x53)",
	"FUNCTION_NOT_SUPPORTED");
ENUM_NEXT(ck_rv_names, CKR_KEY_HANDLE_INVALID, CKR_KEY_UNEXTRACTABLE,
		CKR_FUNCTION_NOT_SUPPORTED,
	"KEY_HANDLE_INVALID",
	"(0x61)",
	"KEY_SIZE_RANGE",
	"KEY_TYPE_INCONSISTENT",
	"KEY_NOT_NEEDED",
	"KEY_CHANGED",
	"KEY_NEEDED",
	"KEY_INDIGESTIBLE",
	"KEY_FUNCTION_NOT_PERMITTED",
	"KEY_NOT_WRAPPABLE",
	"KEY_UNEXTRACTABLE");
ENUM_NEXT(ck_rv_names, CKR_MECHANISM_INVALID, CKR_MECHANISM_PARAM_INVALID,
		CKR_KEY_UNEXTRACTABLE,
	"MECHANISM_INVALID",
	"MECHANISM_PARAM_INVALID");
ENUM_NEXT(ck_rv_names, CKR_OBJECT_HANDLE_INVALID, CKR_OBJECT_HANDLE_INVALID,
		CKR_MECHANISM_PARAM_INVALID,
	"OBJECT_HANDLE_INVALID");
ENUM_NEXT(ck_rv_names, CKR_OPERATION_ACTIVE, CKR_OPERATION_NOT_INITIALIZED,
		CKR_OBJECT_HANDLE_INVALID,
	"OPERATION_ACTIVE",
	"OPERATION_NOT_INITIALIZED");
ENUM_NEXT(ck_rv_names, CKR_PIN_INCORRECT, CKR_PIN_LOCKED,
		CKR_OPERATION_NOT_INITIALIZED,
	"PIN_INCORRECT",
	"PIN_INVALID",
	"PIN_LEN_RANGE",
	"PIN_EXPIRED",
	"PIN_LOCKED");
ENUM_NEXT(ck_rv_names, CKR_SESSION_CLOSED, CKR_SESSION_READ_WRITE_SO_EXISTS,
		CKR_PIN_LOCKED,
	"SESSION_CLOSED",
	"SESSION_COUNT",
	"(0xb2)",
	"SESSION_HANDLE_INVALID",
	"SESSION_PARALLEL_NOT_SUPPORTED",
	"SESSION_READ_ONLY",
	"SESSION_EXISTS",
	"SESSION_READ_ONLY_EXISTS",
	"SESSION_READ_WRITE_SO_EXISTS");
ENUM_NEXT(ck_rv_names, CKR_SIGNATURE_INVALID, CKR_SIGNATURE_LEN_RANGE,
		CKR_SESSION_READ_WRITE_SO_EXISTS,
	"SIGNATURE_INVALID",
	"SIGNATURE_LEN_RANGE");
ENUM_NEXT(ck_rv_names, CKR_TEMPLATE_INCOMPLETE, CKR_TEMPLATE_INCONSISTENT,
		CKR_SIGNATURE_LEN_RANGE,
	"TEMPLATE_INCOMPLETE",
	"TEMPLATE_INCONSISTENT",
);
ENUM_NEXT(ck_rv_names, CKR_TOKEN_NOT_PRESENT, CKR_TOKEN_WRITE_PROTECTED,
		CKR_TEMPLATE_INCONSISTENT,
	"TOKEN_NOT_PRESENT",
	"TOKEN_NOT_RECOGNIZED",
	"TOKEN_WRITE_PROTECTED");
ENUM_NEXT(ck_rv_names, CKR_UNWRAPPING_KEY_HANDLE_INVALID, CKR_UNWRAPPING_KEY_TYPE_INCONSISTENT,
		CKR_TOKEN_WRITE_PROTECTED,
	"UNWRAPPING_KEY_HANDLE_INVALID",
	"UNWRAPPING_KEY_SIZE_RANGE",
	"UNWRAPPING_KEY_TYPE_INCONSISTENT");
ENUM_NEXT(ck_rv_names, CKR_USER_ALREADY_LOGGED_IN, CKR_USER_TOO_MANY_TYPES,
		CKR_UNWRAPPING_KEY_TYPE_INCONSISTENT,
	"USER_ALREADY_LOGGED_IN",
	"USER_NOT_LOGGED_IN",
	"USER_PIN_NOT_INITIALIZED",
	"USER_TYPE_INVALID",
	"USER_ANOTHER_ALREADY_LOGGED_IN",
	"USER_TOO_MANY_TYPES");
ENUM_NEXT(ck_rv_names, CKR_WRAPPED_KEY_INVALID, CKR_WRAPPING_KEY_TYPE_INCONSISTENT,
		CKR_USER_TOO_MANY_TYPES,
	"WRAPPED_KEY_INVALID",
	"(0x111)",
	"WRAPPED_KEY_LEN_RANGE",
	"WRAPPING_KEY_HANDLE_INVALID",
	"WRAPPING_KEY_SIZE_RANGE",
	"WRAPPING_KEY_TYPE_INCONSISTENT");
ENUM_NEXT(ck_rv_names, CKR_RANDOM_SEED_NOT_SUPPORTED, CKR_RANDOM_NO_RNG,
		CKR_WRAPPING_KEY_TYPE_INCONSISTENT,
	"RANDOM_SEED_NOT_SUPPORTED",
	"RANDOM_NO_RNG");
ENUM_NEXT(ck_rv_names, CKR_DOMAIN_PARAMS_INVALID, CKR_DOMAIN_PARAMS_INVALID,
		CKR_RANDOM_NO_RNG,
	"DOMAIN_PARAMS_INVALID");
ENUM_NEXT(ck_rv_names, CKR_BUFFER_TOO_SMALL, CKR_BUFFER_TOO_SMALL,
		CKR_DOMAIN_PARAMS_INVALID,
	"BUFFER_TOO_SMALL");
ENUM_NEXT(ck_rv_names, CKR_SAVED_STATE_INVALID, CKR_SAVED_STATE_INVALID,
		CKR_BUFFER_TOO_SMALL,
	"SAVED_STATE_INVALID");
ENUM_NEXT(ck_rv_names, CKR_INFORMATION_SENSITIVE, CKR_INFORMATION_SENSITIVE,
		CKR_SAVED_STATE_INVALID,
	"INFORMATION_SENSITIVE");
ENUM_NEXT(ck_rv_names, CKR_STATE_UNSAVEABLE, CKR_STATE_UNSAVEABLE,
		CKR_INFORMATION_SENSITIVE,
	"STATE_UNSAVEABLE");
ENUM_NEXT(ck_rv_names, CKR_CRYPTOKI_NOT_INITIALIZED, CKR_CRYPTOKI_ALREADY_INITIALIZED,
		CKR_STATE_UNSAVEABLE,
	"CRYPTOKI_NOT_INITIALIZED",
	"CRYPTOKI_ALREADY_INITIALIZED");
ENUM_NEXT(ck_rv_names, CKR_MUTEX_BAD, CKR_MUTEX_NOT_LOCKED,
		CKR_CRYPTOKI_ALREADY_INITIALIZED,
	"MUTEX_BAD",
	"MUTEX_NOT_LOCKED");
ENUM_NEXT(ck_rv_names, CKR_FUNCTION_REJECTED, CKR_FUNCTION_REJECTED,
		CKR_MUTEX_NOT_LOCKED,
	"FUNCTION_REJECTED");
ENUM_END(ck_rv_names, CKR_FUNCTION_REJECTED);


/**
 * Private data of an pkcs11_library_t object.
 */
struct private_pkcs11_library_t {

	/**
	 * Public pkcs11_library_t interface.
	 */
	pkcs11_library_t public;

	/**
	 * dlopen() handle
	 */
	void *handle;

	/**
	 * Name as passed to the constructor
	 */
	char *name;
};

METHOD(pkcs11_library_t, get_name, char*,
	private_pkcs11_library_t *this)
{
	return this->name;
}

METHOD(pkcs11_library_t, destroy, void,
	private_pkcs11_library_t *this)
{
	this->public.f->C_Finalize(NULL);
	dlclose(this->handle);
	free(this);
}

/**
 * See header
 */
void pkcs11_library_trim(char *str, int len)
{
	int i;

	str[len - 1] = '\0';
	for (i = len - 2; i > 0; i--)
	{
		if (str[i] == ' ')
		{
			str[i] = '\0';
			continue;
		}
		break;
	}
}

/**
 * Mutex creation callback
 */
static CK_RV CreateMutex(CK_VOID_PTR_PTR data)
{
	*data = mutex_create(MUTEX_TYPE_DEFAULT);
	return CKR_OK;
}

/**
 * Mutex destruction callback
 */
static CK_RV DestroyMutex(CK_VOID_PTR data)
{
	mutex_t *mutex = (mutex_t*)data;

	mutex->destroy(mutex);
	return CKR_OK;
}

/**
 * Mutex lock callback
 */
static CK_RV LockMutex(CK_VOID_PTR data)
{
	mutex_t *mutex = (mutex_t*)data;

	mutex->lock(mutex);
	return CKR_OK;
}

/**
 * Mutex unlock callback
 */
static CK_RV UnlockMutex(CK_VOID_PTR data)
{
	mutex_t *mutex = (mutex_t*)data;

	mutex->unlock(mutex);
	return CKR_OK;
}

/**
 * Initialize a PKCS#11 library
 */
static bool initialize(private_pkcs11_library_t *this, char *name, char *file)
{
	CK_C_GetFunctionList pC_GetFunctionList;
	CK_INFO info;
	CK_RV rv;
	CK_C_INITIALIZE_ARGS args = {
		.CreateMutex = CreateMutex,
		.DestroyMutex = DestroyMutex,
		.LockMutex = LockMutex,
		.UnlockMutex = UnlockMutex,
	};

	pC_GetFunctionList = dlsym(this->handle, "C_GetFunctionList");
	if (!pC_GetFunctionList)
	{
		DBG1(DBG_CFG, "C_GetFunctionList not found for '%s': %s", name, dlerror());
		return FALSE;
	}
	rv = pC_GetFunctionList(&this->public.f);
	if (rv != CKR_OK)
	{
		DBG1(DBG_CFG, "C_GetFunctionList() error for '%s': %N",
			 name, ck_rv_names, rv);
		return FALSE;
	}

	rv = this->public.f->C_Initialize(&args);
	if (rv == CKR_CANT_LOCK)
	{	/* try OS locking */
		memset(&args, 0, sizeof(args));
		args.flags = CKF_OS_LOCKING_OK;
		rv = this->public.f->C_Initialize(&args);
	}
	if (rv != CKR_OK)
	{
		DBG1(DBG_CFG, "C_Initialize() error for '%s': %N",
			 name, ck_rv_names, rv);
		return FALSE;
	}
	rv = this->public.f->C_GetInfo(&info);
	if (rv != CKR_OK)
	{
		DBG1(DBG_CFG, "C_GetInfo() error for '%s': %N",
			 name, ck_rv_names, rv);
		this->public.f->C_Finalize(NULL);
		return FALSE;
	}

	pkcs11_library_trim(info.manufacturerID,
			strnlen(info.manufacturerID, sizeof(info.manufacturerID)));
	pkcs11_library_trim(info.libraryDescription,
			strnlen(info.libraryDescription, sizeof(info.libraryDescription)));

	DBG1(DBG_CFG, "loaded PKCS#11 v%d.%d library '%s' (%s)",
		 info.cryptokiVersion.major, info.cryptokiVersion.minor, name, file);
	DBG1(DBG_CFG, "  %s: %s v%d.%d",
		 info.manufacturerID, info.libraryDescription,
		 info.libraryVersion.major, info.libraryVersion.minor);
	if (args.flags & CKF_OS_LOCKING_OK)
	{
		DBG1(DBG_CFG, "  uses OS locking functions");
	}
	return TRUE;
}

/**
 * See header
 */
pkcs11_library_t *pkcs11_library_create(char *name, char *file)
{
	private_pkcs11_library_t *this;

	INIT(this,
		.public = {
			.get_name = _get_name,
			.destroy = _destroy,
		},
		.name = name,
		.handle = dlopen(file, RTLD_LAZY),
	);

	if (!this->handle)
	{
		DBG1(DBG_CFG, "opening PKCS#11 library failed: %s", dlerror());
		free(this);
		return NULL;
	}

	if (!initialize(this, name, file))
	{
		dlclose(this->handle);
		free(this);
		return NULL;
	}

	return &this->public;
}
