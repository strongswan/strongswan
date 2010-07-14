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

typedef struct private_pkcs11_library_t private_pkcs11_library_t;

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
};

METHOD(pkcs11_library_t, destroy, void,
	private_pkcs11_library_t *this)
{
	this->public.f->C_Finalize(NULL);
	dlclose(this->handle);
	free(this);
}

/**
 * Trim a string
 */
static void trim(char *str, int len)
{
	int i;

	for (i = len - 1; i > 0; i--)
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
 * Initialize a PKCS#11 library
 */
static bool initialize(private_pkcs11_library_t *this, char *name, char *file)
{
	CK_C_GetFunctionList pC_GetFunctionList;
	CK_INFO info;
	CK_RV rv;

	pC_GetFunctionList = dlsym(this->handle, "C_GetFunctionList");
	if (!pC_GetFunctionList)
	{
		DBG1(DBG_CFG, "C_GetFunctionList not found for '%s': %s", name, dlerror());
		return FALSE;
	}
	rv = pC_GetFunctionList(&this->public.f);
	if (rv != CKR_OK)
	{
		DBG1(DBG_CFG, "C_GetFunctionList() error for '%s': %d", name, rv);
		return FALSE;
	}

	rv = this->public.f->C_Initialize(NULL);
	if (rv != CKR_OK)
	{
		DBG1(DBG_CFG, "C_Initialize() error for '%s': %d", name, rv);
		return FALSE;
	}
	rv = this->public.f->C_GetInfo(&info);
	if (rv != CKR_OK)
	{
		DBG1(DBG_CFG, "C_GetInfo() error for '%s': %d", name, rv);
		this->public.f->C_Finalize(NULL);
		return FALSE;
	}

	trim(info.manufacturerID,
		 strnlen(info.manufacturerID, sizeof(info.manufacturerID)));
	trim(info.libraryDescription,
		 strnlen(info.libraryDescription, sizeof(info.libraryDescription)));

	DBG1(DBG_CFG, "loaded PKCS#11 v%d.%d library '%s' (%s)",
		 info.cryptokiVersion.major, info.cryptokiVersion.minor, name, file);
	DBG1(DBG_CFG, "  %.*s: %.*s v%d.%d",
		 sizeof(info.manufacturerID), info.manufacturerID,
		 sizeof(info.libraryDescription), info.libraryDescription,
		 info.libraryVersion.major, info.libraryVersion.minor);
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
			.destroy = _destroy,
		},
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
