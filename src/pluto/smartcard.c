/* Support of smartcards and cryptotokens
 * Copyright (C) 2003 Christoph Gysin, Simon Zwahlen
 * Copyright (C) 2004 David Buechi, Michael Meier
 * Zuercher Hochschule Winterthur, Switzerland
 *
 * Copyright (C) 2005 Michael Joosten
 *
 * Copyright (C) 2005 Andreas Steffen
 * Hochschule für Technik Rapperswil, Switzerland
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
 *
 * RCSID $Id$
 */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <time.h>
#include <dlfcn.h>

#include <freeswan.h>
#include <ipsec_policy.h>

#include "constants.h"

#ifdef SMARTCARD
#include "rsaref/unix.h"
#include "rsaref/pkcs11.h"
#endif

#include "defs.h"
#include "mp_defs.h"
#include "log.h"
#include "x509.h"
#include "ca.h"
#include "certs.h"
#include "keys.h"
#include "smartcard.h"
#include "whack.h"
#include "fetch.h"

#define DEFAULT_BASE	16

/* chained list of smartcard records */
static smartcard_t *smartcards   = NULL;

/* number of generated sc objects */
static int sc_number = 0;

const smartcard_t empty_sc = {
      NULL		 , /* next */
            0		 , /* last_load */
    { CERT_NONE, {NULL} }, /* last_cert */
            0		 , /* count */
            0		 , /* number */
       999999		 , /* slot */
      NULL		 , /* id */
      NULL		 , /* label */
    { NULL, 0 }		 , /* pin */
      FALSE		 , /* pinpad */
      FALSE		 , /* valid */
      FALSE		 , /* session_opened */
      FALSE		 , /* logged_in */
      TRUE		 , /* any_slot */
	    0L		 , /* session */
};

#ifdef SMARTCARD	/* compile with smartcard support */

#define SCX_MAGIC	0xd00bed00

struct scx_pkcs11_module {
        u_int _magic;
        void *handle;
};

typedef struct scx_pkcs11_module scx_pkcs11_module_t;

/* PKCS #11 cryptoki context */
static bool scx_initialized = FALSE;
static scx_pkcs11_module_t *pkcs11_module = NULL_PTR;
static CK_FUNCTION_LIST_PTR pkcs11_functions = NULL_PTR;

/* crytoki v2.11 - return values of PKCS #11 functions*/

static const char *const pkcs11_return_name[] = {
	"CKR_OK",
	"CKR_CANCEL",
	"CKR_HOST_MEMORY",
	"CKR_SLOT_ID_INVALID",
	"CKR_FLAGS_INVALID",
	"CKR_GENERAL_ERROR",
	"CKR_FUNCTION_FAILED",
	"CKR_ARGUMENTS_BAD",
	"CKR_NO_EVENT",
	"CKR_NEED_TO_CREATE_THREADS",
	"CKR_CANT_LOCK"
    };

static const char *const pkcs11_return_name_10[] = {
	"CKR_ATTRIBUTE_READ_ONLY",
	"CKR_ATTRIBUTE_SENSITIVE",
	"CKR_ATTRIBUTE_TYPE_INVALID",
	"CKR_ATTRIBUTE_VALUE_INVALID"
    };

static const char *const pkcs11_return_name_20[] = {
	"CKR_DATA_INVALID", 
	"CKR_DATA_LEN_RANGE"
    };

static const char *const pkcs11_return_name_30[] = {
	"CKR_DEVICE_ERROR",
	"CKR_DEVICE_MEMORY",
	"CKR_DEVICE_REMOVED"
    };

static const char *const pkcs11_return_name_40[] = {
	"CKR_ENCRYPTED_DATA_INVALID",
	"CKR_ENCRYPTED_DATA_LEN_RANGE"
    };

static const char *const pkcs11_return_name_50[] = {
	"CKR_FUNCTION_CANCELED",
	"CKR_FUNCTION_NOT_PARALLEL",
	"CKR_0x52_UNDEFINED",
	"CKR_0x53_UNDEFINED",
	"CKR_FUNCTION_NOT_SUPPORTED"
    };

static const char *const pkcs11_return_name_60[] = {
	"CKR_KEY_HANDLE_INVALID",
	"CKR_KEY_SENSITIVE",
	"CKR_KEY_SIZE_RANGE",
	"CKR_KEY_TYPE_INCONSISTENT",
	"CKR_KEY_NOT_NEEDED",
	"CKR_KEY_CHANGED",
	"CKR_KEY_NEEDED",
	"CKR_KEY_INDIGESTIBLE",
	"CKR_KEY_FUNCTION_NOT_PERMITTED",
	"CKR_KEY_NOT_WRAPPABLE",
	"CKR_KEY_UNEXTRACTABLE"
     };

static const char *const pkcs11_return_name_70[] = {
	"CKR_MECHANISM_INVALID",
	"CKR_MECHANISM_PARAM_INVALID"
     };

static const char *const pkcs11_return_name_80[] = {
	"CKR_OBJECT_HANDLE_INVALID"
     };

static const char *const pkcs11_return_name_90[] = {
	"CKR_OPERATION_ACTIVE",
	"CKR_OPERATION_NOT_INITIALIZED"
     };

static const char *const pkcs11_return_name_A0[] = {
	"CKR_PIN_INCORRECT",
	"CKR_PIN_INVALID",
	"CKR_PIN_LEN_RANGE",
	"CKR_PIN_EXPIRED",
	"CKR_PIN_LOCKED"
     };

static const char *const pkcs11_return_name_B0[] = {
	"CKR_SESSION_CLOSED",
	"CKR_SESSION_COUNT",
	"CKR_0xB2_UNDEFINED",
	"CKR_SESSION_HANDLE_INVALID",
	"CKR_SESSION_PARALLEL_NOT_SUPPORTED",
	"CKR_SESSION_READ_ONLY",
	"CKR_SESSION_EXISTS",
	"CKR_SESSION_READ_ONLY_EXISTS",
	"CKR_SESSION_READ_WRITE_SO_EXISTS"
     };

static const char *const pkcs11_return_name_C0[] = {
	"CKR_SIGNATURE_INVALID",
	"CKR_SIGNATURE_LEN_RANGE"
     };

static const char *const pkcs11_return_name_D0[] = {
	"CKR_TEMPLATE_INCOMPLETE",
	"CKR_TEMPLATE_INCONSISTENT"
     };

static const char *const pkcs11_return_name_E0[] = {
	"CKR_TOKEN_NOT_PRESENT",
	"CKR_TOKEN_NOT_RECOGNIZED",
	"CKR_TOKEN_WRITE_PROTECTED"
     };

static const char *const pkcs11_return_name_F0[] = {
	"CKR_UNWRAPPING_KEY_HANDLE_INVALID",
	"CKR_UNWRAPPING_KEY_SIZE_RANGE",
	"CKR_UNWRAPPING_KEY_TYPE_INCONSISTENT"
     };

static const char *const pkcs11_return_name_100[] = {
	"CKR_USER_ALREADY_LOGGED_IN",
	"CKR_USER_NOT_LOGGED_IN",
	"CKR_USER_PIN_NOT_INITIALIZED",
	"CKR_USER_TYPE_INVALID",
	"CKR_USER_ANOTHER_ALREADY_LOGGED_IN",
	"CKR_USER_TOO_MANY_TYPES"
     };

static const char *const pkcs11_return_name_110[] = {
	"CKR_WRAPPED_KEY_INVALID",
	"CKR_0x111_UNDEFINED",
	"CKR_WRAPPED_KEY_LEN_RANGE",
	"CKR_WRAPPING_KEY_HANDLE_INVALID",
	"CKR_WRAPPING_KEY_SIZE_RANGE",
	"CKR_WRAPPING_KEY_TYPE_INCONSISTENT"
     };

static const char *const pkcs11_return_name_120[] = {
	"CKR_RANDOM_SEED_NOT_SUPPORTED",
	"CKR_RANDOM_NO_RNG"
     };

static const char *const pkcs11_return_name_130[] = {
	"CKR_DOMAIN_PARAMS_INVALID"
     };

static const char *const pkcs11_return_name_150[] = {
	"CKR_BUFFER_TOO_SMALL"
     };

static const char *const pkcs11_return_name_160[] = {
	"CKR_SAVED_STATE_INVALID"
     };

static const char *const pkcs11_return_name_170[] = {
	"CKR_INFORMATION_SENSITIVE"
     };

static const char *const pkcs11_return_name_180[] = {
	"CKR_STATE_UNSAVEABLE"
     };

static const char *const pkcs11_return_name_190[] = {
	"CKR_CRYPTOKI_NOT_INITIALIZED",
	"CKR_CRYPTOKI_ALREADY_INITIALIZED"
     };

static const char *const pkcs11_return_name_1A0[] = {
	"CKR_MUTEX_BAD",
	"CKR_MUTEX_NOT_LOCKED"
     };

static const char *const pkcs11_return_name_200[] = {
	"CKR_FUNCTION_REJECTED"
     };

static const char *const pkcs11_return_name_vendor[] = {
	"CKR_VENDOR_DEFINED"
     };

static enum_names pkcs11_return_names_vendor =
    { CKR_VENDOR_DEFINED, CKR_VENDOR_DEFINED
	, pkcs11_return_name_vendor, NULL };

static enum_names pkcs11_return_names_200 =
    { CKR_FUNCTION_REJECTED, CKR_FUNCTION_REJECTED
	, pkcs11_return_name_200, &pkcs11_return_names_vendor };

static enum_names pkcs11_return_names_1A0 =
    { CKR_MUTEX_BAD, CKR_MUTEX_NOT_LOCKED
	, pkcs11_return_name_1A0, &pkcs11_return_names_200 };

static enum_names pkcs11_return_names_190 =
    { CKR_CRYPTOKI_NOT_INITIALIZED, CKR_CRYPTOKI_ALREADY_INITIALIZED
	, pkcs11_return_name_190, &pkcs11_return_names_1A0 };

static enum_names pkcs11_return_names_180 =
    { CKR_STATE_UNSAVEABLE, CKR_STATE_UNSAVEABLE
	, pkcs11_return_name_180, &pkcs11_return_names_190 };

static enum_names pkcs11_return_names_170 =
    { CKR_INFORMATION_SENSITIVE, CKR_INFORMATION_SENSITIVE
	, pkcs11_return_name_170, &pkcs11_return_names_180 };

static enum_names pkcs11_return_names_160 =
    { CKR_SAVED_STATE_INVALID, CKR_SAVED_STATE_INVALID
	, pkcs11_return_name_160, &pkcs11_return_names_170 };

static enum_names pkcs11_return_names_150 =
    { CKR_BUFFER_TOO_SMALL, CKR_BUFFER_TOO_SMALL
	, pkcs11_return_name_150, &pkcs11_return_names_160 };

static enum_names pkcs11_return_names_130 =
    { CKR_DOMAIN_PARAMS_INVALID, CKR_DOMAIN_PARAMS_INVALID
	, pkcs11_return_name_130, &pkcs11_return_names_150 };

static enum_names pkcs11_return_names_120 =
    { CKR_RANDOM_SEED_NOT_SUPPORTED, CKR_RANDOM_NO_RNG
	, pkcs11_return_name_120, &pkcs11_return_names_130 };

static enum_names pkcs11_return_names_110 =
    { CKR_WRAPPED_KEY_INVALID, CKR_WRAPPING_KEY_TYPE_INCONSISTENT
	, pkcs11_return_name_110, &pkcs11_return_names_120 };

static enum_names pkcs11_return_names_100 =
    { CKR_USER_ALREADY_LOGGED_IN, CKR_USER_TOO_MANY_TYPES
	, pkcs11_return_name_100, &pkcs11_return_names_110 };

static enum_names pkcs11_return_names_F0 =
    { CKR_UNWRAPPING_KEY_HANDLE_INVALID, CKR_UNWRAPPING_KEY_TYPE_INCONSISTENT
	, pkcs11_return_name_F0, &pkcs11_return_names_100 };

static enum_names pkcs11_return_names_E0 =
    { CKR_TOKEN_NOT_PRESENT, CKR_TOKEN_WRITE_PROTECTED
	, pkcs11_return_name_E0, &pkcs11_return_names_F0 };

static enum_names pkcs11_return_names_D0 =
    { CKR_TEMPLATE_INCOMPLETE, CKR_TEMPLATE_INCONSISTENT
	, pkcs11_return_name_D0,&pkcs11_return_names_E0 };

static enum_names pkcs11_return_names_C0 =
    { CKR_SIGNATURE_INVALID, CKR_SIGNATURE_LEN_RANGE
	, pkcs11_return_name_C0, &pkcs11_return_names_D0 };

static enum_names pkcs11_return_names_B0 =
    { CKR_SESSION_CLOSED, CKR_SESSION_READ_WRITE_SO_EXISTS
	, pkcs11_return_name_B0, &pkcs11_return_names_C0 };

static enum_names pkcs11_return_names_A0 =
    { CKR_PIN_INCORRECT, CKR_PIN_LOCKED
	, pkcs11_return_name_A0, &pkcs11_return_names_B0 };

static enum_names pkcs11_return_names_90 =
    { CKR_OPERATION_ACTIVE, CKR_OPERATION_NOT_INITIALIZED
	, pkcs11_return_name_90, &pkcs11_return_names_A0 };

static enum_names pkcs11_return_names_80 =
    { CKR_OBJECT_HANDLE_INVALID, CKR_OBJECT_HANDLE_INVALID
	, pkcs11_return_name_80, &pkcs11_return_names_90 };

static enum_names pkcs11_return_names_70 =
    { CKR_MECHANISM_INVALID, CKR_MECHANISM_PARAM_INVALID
	, pkcs11_return_name_70, &pkcs11_return_names_80 };

static enum_names pkcs11_return_names_60 =
    { CKR_KEY_HANDLE_INVALID, CKR_KEY_UNEXTRACTABLE
	, pkcs11_return_name_60, &pkcs11_return_names_70 };

static enum_names pkcs11_return_names_50 =
    { CKR_FUNCTION_CANCELED, CKR_FUNCTION_NOT_SUPPORTED
	, pkcs11_return_name_50, &pkcs11_return_names_60 };

static enum_names pkcs11_return_names_40 =
    { CKR_ENCRYPTED_DATA_INVALID, CKR_ENCRYPTED_DATA_LEN_RANGE
	, pkcs11_return_name_40, &pkcs11_return_names_50 };

static enum_names pkcs11_return_names_30 =
    { CKR_DEVICE_ERROR, CKR_DEVICE_REMOVED
	, pkcs11_return_name_30, &pkcs11_return_names_40 };

static enum_names pkcs11_return_names_20 =
    { CKR_DATA_INVALID, CKR_DATA_LEN_RANGE
	, pkcs11_return_name_20, &pkcs11_return_names_30 };

static enum_names pkcs11_return_names_10 =
    { CKR_ATTRIBUTE_READ_ONLY, CKR_ATTRIBUTE_VALUE_INVALID
	, pkcs11_return_name_10, &pkcs11_return_names_20};

static enum_names pkcs11_return_names =
    { CKR_OK, CKR_CANT_LOCK
	, pkcs11_return_name, &pkcs11_return_names_10};

/*
 * Unload a PKCS#11 module.
 * The calling application is responsible for cleaning up
 * and calling C_Finalize()
 */
static CK_RV
scx_unload_pkcs11_module(scx_pkcs11_module_t *mod)
{
    if (!mod || mod->_magic != SCX_MAGIC)
	return CKR_ARGUMENTS_BAD;

    if (dlclose(mod->handle) < 0)
	return CKR_FUNCTION_FAILED;

    memset(mod, 0, sizeof(*mod));
    free(mod);
    return CKR_OK;
}

static scx_pkcs11_module_t*
scx_load_pkcs11_module(const char *name, CK_FUNCTION_LIST_PTR_PTR funcs)
{
    CK_RV (*c_get_function_list)(CK_FUNCTION_LIST_PTR_PTR);
    scx_pkcs11_module_t *mod;
    void *handle;
    int rv;

    if (name == NULL || *name == '\0')
	return NULL;

    /* Try to load PKCS#11 library module*/
    handle = dlopen(name, RTLD_NOW);
    if (handle == NULL)
	return NULL;

    mod = malloc_thing(scx_pkcs11_module_t);
    mod->_magic = SCX_MAGIC;
    mod->handle = handle;

   /* Get the list of function pointers */
    c_get_function_list = (CK_RV (*)(CK_FUNCTION_LIST_PTR_PTR))
	    dlsym(mod->handle, "C_GetFunctionList");
    if (!c_get_function_list)
	goto failed;

    rv = c_get_function_list(funcs);
    if (rv == CKR_OK)
	return mod;

failed: scx_unload_pkcs11_module(mod);
	return NULL;
}

/*
 * retrieve a certificate object
 */
static bool
scx_find_cert_object(CK_SESSION_HANDLE session, CK_OBJECT_HANDLE object
, smartcard_t *sc, cert_t *cert)
{
    size_t hex_len, label_len;
    u_char *hex_id = NULL;
    chunk_t blob;
    x509cert_t *x509cert;

    CK_ATTRIBUTE attr[] = {
	{ CKA_ID,    NULL_PTR, 0L },
	{ CKA_LABEL, NULL_PTR, 0L },
	{ CKA_VALUE, NULL_PTR, 0L }
    };

    /* initialize the return argument */
    *cert = empty_cert;

    /* get the length of the attributes first */
    CK_RV rv = pkcs11_functions->C_GetAttributeValue(session, object, attr, 3);
    if (rv != CKR_OK)
    {
	plog("couldn't read the attribute sizes: %s"
	    , enum_show(&pkcs11_return_names, rv));
	return FALSE;
    }

    free(sc->label);

    hex_id    = malloc(attr[0].ulValueLen);
    hex_len   = attr[0].ulValueLen;
    sc->label = malloc(attr[1].ulValueLen + 1);
    label_len = attr[1].ulValueLen;
    blob.ptr  = malloc(attr[2].ulValueLen);
    blob.len  = attr[2].ulValueLen;

    attr[0].pValue = hex_id;
    attr[1].pValue = sc->label;
    attr[2].pValue = blob.ptr;

    /* now get the attributes */
    rv = pkcs11_functions->C_GetAttributeValue(session, object, attr, 3);
    if (rv != CKR_OK)
    {
	plog("couldn't read the attributes: %s"
	    , enum_show(&pkcs11_return_names, rv));
	free(hex_id);
	free(sc->label);
	free(blob.ptr);
	return FALSE;
    }

    free(sc->id);

    /* convert id from hex to ASCII */
    sc->id = malloc(2*hex_len + 1);
    datatot(hex_id, hex_len, 16, sc->id, 2*hex_len + 1);
    free(hex_id);

    /* safeguard in case the label is not null terminated */
    sc->label[label_len] = '\0';

    /* parse the retrieved cert */
    x509cert = malloc_thing(x509cert_t);
    *x509cert = empty_x509cert;
    x509cert->smartcard = TRUE;

    if (!parse_x509cert(blob, 0, x509cert))
    {
	plog("failed to load cert from smartcard, error in X.509 certificate");
	free_x509cert(x509cert);
	return FALSE;
    }
    cert->type = CERT_X509_SIGNATURE;
    cert->u.x509 = x509cert;
    return TRUE;
}

/*
 * search a given slot for PKCS#11 certificate objects
 */
static void
scx_find_cert_objects(CK_SLOT_ID slot, CK_SESSION_HANDLE session)
{
    CK_RV rv;
    CK_OBJECT_CLASS class = CKO_CERTIFICATE;
    CK_ATTRIBUTE attr[] = {{ CKA_CLASS, &class, sizeof(class) }};

    rv = pkcs11_functions->C_FindObjectsInit(session, attr, 1);
    if (rv != CKR_OK)
    {
	plog("error in C_FindObjectsInit: %s"
	    , enum_show(&pkcs11_return_names, rv));
	return;
    }

    for (;;)
    {
	CK_OBJECT_HANDLE object;
	CK_ULONG obj_count = 0;
	err_t ugh;
	time_t valid_until;
	smartcard_t *sc;
	x509cert_t *cert;

	rv = pkcs11_functions->C_FindObjects(session, &object, 1, &obj_count);
	if (rv != CKR_OK)
	{
	    plog("error in C_FindObjects: %s"
		, enum_show(&pkcs11_return_names, rv));
	    break;
	}

	/* no objects left */
	if (obj_count == 0)
	    break;

	/* create and initialize a new smartcard object */
	sc  = malloc_thing(smartcard_t);
	*sc = empty_sc;
	sc->any_slot = FALSE;
	sc->slot  = slot;

        if (!scx_find_cert_object(session, object, sc, &sc->last_cert))
	{
	    scx_free(sc);
	    continue;
	}
 	DBG(DBG_CONTROL,
	    DBG_log("found cert in %s with id: %s, label: '%s'"
		, scx_print_slot(sc, ""), sc->id, sc->label)
	)

	/* check validity of certificate */
	cert = sc->last_cert.u.x509;
	valid_until = cert->notAfter;
	ugh = check_validity(cert, &valid_until);
	if (ugh != NULL)
	{
	    plog("  %s", ugh);
	    free_x509cert(cert);
	    scx_free(sc);
	    continue;
	}
	else
	{
	    DBG(DBG_CONTROL,
	 	DBG_log("  certificate is valid")
	    )
	}

	sc = scx_add(sc);

	/* put end entity and ca certificates into different chains */
	if (cert->isCA)
	{
	    sc->last_cert.u.x509 = add_authcert(cert, AUTH_CA);
	}
	else
	{
	    add_x509_public_key(cert, valid_until, DAL_LOCAL);
	    sc->last_cert.u.x509 = add_x509cert(cert);
	}

	share_cert(sc->last_cert);
	time(&sc->last_load);
    }

    rv = pkcs11_functions->C_FindObjectsFinal(session);
    if (rv != CKR_OK)
    {
	plog("error in C_FindObjectsFinal: %s"
	        , enum_show(&pkcs11_return_names, rv));
    }
}

/*
 * search all slots for PKCS#11 certificate objects
 */
static void
scx_find_all_cert_objects(void)
{
    CK_RV rv;
    CK_SLOT_ID_PTR slots = NULL_PTR;
    CK_ULONG slot_count = 0;
    CK_ULONG i;

    if (!scx_initialized)
    {
	plog("pkcs11 module not initialized");
	return;
    }

    /* read size, always returns CKR_OK ! */
    rv = pkcs11_functions->C_GetSlotList(FALSE, NULL_PTR, &slot_count);

    /* allocate memory for the slots */
    slots = (CK_SLOT_ID *)malloc(slot_count * sizeof(CK_SLOT_ID));

    rv = pkcs11_functions->C_GetSlotList(FALSE, slots, &slot_count);
    if (rv != CKR_OK)
    {
	plog("error in C_GetSlotList: %s", enum_show(&pkcs11_return_names, rv));
	free(slots);
	return;
    }

    /* look in every slot for certificate objects */
    for (i = 0; i < slot_count; i++)
    {
	CK_SLOT_ID slot = slots[i];
	CK_SLOT_INFO info;
	CK_SESSION_HANDLE session;

	rv = pkcs11_functions->C_GetSlotInfo(slot, &info);

	if (rv != CKR_OK)
	{
	    plog("error in C_GetSlotInfo: %s"
		, enum_show(&pkcs11_return_names, rv));
	    continue;
	}
	
	if (!(info.flags & CKF_TOKEN_PRESENT))
	{
	    plog("no token present in slot %lu", slot);
	    continue;
	}

	rv = pkcs11_functions->C_OpenSession(slot
		, CKF_SERIAL_SESSION, NULL_PTR, NULL_PTR, &session);
	if (rv != CKR_OK)
	{
	    plog("failed to open a session on slot %lu: %s"
		, slot, enum_show(&pkcs11_return_names, rv));
	    continue;
	}
	DBG(DBG_CONTROLMORE,
	    DBG_log("pkcs11 session #%ld for searching slot %lu", session, slot)
	)
	scx_find_cert_objects(slot, session);

	rv = pkcs11_functions->C_CloseSession(session);
	if (rv != CKR_OK)
	{
	    plog("error in C_CloseSession: %s"
		, enum_show(&pkcs11_return_names, rv));
	}
    }
    free(slots);
}
#endif

/*
 * load and initialize PKCS#11 cryptoki module
 *
 * init_args should be unused when we have a PKCS#11 compliant module,
 * but NSS softoken breaks that API.
 */
void
scx_init(const char* module, const char *init_args)
{
#ifdef SMARTCARD
    CK_C_INITIALIZE_ARGS args = { .pReserved = (char *)init_args, };
    CK_RV rv;

    if (scx_initialized)
    {
	plog("weird - pkcs11 module seems already to be initialized");
	return;
    }

    if (module == NULL)
#ifdef PKCS11_DEFAULT_LIB
	module = PKCS11_DEFAULT_LIB;
#else
    {
	plog("no pkcs11 module defined");
	return;
    }
#endif

    DBG(DBG_CONTROL | DBG_CRYPT,
	DBG_log("pkcs11 module '%s' loading...", module)
    )
    pkcs11_module = scx_load_pkcs11_module(module, &pkcs11_functions);
    if (pkcs11_module == NULL)
    {
	 plog("failed to load pkcs11 module '%s'", module);
	 return;
    }

    DBG(DBG_CONTROL | DBG_CRYPT,
	DBG_log("pkcs11 module initializing...")
    )
    rv = pkcs11_functions->C_Initialize(init_args ? &args : NULL);
    if (rv != CKR_OK)
    {
	plog("failed to initialize pkcs11 module: %s"
	    , enum_show(&pkcs11_return_names, rv));
	return;
    }

    scx_initialized = TRUE;
    DBG(DBG_CONTROL | DBG_CRYPT,
	DBG_log("pkcs11 module loaded and initialized")
    )

    scx_find_all_cert_objects();
#endif
}

/*
 * finalize and unload PKCS#11 cryptoki module 
 */
void
scx_finalize(void)
{
#ifdef SMARTCARD
    while (smartcards != NULL)
    {
	scx_release(smartcards);
    }

    if (pkcs11_functions != NULL_PTR)
    {
	pkcs11_functions->C_Finalize(NULL_PTR);
	pkcs11_functions = NULL_PTR;
    }

    if (pkcs11_module != NULL)
    {
	scx_unload_pkcs11_module(pkcs11_module);
	pkcs11_module = NULL;
    }

    scx_initialized = FALSE;
    DBG(DBG_CONTROL | DBG_CRYPT,
	DBG_log("pkcs11 module finalized and unloaded")
    )
#endif
}

/*
 * does a filename contain the token %smartcard?
 */
bool
scx_on_smartcard(const char *filename)
{
    return strneq(filename, SCX_TOKEN, strlen(SCX_TOKEN));
}

#ifdef SMARTCARD
/*
 * find a specific object on the smartcard 
 */
static bool
scx_pkcs11_find_object(	CK_SESSION_HANDLE session, 
			CK_OBJECT_HANDLE_PTR object, 
			CK_OBJECT_CLASS class, 
			const char* id)
{
    size_t len;
    char buf[BUF_LEN];
    CK_RV rv;
    CK_ULONG obj_count = 0;
    CK_ULONG attr_count = 1;

    CK_ATTRIBUTE attr[] = {
	{ CKA_CLASS, &class, sizeof(class) },
	{ CKA_ID, &buf, 0L }
    };

    if (id != NULL)
    {
	ttodata(id, strlen(id), 16, buf, BUF_LEN, &len);
	attr[1].ulValueLen = len;
	attr_count = 2;
    }

    /* get info for certificate with id */
    rv = pkcs11_functions->C_FindObjectsInit(session, attr, attr_count);
    if (rv != CKR_OK)
    {
	plog("error in C_FindObjectsInit: %s"
	        , enum_show(&pkcs11_return_names, rv));
	return FALSE;
    }

    rv = pkcs11_functions->C_FindObjects(session, object, 1,  &obj_count);
    if (rv != CKR_OK)
    {
	plog("error in C_FindObjects: %s"
	        , enum_show(&pkcs11_return_names, rv));
	return FALSE;
    }

    rv = pkcs11_functions->C_FindObjectsFinal(session);
    if (rv != CKR_OK)
    {
	plog("error in C_FindObjectsFinal: %s"
	        , enum_show(&pkcs11_return_names, rv));
	return FALSE;
    }

    return (obj_count != 0);
}

/*
 * check if a given certificate object id is found in a slot
 */
static bool
scx_find_cert_id_in_slot(smartcard_t *sc, CK_SLOT_ID slot)
{
    CK_SESSION_HANDLE session;
    CK_OBJECT_HANDLE object;
    CK_SLOT_INFO info;

    CK_RV rv = pkcs11_functions->C_GetSlotInfo(slot, &info);

    if (rv != CKR_OK)
    {
	plog("error in C_GetSlotInfo: %s"
	    , enum_show(&pkcs11_return_names, rv));
	 return FALSE;
    }
	
    if (!(info.flags & CKF_TOKEN_PRESENT))
    {
	plog("no token present in slot %lu", slot);
	return FALSE;
    }

    rv = pkcs11_functions->C_OpenSession(slot
		, CKF_SERIAL_SESSION, NULL_PTR, NULL_PTR, &session);
    if (rv != CKR_OK)
    {
	plog("failed to open a session on slot %lu: %s"
	    , slot, enum_show(&pkcs11_return_names, rv));
	return FALSE;
    }
    DBG(DBG_CONTROLMORE,
	DBG_log("pkcs11 session #%ld for searching slot %lu", session, slot)
    )

    /* check if there is a certificate on the card in the specified slot */
    if (scx_pkcs11_find_object(session, &object, CKO_CERTIFICATE, sc->id))
    {
	sc->slot = slot;
	sc->any_slot = FALSE;
	sc->session = session;
	sc->session_opened = TRUE;
	return TRUE;
    }
	
    rv = pkcs11_functions->C_CloseSession(session);
    if (rv != CKR_OK)
    {
	plog("error in C_CloseSession: %s"
		, enum_show(&pkcs11_return_names, rv));
    }
    return FALSE;
}
#endif

/*
 * Connect to the smart card in the reader and select the correct slot
 */
bool
scx_establish_context(smartcard_t *sc)
{
#ifdef SMARTCARD
    bool id_found = FALSE;

    if (!scx_initialized)
    {
	plog("pkcs11 module not initialized");
	return FALSE;
    }

    if (sc->session_opened)
    {
	DBG(DBG_CONTROL | DBG_CRYPT,
	    DBG_log("pkcs11 session #%ld already open", sc->session)
	)
	return TRUE;
    }

    if (!sc->any_slot)
	id_found = scx_find_cert_id_in_slot(sc, sc->slot);

    if (!id_found)
    {
	CK_RV rv;
	CK_SLOT_ID slot;
	CK_SLOT_ID_PTR slots = NULL_PTR;
	CK_ULONG slot_count = 0;
	CK_ULONG i;

	/* read size, always returns CKR_OK ! */
	rv = pkcs11_functions->C_GetSlotList(FALSE, NULL_PTR, &slot_count);

	/* allocate memory for the slots */
	slots = (CK_SLOT_ID *)malloc(slot_count * sizeof(CK_SLOT_ID));

	rv = pkcs11_functions->C_GetSlotList(FALSE, slots, &slot_count);
	if (rv != CKR_OK)
	{
	    plog("error in C_GetSlotList: %s"
		, enum_show(&pkcs11_return_names, rv));
	    free(slots);
	    return FALSE;
        }

        /* look in every slot for a certificate with a given object ID */
	for (i = 0; i < slot_count; i++)
	{
	    slot = slots[i];
	    id_found = scx_find_cert_id_in_slot(sc, slot);
	    if (id_found)
	        break;
        }
	free(slots);
    }

    if (id_found)
    {
	DBG(DBG_CONTROL | DBG_CRYPT,
	    DBG_log("found token with id %s in slot %lu", sc->id, sc->slot);
	    DBG_log("pkcs11 session #%ld opened", sc->session)
	)
    }
    else
    {
	plog("  no certificate with id %s found on smartcard", sc->id);
    }
    return id_found;
#else
    plog("warning: SMARTCARD support is deactivated in pluto/Makefile!");
    return FALSE;
#endif
}

/*
 * log in to a session
 */
bool
scx_login(smartcard_t *sc)
{
#ifdef SMARTCARD
    CK_RV rv;

    if (sc->logged_in)
    {
	DBG(DBG_CONTROL | DBG_CRYPT,
	    DBG_log("pkcs11 session #%ld login already done", sc->session)
	)
	return TRUE;
    }
	
    if (sc->pin.ptr == NULL)
    {
	plog("unable to log in without PIN!");
	return FALSE;
    }

    if (!sc->session_opened)
    {
	plog("session not opened");
	return FALSE;
    }

    rv = pkcs11_functions->C_Login(sc->session, CKU_USER 
				, (CK_UTF8CHAR *) sc->pin.ptr, sc->pin.len);
    if (rv != CKR_OK && rv != CKR_USER_ALREADY_LOGGED_IN)
    {
	plog("unable to login: %s"
	    , enum_show(&pkcs11_return_names, rv));
	return FALSE;
    }
    DBG(DBG_CONTROL | DBG_CRYPT,
	DBG_log("pkcs11 session #%ld login successful", sc->session)
    )
    sc->logged_in = TRUE;
    return TRUE;
#else
   return FALSE;
#endif
}

#ifdef SMARTCARD
/*
 * logout from a session
 */
static void
scx_logout(smartcard_t *sc)
{
    CK_RV rv;
    
    rv = pkcs11_functions->C_Logout(sc->session);
    if (rv != CKR_OK)
	plog("error in C_Logout: %s"
	    , enum_show(&pkcs11_return_names, rv));
    else
	DBG(DBG_CONTROL | DBG_CRYPT,
	    DBG_log("pkcs11 session #%ld logout", sc->session)
	)
    sc->logged_in = FALSE;
}
#endif


/*
 * Release context and disconnect from card
 */
void
scx_release_context(smartcard_t *sc)
{
#ifdef SMARTCARD
    CK_RV rv;

    if (!scx_initialized)
	return;

    if (sc->session_opened)
    {
	if (sc->logged_in)
	    scx_logout(sc);

	sc->session_opened = FALSE;
	
	rv = pkcs11_functions->C_CloseSession(sc->session);
	if (rv != CKR_OK)
	    plog("error in C_CloseSession: %s"
		, enum_show(&pkcs11_return_names, rv));
	else
	    DBG(DBG_CONTROL | DBG_CRYPT,
		DBG_log("pkcs11 session #%ld closed", sc->session)
	    )
    }
#endif
}

/*
 * Load host certificate from smartcard
 */
bool
scx_load_cert(const char *filename, smartcard_t **scp, cert_t *cert
, bool *cached)
{
#ifdef SMARTCARD	/* compile with smartcard support */
    CK_OBJECT_HANDLE object;

    const char *number_slot_id = filename + strlen(SCX_TOKEN);

    smartcard_t *sc = scx_add(scx_parse_number_slot_id(number_slot_id));

    /* return the smartcard object */
    *scp = sc;

    /* is there a cached smartcard certificate? */
    *cached = sc->last_cert.type != CERT_NONE
	      && (time(NULL) - sc->last_load) < SCX_CERT_CACHE_INTERVAL;

    if (*cached)
    {
	*cert = sc->last_cert;
	plog("  using cached cert from smartcard #%d (%s, id: %s, label: '%s')"
		, sc->number
		, scx_print_slot(sc, "")
		, sc->id
		, sc->label);
	return TRUE;
    }

    if (!scx_establish_context(sc))
    {
	scx_release_context(sc);
	return FALSE;
    }

    /* find the certificate object */
    if (!scx_pkcs11_find_object(sc->session, &object, CKO_CERTIFICATE, sc->id))
    {
	scx_release_context(sc);
	return FALSE;
    }

    /* retrieve the certificate object */
    if (!scx_find_cert_object(sc->session, object, sc, cert))
    {
	scx_release_context(sc);
	return FALSE;
    }

    if (!pkcs11_keep_state)
	scx_release_context(sc);

    plog("  loaded cert from smartcard #%d (%s, id: %s, label: '%s')"
	, sc->number
	, scx_print_slot(sc, "")
	, sc->id
	, sc->label);

    return TRUE;
#else
    plog("  warning: SMARTCARD support is deactivated in pluto/Makefile!");
    return FALSE;
#endif
}

/*
 * parse slot number and key id
 * the following syntax is allowed
 *               number   slot   id
 * %smartcard      1       -     -
 * %smartcard#2    2       -     -
 * %smartcard0     -       0     -
 * %smartcard:45   -       -     45
 * %smartcard0:45  -       0     45
 */
smartcard_t*
scx_parse_number_slot_id(const char *number_slot_id)
{
    int len = strlen(number_slot_id);
    smartcard_t *sc = malloc_thing(smartcard_t);

    /* assign default values */
    *sc = empty_sc;

    if (len == 0)			/* default: use certificate #1 */
    {
	sc->number = 1;	
    }
    else if (*number_slot_id == '#')	/* #number scheme */
    {
	err_t ugh;
	unsigned long ul;

	ugh = atoul(number_slot_id+1, len-1 , 10, &ul);
	if (ugh == NULL)
	    sc->number = (int)ul;
	else
	    plog("error parsing smartcard number: %s", ugh);
    }
    else				/* slot:id scheme */
    {
	int slot_len = len;
	char *p = strchr(number_slot_id, ':');

	if (p != NULL)
	{
	    int id_len = len - (p + 1 - number_slot_id);
	    slot_len -= (1 + id_len);

	    if (id_len > 0)		/* we have an id */
		sc->id = p + 1;
	}
	if (slot_len > 0)		/* we have a slot */
	{
	    err_t ugh = NULL;
	    unsigned long ul;

	    ugh = atoul(number_slot_id, slot_len, 10, &ul);
	    if (ugh == NULL)
	    {
		sc->slot = ul;
                sc->any_slot = FALSE;
	    }
	    else
		plog("error parsing smartcard slot number: %s", ugh);
	}
    }
    /* unshare the id string */
    sc->id = clone_str(sc->id);
    return sc;
}

/*
 * Verify pin on card
 */
bool
scx_verify_pin(smartcard_t *sc)
{
#ifdef SMARTCARD
    CK_RV rv;
    
    if (!sc->pinpad)
	sc->valid = FALSE;

    if (sc->pin.ptr == NULL)
    {
	plog("unable to verify without PIN");
	return FALSE;
    }

    /* establish context */
    if (!scx_establish_context(sc))
    {
	scx_release_context(sc);
	return FALSE;
    }

    rv = pkcs11_functions->C_Login(sc->session, CKU_USER,
			      (CK_UTF8CHAR *) sc->pin.ptr, sc->pin.len);
    if (rv == CKR_OK || rv == CKR_USER_ALREADY_LOGGED_IN)
    {
	sc->valid = TRUE;
	sc->logged_in = TRUE;
	DBG(DBG_CONTROL | DBG_CRYPT,
	    DBG_log((rv == CKR_OK)
		? "PIN code correct"
		: "already logged in, no PIN entry required");
	    DBG_log("pkcs11 session #%ld login successful", sc->session)
        )
    }
    else
    {
	DBG(DBG_CONTROL | DBG_CRYPT,
	    DBG_log("PIN code incorrect")
        )
    }
    if (!pkcs11_keep_state)
	scx_release_context(sc);
#else
    sc->valid = FALSE;
#endif
    return sc->valid;
}

/*
 * Sign hash on smartcard
 */
bool
scx_sign_hash(smartcard_t *sc, const u_char *in, size_t inlen
, u_char *out, size_t outlen)
{
#ifdef SMARTCARD
    CK_RV rv;
    CK_OBJECT_HANDLE object;
    CK_ULONG siglen = (CK_ULONG)outlen;
    CK_BBOOL sign_flag, decrypt_flag;
    CK_ATTRIBUTE attr[] = {
	{ CKA_SIGN,    &sign_flag,    sizeof(sign_flag) },
	{ CKA_DECRYPT, &decrypt_flag, sizeof(decrypt_flag) }
    };

    if (!sc->logged_in)
    	return FALSE;

    if (!scx_pkcs11_find_object(sc->session, &object, CKO_PRIVATE_KEY, sc->id))
    {
	plog("unable to find private key with id '%s'", sc->id);
	return FALSE;
    }

    rv = pkcs11_functions->C_GetAttributeValue(sc->session, object, attr, 2);
    if (rv != CKR_OK)
    {
	plog("couldn't read the private key attributes: %s"
	    , enum_show(&pkcs11_return_names, rv));
	return FALSE;
    }
    DBG(DBG_CONTROL,
	DBG_log("RSA key flags: sign = %s, decrypt = %s"
	    , (sign_flag)?    "true":"false"
	    , (decrypt_flag)? "true":"false")
    )

    if (sign_flag)
    {
	CK_MECHANISM mech  = { CKM_RSA_PKCS, NULL_PTR, 0 };

	rv = pkcs11_functions->C_SignInit(sc->session, &mech, object);
	if (rv != CKR_OK)
	{
	    plog("error in C_SignInit: %s"
		, enum_show(&pkcs11_return_names, rv));
	    return FALSE;
	}

	rv = pkcs11_functions->C_Sign(sc->session, (CK_BYTE_PTR)in, inlen
		, out, &siglen);
	if (rv != CKR_OK)
	{
	    plog("error in C_Sign: %s"
		, enum_show(&pkcs11_return_names, rv));
	    return FALSE;
    	}
    }
    else if (decrypt_flag)
    {
	CK_MECHANISM mech = { CKM_RSA_X_509, NULL_PTR, 0 };
	size_t padlen;
	u_char *p = out ;

	/* PKCS#1 v1.5 8.1 encryption-block formatting */
	*p++ = 0x00;
	*p++ = 0x01;	/* BT (block type) 01 */
	padlen = outlen - 3 - inlen;
	memset(p, 0xFF, padlen);
	p += padlen;
	*p++ = 0x00;
	memcpy(p, in, inlen);

	rv = pkcs11_functions->C_DecryptInit(sc->session, &mech, object);
	if (rv != CKR_OK)
	{
	    plog("error in C_DecryptInit: %s"
	        , enum_show(&pkcs11_return_names, rv));
	    return FALSE;
        }

        rv = pkcs11_functions->C_Decrypt(sc->session, out, outlen
		, out, &siglen);
	if (rv != CKR_OK)
        {
	    plog("error in C_Decrypt: %s"
	        , enum_show(&pkcs11_return_names, rv));
	    return FALSE;
        }
    }
    else
    {
	plog("private key has neither sign nor decrypt flag set");
	return FALSE;
    }

    if (siglen > (CK_ULONG)outlen)
    {
	plog("signature length (%lu) larger than allocated buffer (%d)"
	    , siglen, (int)outlen);
	return FALSE;
    }
    return TRUE;
#else
    return FALSE;
#endif
}

/* 
 * encrypt data block with an RSA public key
 */
bool
scx_encrypt(smartcard_t *sc, const u_char *in, size_t inlen
, u_char *out, size_t *outlen)
{
#ifdef SMARTCARD
    CK_RV rv;
    CK_OBJECT_HANDLE object;
    CK_ULONG len = (CK_ULONG)(*outlen);
    CK_BBOOL encrypt_flag;
    CK_ATTRIBUTE attr[] = {
	{ CKA_MODULUS,         NULL_PTR, 0L },
	{ CKA_PUBLIC_EXPONENT, NULL_PTR, 0L },
	{ CKA_ENCRYPT,         &encrypt_flag, sizeof(encrypt_flag) }
    };
    CK_MECHANISM mech = { CKM_RSA_PKCS, NULL_PTR, 0 };

    if (!scx_establish_context(sc))
    {
	scx_release_context(sc);
	    return FALSE;
    }

    if (!scx_pkcs11_find_object(sc->session, &object, CKO_PUBLIC_KEY, sc->id))
    {
	plog("unable to find public key with id '%s'", sc->id);
	return FALSE;
    }

    rv = pkcs11_functions->C_GetAttributeValue(sc->session, object, attr, 3);
    if (rv != CKR_OK)
    {
	plog("couldn't read the public key attributes: %s"
	    , enum_show(&pkcs11_return_names, rv));
	scx_release_context(sc);
	return FALSE;
    }

    if (!encrypt_flag)
    {
	plog("public key cannot be used for encryption");
	scx_release_context(sc);
	return FALSE;
    }
	
    /* there must be enough space left for the PKCS#1 v1.5 padding */
    if (inlen > attr[0].ulValueLen - 11)
    {
	plog("smartcard input data length (%d) exceeds maximum of %lu bytes"
		, (int)inlen, attr[0].ulValueLen - 11);
	if (!pkcs11_keep_state)
	    scx_release_context(sc);
	return FALSE;
    }

    rv = pkcs11_functions->C_EncryptInit(sc->session, &mech, object);

    if (rv != CKR_OK)
    {
	if (rv == CKR_FUNCTION_NOT_SUPPORTED)
	{
	    RSA_public_key_t rsa;
	    chunk_t plain_text = {(u_char*)in, inlen};
	    chunk_t cipher_text; 

	    DBG(DBG_CONTROL,
		DBG_log("doing RSA encryption in software")
	    )
	    attr[0].pValue = malloc(attr[0].ulValueLen);
	    attr[1].pValue = malloc(attr[1].ulValueLen);

	    rv = pkcs11_functions->C_GetAttributeValue(sc->session, object, attr, 2);
	    if (rv != CKR_OK)
	    {
		plog("couldn't read modulus and public exponent: %s"
		    , enum_show(&pkcs11_return_names, rv));
		free(attr[0].pValue);
		free(attr[1].pValue);
		scx_release_context(sc);
		return FALSE;
	    }
	    rsa.k = attr[0].ulValueLen;
	    n_to_mpz(&rsa.n, attr[0].pValue, attr[0].ulValueLen);
	    n_to_mpz(&rsa.e, attr[1].pValue, attr[1].ulValueLen);
	    free(attr[0].pValue);
	    free(attr[1].pValue);

	    cipher_text = RSA_encrypt(&rsa, plain_text);
	    free_RSA_public_content(&rsa);
	    if (cipher_text.ptr == NULL)
	    {
		plog("smartcard input data length is too large");
		if (!pkcs11_keep_state)
		    scx_release_context(sc);
	        return FALSE;
	    }

	    memcpy(out, cipher_text.ptr, cipher_text.len);
	    *outlen = cipher_text.len;
	    freeanychunk(cipher_text);
	    if (!pkcs11_keep_state)
		scx_release_context(sc);
	    return TRUE;
	}
	else
	{
	    plog("error in C_EncryptInit: %s"
		, enum_show(&pkcs11_return_names, rv));
	    scx_release_context(sc);
	    return FALSE;
	}
    }

    DBG(DBG_CONTROL,
	DBG_log("doing RSA encryption on smartcard")
    )
    rv = pkcs11_functions->C_Encrypt(sc->session, (u_char*)in, inlen
		, out, &len);
    if (rv != CKR_OK)
    {
	plog("error in C_Encrypt: %s"
	    , enum_show(&pkcs11_return_names, rv));
	scx_release_context(sc);
	return FALSE;
    }
    if (!pkcs11_keep_state)
	scx_release_context(sc);

    *outlen = (size_t)len;
    return TRUE;
#else
    return FALSE;
#endif
}
/* 
 * decrypt a data block with an RSA private key
 */
bool
scx_decrypt(smartcard_t *sc, const u_char *in, size_t inlen
, u_char *out, size_t *outlen)
{
#ifdef SMARTCARD
    CK_RV rv;
    CK_OBJECT_HANDLE object;
    CK_ULONG len = (CK_ULONG)(*outlen);
    CK_BBOOL decrypt_flag;
    CK_ATTRIBUTE attr[] = {
	{ CKA_DECRYPT, &decrypt_flag, sizeof(decrypt_flag) }
    };
    CK_MECHANISM mech = { CKM_RSA_PKCS, NULL_PTR, 0 };

    if (!scx_establish_context(sc) || !scx_login(sc))
    {
	scx_release_context(sc);
	    return FALSE;
    }

    if (!scx_pkcs11_find_object(sc->session, &object, CKO_PRIVATE_KEY, sc->id))
    {
	plog("unable to find private key with id '%s'", sc->id);
	return FALSE;
    }

    rv = pkcs11_functions->C_GetAttributeValue(sc->session, object, attr, 1);
    if (rv != CKR_OK)
    {
	plog("couldn't read the private key attributes: %s"
	    , enum_show(&pkcs11_return_names, rv));
	return FALSE;
    }

    if (!decrypt_flag)
    {
	plog("private key cannot be used for decryption");
	scx_release_context(sc);
	return FALSE;
    }
	
    DBG(DBG_CONTROL,
	DBG_log("doing RSA decryption on smartcard")
    )
    rv = pkcs11_functions->C_DecryptInit(sc->session, &mech, object);
    if (rv != CKR_OK)
    {
	plog("error in C_DecryptInit: %s"
	    , enum_show(&pkcs11_return_names, rv));
	scx_release_context(sc);
	return FALSE;
    }

    rv = pkcs11_functions->C_Decrypt(sc->session, (u_char*)in, inlen
		, out, &len);
    if (rv != CKR_OK)
    {
	plog("error in C_Decrypt: %s"
	    , enum_show(&pkcs11_return_names, rv));
	scx_release_context(sc);
	return FALSE;
    }
    if (!pkcs11_keep_state)
	scx_release_context(sc);

    *outlen = (size_t)len;
    return TRUE;
#else
    return FALSE;
#endif
}

/* receive an encrypted data block via whack,
 * decrypt it using a private RSA key and
 * return the decrypted data block via whack
 */
bool
scx_op_via_whack(const char* msg, int inbase, int outbase, sc_op_t op
, const char* keyid, int whackfd)
{
    char inbuf[RSA_MAX_OCTETS];
    char outbuf[2*RSA_MAX_OCTETS + 1];
    size_t outlen = sizeof(inbuf);
    size_t inlen;
    smartcard_t *sc,*sc_new;

    const char *number_slot_id = "";

    err_t ugh = ttodata(msg, 0, inbase, inbuf, sizeof(inbuf), &inlen);

    /* no prefix - use default base */
    if (ugh != NULL  && inbase == 0)
       ugh = ttodata(msg, 0, DEFAULT_BASE, inbuf, sizeof(inbuf), &inlen);

    if (ugh != NULL)
    {
	plog("format error in smartcard input data: %s", ugh);
	return FALSE;
    }

    if (keyid != NULL)
    {
	number_slot_id = (strneq(keyid, SCX_TOKEN, strlen(SCX_TOKEN)))
			 ? keyid + strlen(SCX_TOKEN) : keyid;
    }

    sc_new = scx_parse_number_slot_id(number_slot_id);
    sc = scx_add(sc_new);
    if (sc == sc_new)
	scx_share(sc);

    DBG((op == SC_OP_ENCRYPT)? DBG_PRIVATE:DBG_RAW,
	DBG_dump("smartcard input data:\n", inbuf, inlen)
    )

    if (op == SC_OP_DECRYPT)
    {
	if (!sc->valid && whackfd != NULL_FD)
	    scx_get_pin(sc, whackfd);

	if (!sc->valid)
	{
	    loglog(RC_NOVALIDPIN, "cannot decrypt without valid PIN");
	    return FALSE;
        }
    }

    DBG(DBG_CONTROL | DBG_CRYPT,
	DBG_log("using RSA key from smartcard (slot: %d, id: %s)"
	    , (int)sc->slot, sc->id)
    )

    switch (op)
    {
    case SC_OP_ENCRYPT:
	if (!scx_encrypt(sc, inbuf, inlen, inbuf, &outlen))
	    return FALSE;
	break;
    case SC_OP_DECRYPT:
	if (!scx_decrypt(sc, inbuf, inlen, inbuf, &outlen))
	    return FALSE;
	break;
    default:
	break;
    }

    DBG((op == SC_OP_DECRYPT)? DBG_PRIVATE:DBG_RAW,
	DBG_dump("smartcard output data:\n", inbuf, outlen)
    )

    if (outbase == 0)  /* use default base */ 
	outbase = DEFAULT_BASE;

    if (outbase == 256) /* ascii plain text */
	whack_log(RC_COMMENT, "%.*s", (int)outlen, inbuf);
    else
    {
	outlen = datatot(inbuf, outlen, outbase, outbuf, sizeof(outbuf));
	if (outlen == 0)
	{
	    plog("error in output format conversion");
	    return FALSE;
	}
    	whack_log(RC_COMMENT, "%s", outbuf);
    }
    return TRUE;
}

 /*
 * get length of RSA key in bytes
 */
size_t
scx_get_keylength(smartcard_t *sc)
{
#ifdef SMARTCARD
    CK_RV rv;
    CK_OBJECT_HANDLE object;
    CK_ATTRIBUTE attr[] = {{ CKA_MODULUS, NULL_PTR, 0}};

    if (!sc->logged_in)
    	return FALSE;

    if (!scx_pkcs11_find_object(sc->session, &object, CKO_PRIVATE_KEY, sc->id))
    {
	plog("unable to find private key with id '%s'", sc->id);
	return FALSE;
    }

    /* get the length of the private key */
    rv = pkcs11_functions->C_GetAttributeValue(sc->session, object
		, (CK_ATTRIBUTE_PTR)&attr, 1);
    if (rv != CKR_OK)
    {
	plog("failed to get key length: %s"
	    , enum_show(&pkcs11_return_names, rv));
	return FALSE;
    }

    return attr[0].ulValueLen;	/*Return key length in bytes */
#else
    return 0;
#endif
}

/*
 * prompt for pin and verify it
 */
bool
scx_get_pin(smartcard_t *sc, int whackfd)
{
#ifdef SMARTCARD
    char pin[BUF_LEN];
    int i, n;

    whack_log(RC_ENTERSECRET, "need PIN for #%d (%s, id: %s, label: '%s')"
	, sc->number, scx_print_slot(sc, ""), sc->id, sc->label);

    for (i = 0; i < SCX_MAX_PIN_TRIALS; i++)
    {
	if (i > 0)
	    whack_log(RC_ENTERSECRET, "invalid PIN, please try again");

	n = read(whackfd, pin, BUF_LEN);

	if (n == -1)
	{
	    whack_log(RC_LOG_SERIOUS, "read(whackfd) failed");
	    return FALSE;
	}

	if (strlen(pin) == 0)
	{
	    whack_log(RC_LOG_SERIOUS, "no PIN entered, aborted");
	    return FALSE;
	}

	sc->pin.ptr = pin;
	sc->pin.len = strlen(pin);

	/* verify the pin */
	if (scx_verify_pin(sc))
	{
	    clonetochunk(sc->pin, pin, strlen(pin));
	    break;
	}

	/* wrong pin - we try another round */
	sc->pin = chunk_empty;
    }

    if (sc->valid)
	whack_log(RC_SUCCESS, "valid PIN");
    else
	whack_log(RC_LOG_SERIOUS, "invalid PIN, too many trials");
#else
    sc->valid = FALSE;
    whack_log(RC_LOG_SERIOUS, "SMARTCARD support is deactivated in pluto/Makefile!");
#endif
    return sc->valid;
}


/*
 * free the pin code
 */
void
scx_free_pin(chunk_t *pin)
{
    if (pin->ptr != NULL)
    {
	/* clear pin field in memory */
	memset(pin->ptr, '\0', pin->len);
	free(pin->ptr);
	*pin = chunk_empty;
    }
}

/*
 * frees a smartcard record
 */
void
scx_free(smartcard_t *sc)
{
    if (sc != NULL)
    {
	scx_release_context(sc);
	free(sc->id);
	free(sc->label);
	scx_free_pin(&sc->pin);
	free(sc);
    }
}

/*  release of a smartcard record decreases the count by one
 "  the record is freed when the counter reaches zero
 */
void
scx_release(smartcard_t *sc)
{
    if (sc != NULL && --sc->count == 0)
    {
	smartcard_t **pp = &smartcards;
	while (*pp != sc)
	    pp = &(*pp)->next;
        *pp = sc->next;
	release_cert(sc->last_cert);
	scx_free(sc);
    }
}

/*
 *  compare two smartcard records by comparing their slots and ids
 */
static bool
scx_same(smartcard_t *a, smartcard_t *b)
{
    if  (a->number && b->number)
    {
	/* same number */
	return a->number == b->number;
    }
    else
    {
	/* same id and/or same slot */
        return (!a->id || (b->id && streq(a->id, b->id)))
	    && (a->any_slot || b->any_slot || a->slot == b->slot);
    }
}

/*  for each link pointing to the smartcard record
 "  increase the count by one
 */
void
scx_share(smartcard_t *sc)
{
    if (sc != NULL)
 	sc->count++;
}

/*
 *  adds a smartcard record to the chained list
 */
smartcard_t*
scx_add(smartcard_t *smartcard)
{
    smartcard_t *sc = smartcards;
    smartcard_t **psc = &smartcards;

    while (sc != NULL)
    {
	if (scx_same(smartcard, sc)) /* already in chain, free smartcard record */
	{
	    scx_free(smartcard);
	    return sc;
	}
        psc = &sc->next;
	sc = sc->next;
    }

    /* insert new smartcard record at the end of the chain */
    *psc = smartcard;
    smartcard->number = ++sc_number;
    smartcard->count = 1;
    DBG(DBG_CONTROL | DBG_PARSING,
	DBG_log("  smartcard #%d added", sc_number)
    )
    return smartcard;
}

/*
 * get the smartcard that belongs to an X.509 certificate
 */
smartcard_t*
scx_get(x509cert_t *cert)
{
    smartcard_t *sc = smartcards;

    while (sc != NULL)
    {
	if (sc->last_cert.u.x509 == cert)
	    return sc;
	sc = sc->next;
    }
    return NULL;
}

/*
 * prints either the slot number or 'any slot'
 */
char *
scx_print_slot(smartcard_t *sc, const char *whitespace)
{
    char *buf = temporary_cyclic_buffer();

    if (sc->any_slot)
	snprintf(buf, BUF_LEN, "any slot");
    else
	snprintf(buf, BUF_LEN, "slot: %s%lu", whitespace, sc->slot);
    return buf;
}

/*
 *  list all smartcard info records in a chained list
 */
void
scx_list(bool utc)
{
    smartcard_t *sc = smartcards;

    if (sc != NULL)
    {
	whack_log(RC_COMMENT, " ");
	whack_log(RC_COMMENT, "List of Smartcard Objects:");
	whack_log(RC_COMMENT, " ");
    }

    while (sc != NULL)
    {
	whack_log(RC_COMMENT, "%s, #%d, count: %d"
	    , timetoa(&sc->last_load, utc)
	    , sc->number
	    , sc->count);
	whack_log(RC_COMMENT, "       %s, session %s, logged %s, has %s"
	    , scx_print_slot(sc, "    ")
	    , sc->session_opened? "opened" : "closed"
	    , sc->logged_in? "in" : "out"
	    , sc->pinpad? "pin pad" 
		: ((sc->pin.ptr == NULL)? "no pin"
		    : sc->valid? "valid pin" : "invalid pin"));
	if (sc->id != NULL)
	    whack_log(RC_COMMENT, "       id:       %s", sc->id);
	if (sc->label != NULL)
	    whack_log(RC_COMMENT, "       label:   '%s'", sc->label);
	if (sc->last_cert.type == CERT_X509_SIGNATURE)
	{
	    char buf[BUF_LEN];

	    dntoa(buf, BUF_LEN, sc->last_cert.u.x509->subject);
	    whack_log(RC_COMMENT, "       subject: '%s'", buf);
	}
	sc = sc->next;
    }
}
