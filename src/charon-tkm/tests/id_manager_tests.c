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

#include <stdlib.h>
#include <check.h>

#include "tkm_id_manager.h"

START_TEST(test_id_mgr_creation)
{
	tkm_id_manager_t *idmgr = NULL;

	idmgr = tkm_id_manager_create();
	fail_if(idmgr == NULL, "Error creating tkm id manager");

	idmgr->destroy(idmgr);
}
END_TEST

START_TEST(test_acquire_id)
{
	int i, id = 0;
	tkm_id_manager_t *idmgr = tkm_id_manager_create();

	for (i = 0; i < TKM_CTX_MAX; i++)
	{
		id = idmgr->acquire_id(idmgr, i);
		fail_unless(id > 0, "Error acquiring id of context kind %d", i);

		/* Reset test variable */
		id = 0;
	}

	idmgr->destroy(idmgr);
}
END_TEST

START_TEST(test_acquire_id_invalid_kind)
{
	int id = 0;
	tkm_id_manager_t *idmgr = tkm_id_manager_create();

	id = idmgr->acquire_id(idmgr, TKM_CTX_MAX);
	fail_unless(id == 0, "Acquired id for invalid context kind %d", TKM_CTX_MAX);

	/* Reset test variable */
	id = 0;

	id = idmgr->acquire_id(idmgr, -1);
	fail_unless(id == 0, "Acquired id for invalid context kind %d", -1);

	idmgr->destroy(idmgr);
}
END_TEST

START_TEST(test_release_id)
{
	int i, id = 0;
	bool released = false;
	tkm_id_manager_t *idmgr = tkm_id_manager_create();

	for (i = 0; i < TKM_CTX_MAX; i++)
	{
		id = idmgr->acquire_id(idmgr, i);
		released = idmgr->release_id(idmgr, i, id);

		fail_unless(released, "Error releasing id of context kind %d", i);

		/* Reset released variable */
		released = FALSE;
	}

	idmgr->destroy(idmgr);
}
END_TEST

START_TEST(test_release_id_invalid_kind)
{
	bool released = TRUE;
	tkm_id_manager_t *idmgr = tkm_id_manager_create();

	released = idmgr->release_id(idmgr, TKM_CTX_MAX, 1);
	fail_if(released, "Released id for invalid context kind %d", TKM_CTX_MAX);

	/* Reset test variable */
	released = TRUE;

	released = idmgr->release_id(idmgr, -1, 1);
	fail_if(released, "Released id for invalid context kind %d", -1);

	idmgr->destroy(idmgr);
}
END_TEST

START_TEST(test_release_id_nonexistent)
{
	bool released = FALSE;
	tkm_id_manager_t *idmgr = tkm_id_manager_create();

	released = idmgr->release_id(idmgr, TKM_CTX_NONCE, 1);
	fail_unless(released, "Release of nonexistent id failed");

	idmgr->destroy(idmgr);
}
END_TEST

TCase *make_id_manager_tests(void)
{
	TCase *tc = tcase_create("Context id manager tests");
	tcase_add_test(tc, test_id_mgr_creation);
	tcase_add_test(tc, test_acquire_id);
	tcase_add_test(tc, test_acquire_id_invalid_kind);
	tcase_add_test(tc, test_release_id);
	tcase_add_test(tc, test_release_id_invalid_kind);
	tcase_add_test(tc, test_release_id_nonexistent);

	return tc;
}
