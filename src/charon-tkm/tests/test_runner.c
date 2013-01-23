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

#include <library.h>
#include <hydra.h>
#include <daemon.h>

#include "tkm.h"
#include "tkm_nonceg.h"
#include "tkm_diffie_hellman.h"
#include "tkm_kernel_ipsec.h"
#include "test_runner.h"

int main(void)
{
	library_init(NULL);
	libhydra_init("test_runner");
	libcharon_init("test_runner");

	lib->settings->set_int(lib->settings, "test_runner.filelog.stdout.default",
						   1);
	charon->load_loggers(charon, NULL, FALSE);

	/* Register TKM specific plugins */
	static plugin_feature_t features[] = {
		PLUGIN_REGISTER(NONCE_GEN, tkm_nonceg_create),
			PLUGIN_PROVIDE(NONCE_GEN),
		PLUGIN_REGISTER(DH, tkm_diffie_hellman_create),
			PLUGIN_PROVIDE(DH, MODP_3072_BIT),
			PLUGIN_PROVIDE(DH, MODP_4096_BIT),
		PLUGIN_CALLBACK(kernel_ipsec_register, tkm_kernel_ipsec_create),
			PLUGIN_PROVIDE(CUSTOM, "kernel-ipsec"),
	};
	lib->plugins->add_static_features(lib->plugins, "tkm-tests", features,
			countof(features), TRUE);

	if (!charon->initialize(charon, PLUGINS))
	{
		fprintf(stderr, "Unable to init charon");
		return EXIT_FAILURE;
	}

	if (!tkm_init())
	{
		fprintf(stderr, "Could not connect to TKM, aborting tests\n");
		return EXIT_FAILURE;
	}

	int number_failed;
	Suite *s = suite_create("TKM tests");
	suite_add_tcase(s, make_id_manager_tests());
	suite_add_tcase(s, make_chunk_map_tests());
	suite_add_tcase(s, make_utility_tests());
	suite_add_tcase(s, make_nonceg_tests());
	suite_add_tcase(s, make_diffie_hellman_tests());
	suite_add_tcase(s, make_keymat_tests());
	suite_add_tcase(s, make_kernel_sad_tests());

	SRunner *sr = srunner_create(s);

	srunner_run_all(sr, CK_NORMAL);
	number_failed = srunner_ntests_failed(sr);

	tkm_deinit();
	libcharon_deinit();
	libhydra_deinit();
	library_deinit();
	srunner_free(sr);

	return (number_failed == 0) ? EXIT_SUCCESS : EXIT_FAILURE;
}
