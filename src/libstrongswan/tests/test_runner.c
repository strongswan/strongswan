/*
 * Copyright (C) 2013 Tobias Brunner
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

#include <unistd.h>

#include "test_runner.h"

#include <library.h>
#include <plugins/plugin_feature.h>

#include <dirent.h>

/**
 * Load plugins from builddir
 */
static bool load_plugins()
{
	enumerator_t *enumerator;
	char *name, path[PATH_MAX], dir[64];

	enumerator = enumerator_create_token(PLUGINS, " ", "");
	while (enumerator->enumerate(enumerator, &name))
	{
		snprintf(dir, sizeof(dir), "%s", name);
		translate(dir, "-", "_");
		snprintf(path, sizeof(path), "%s/%s/.libs", PLUGINDIR, dir);
		lib->plugins->add_path(lib->plugins, path);
	}
	enumerator->destroy(enumerator);

	return lib->plugins->load(lib->plugins, PLUGINS);
}

int main()
{
	SRunner *sr;
	int nf;

	/* test cases are forked and there is no cleanup, so disable leak detective.
	 * if test_suite.h is included leak detective is enabled in test cases */
	setenv("LEAK_DETECTIVE_DISABLE", "1", 1);
	/* redirect all output to stderr (to redirect make's stdout to /dev/null) */
	dup2(2, 1);

	library_init(NULL);

	/* use non-blocking RNG to generate keys fast */
	lib->settings->set_default_str(lib->settings,
			"libstrongswan.plugins.random.random",
			lib->settings->get_str(lib->settings,
				"libstrongswan.plugins.random.urandom", "/dev/urandom"));

	if (!load_plugins())
	{
		library_deinit();
		return EXIT_FAILURE;
	}
	lib->plugins->status(lib->plugins, LEVEL_CTRL);

	sr = srunner_create(NULL);
	srunner_add_suite(sr, bio_reader_suite_create());
	srunner_add_suite(sr, bio_writer_suite_create());
	srunner_add_suite(sr, chunk_suite_create());
	srunner_add_suite(sr, enum_suite_create());
	srunner_add_suite(sr, enumerator_suite_create());
	srunner_add_suite(sr, linked_list_suite_create());
	srunner_add_suite(sr, linked_list_enumerator_suite_create());
	srunner_add_suite(sr, hashtable_suite_create());
	srunner_add_suite(sr, array_suite_create());
	srunner_add_suite(sr, identification_suite_create());
	srunner_add_suite(sr, threading_suite_create());
	srunner_add_suite(sr, utils_suite_create());
	srunner_add_suite(sr, host_suite_create());
	srunner_add_suite(sr, vectors_suite_create());
	srunner_add_suite(sr, printf_suite_create());
	if (lib->plugins->has_feature(lib->plugins,
								  PLUGIN_DEPENDS(PRIVKEY_GEN, KEY_RSA)))
	{
		srunner_add_suite(sr, rsa_suite_create());
	}
	if (lib->plugins->has_feature(lib->plugins,
								  PLUGIN_DEPENDS(PRIVKEY_GEN, KEY_ECDSA)))
	{
		srunner_add_suite(sr, ecdsa_suite_create());
	}

	srunner_run_all(sr, CK_NORMAL);
	nf = srunner_ntests_failed(sr);

	srunner_free(sr);
	library_deinit();

	return (nf == 0) ? EXIT_SUCCESS : EXIT_FAILURE;
}
