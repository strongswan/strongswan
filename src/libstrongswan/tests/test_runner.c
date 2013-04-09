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

/**
 * Check if the plugin configuration provides a specific feature
 */
static bool has_feature(plugin_feature_t feature)
{
	enumerator_t *plugins, *features;
	plugin_t *plugin;
	linked_list_t *list;
	plugin_feature_t *current;
	bool found = FALSE;

	plugins = lib->plugins->create_plugin_enumerator(lib->plugins);
	while (plugins->enumerate(plugins, &plugin, &list))
	{
		features = list->create_enumerator(list);
		while (features->enumerate(features, &current))
		{
			if (plugin_feature_matches(&feature, current))
			{
				found = TRUE;
				break;
			}
		}
		features->destroy(features);
		list->destroy(list);
	}
	plugins->destroy(plugins);

	return found;
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

	if (!lib->plugins->load(lib->plugins, NULL, PLUGINS))
	{
		library_deinit();
		return EXIT_FAILURE;
	}

	sr = srunner_create(NULL);
	srunner_add_suite(sr, bio_reader_suite_create());
	srunner_add_suite(sr, bio_writer_suite_create());
	srunner_add_suite(sr, chunk_suite_create());
	srunner_add_suite(sr, enum_suite_create());
	srunner_add_suite(sr, enumerator_suite_create());
	srunner_add_suite(sr, linked_list_suite_create());
	srunner_add_suite(sr, linked_list_enumerator_suite_create());
	srunner_add_suite(sr, hashtable_suite_create());
	srunner_add_suite(sr, identification_suite_create());
	srunner_add_suite(sr, threading_suite_create());
	srunner_add_suite(sr, utils_suite_create());
	srunner_add_suite(sr, vectors_suite_create());

	srunner_run_all(sr, CK_NORMAL);
	nf = srunner_ntests_failed(sr);

	srunner_free(sr);
	library_deinit();

	return (nf == 0) ? EXIT_SUCCESS : EXIT_FAILURE;
}
