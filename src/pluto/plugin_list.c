/*
 * Copyright (C) 2011 Martin Willi, revosec AG
 * Copyright (C) 2011 Andreas Steffen, HSR Hochschule fuer Technik Rapperswil
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

#include <whack.h>
#include <log.h>

#include <library.h>
#include <utils/linked_list.h>

/**
 * List loaded plugin information
 */
void plugin_list(void)
{
	plugin_feature_t *features, *fp;
	enumerator_t *enumerator;
	linked_list_t *list;
	plugin_t *plugin;
	int count, i;
	bool loaded;
	char *str;

	whack_log(RC_COMMENT, " ");
	whack_log(RC_COMMENT, "List of loaded Plugins:");
	whack_log(RC_COMMENT, " ");

	enumerator = lib->plugins->create_plugin_enumerator(lib->plugins);
	while (enumerator->enumerate(enumerator, &plugin, &list))
	{
		whack_log(RC_COMMENT, "%s:", plugin->get_name(plugin));
		if (plugin->get_features)
		{
			count = plugin->get_features(plugin, &features);
			for (i = 0; i < count; i++)
			{
				str = plugin_feature_get_string(&features[i]);
				switch (features[i].kind)
				{
					case FEATURE_PROVIDE:
						fp = &features[i];
						loaded = list->find_first(list, NULL,
												  (void**)&fp) == SUCCESS;
						whack_log(RC_COMMENT, "    %s%s",
								  str, loaded ? "" : " (not loaded)");
						break;
					case FEATURE_DEPENDS:
						whack_log(RC_COMMENT, "        %s", str);
						break;
					case FEATURE_SDEPEND:
						whack_log(RC_COMMENT, "        %s(soft)", str);
						break;
					default:
						break;
				}
				free(str);
			}
		}
	}
	enumerator->destroy(enumerator);
}
