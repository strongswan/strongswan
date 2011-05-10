/*
 * Copyright (C) 2010 Andreas Steffen
 * HSR Hochschule fuer Technik Rapperswil
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

#include "tnc_imv_plugin.h"
#include "tnc_imv_manager.h"
#include "tnc_imv.h"

#include <sys/types.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>

#include <daemon.h>
#include <utils/lexparser.h>

/**
 * load IMVs from a configuration file
 */
static bool load_imvs(char *filename)
{
	int fd, line_nr = 0;
	chunk_t src, line;
	struct stat sb;
	void *addr;

	DBG1(DBG_TNC, "loading IMVs from '%s'", filename);
	fd = open(filename, O_RDONLY);
	if (fd == -1)
	{
		DBG1(DBG_TNC, "opening configuration file '%s' failed: %s", filename,
			 strerror(errno));
		return FALSE;
	}
	if (fstat(fd, &sb) == -1)
	{
		DBG1(DBG_LIB, "getting file size of '%s' failed: %s", filename,
			 strerror(errno));
		close(fd);
		return FALSE;
	}
	addr = mmap(NULL, sb.st_size, PROT_READ | PROT_WRITE, MAP_PRIVATE, fd, 0);
	if (addr == MAP_FAILED)
	{
		DBG1(DBG_LIB, "mapping '%s' failed: %s", filename, strerror(errno));
		close(fd);
		return FALSE;
	}
	src = chunk_create(addr, sb.st_size);

	while (fetchline(&src, &line))
	{
		char *name, *path;
		chunk_t token;
		imv_t *imv;

		line_nr++;

		/* skip comments or empty lines */
		if (*line.ptr == '#' || !eat_whitespace(&line))
		{
			continue;
		}

		/* determine keyword */
		if (!extract_token(&token, ' ', &line))
		{
			DBG1(DBG_TNC, "line %d: keyword must be followed by a space",
						   line_nr);
			return FALSE;
		}

		/* only interested in IMVs */
		if (!match("IMV", &token))
		{
			continue;
		}

		/* advance to the IMV name and extract it */
		if (!extract_token(&token, '"', &line) ||
			!extract_token(&token, '"', &line))
		{
			DBG1(DBG_TNC, "line %d: IMV name must be set in double quotes",
						   line_nr);
			return FALSE;
		}

		/* copy the IMV name */
		name = malloc(token.len + 1);
		memcpy(name, token.ptr, token.len);
		name[token.len] = '\0';

		/* advance to the IMV path and extract it */
		if (!eat_whitespace(&line))
		{
			DBG1(DBG_TNC, "line %d: IMV path is missing", line_nr);
			free(name);
			return FALSE;
		}
		if (!extract_token(&token, ' ', &line))
		{
			token = line;
		}

		/* copy the IMV path */
		path = malloc(token.len + 1);
		memcpy(path, token.ptr, token.len);
		path[token.len] = '\0';

		/* load and register IMV instance */
		imv = tnc_imv_create(name, path);
		if (!imv)
		{
			free(name);
			free(path);
			return FALSE;
		}
		if (!charon->imvs->add(charon->imvs, imv))
		{
			if (imv->terminate &&
				imv->terminate(imv->get_id(imv)) != TNC_RESULT_SUCCESS)
			{
				DBG1(DBG_TNC, "IMV \"%s\" not terminated successfully",
							   imv->get_name(imv));
			}
			imv->destroy(imv);
			return FALSE;
		}
		DBG1(DBG_TNC, "IMV %u \"%s\" loaded from '%s'", imv->get_id(imv),
														name, path);
	}
	munmap(addr, sb.st_size);
	close(fd);
	return TRUE;
}

METHOD(plugin_t, get_name, char*,
	tnc_imv_plugin_t *this)
{
	return "tnc-imv";
}

METHOD(plugin_t, destroy, void,
	tnc_imv_plugin_t *this)
{
	charon->imvs->destroy(charon->imvs);
	free(this);
}

/*
 * see header file
 */
plugin_t *tnc_imv_plugin_create()
{
	char *tnc_config;
	tnc_imv_plugin_t *this;

	INIT(this,
		.plugin = {
			.get_name = _get_name,
			.reload = (void*)return_false,
			.destroy = _destroy,
		},
	);

	tnc_config = lib->settings->get_str(lib->settings,
					"charon.plugins.tnc-imv.tnc_config", "/etc/tnc_config");

	/* Create IMV manager */
	charon->imvs = tnc_imv_manager_create();

	/* Load IMVs and abort if not all instances initalize successfully */
	if (!load_imvs(tnc_config))
	{
		charon->imvs->destroy(charon->imvs);
		charon->imvs = NULL;
		free(this);
		return NULL;
	}
	return &this->plugin;
}

