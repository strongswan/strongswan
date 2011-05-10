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

#include "tnc_imc_plugin.h"
#include "tnc_imc_manager.h"
#include "tnc_imc.h"

#include <sys/types.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>

#include <daemon.h>
#include <utils/lexparser.h>

/**
 * load IMCs from a configuration file
 */
static bool load_imcs(char *filename)
{
	int fd, line_nr = 0;
	chunk_t src, line;
	struct stat sb;
	void *addr;

	DBG1(DBG_TNC, "loading IMCs from '%s'", filename);
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
		imc_t *imc;

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

		/* only interested in IMCs */
		if (!match("IMC", &token))
		{
			continue;
		}

		/* advance to the IMC name and extract it */
		if (!extract_token(&token, '"', &line) ||
			!extract_token(&token, '"', &line))
		{
			DBG1(DBG_TNC, "line %d: IMC name must be set in double quotes",
						   line_nr);
			return FALSE;
		}

		/* copy the IMC name */
		name = malloc(token.len + 1);
		memcpy(name, token.ptr, token.len);
		name[token.len] = '\0';

		/* advance to the IMC path and extract it */
		if (!eat_whitespace(&line))
		{
			DBG1(DBG_TNC, "line %d: IMC path is missing", line_nr);
			free(name);
			return FALSE;
		}
		if (!extract_token(&token, ' ', &line))
		{
			token = line;
		}

		/* copy the IMC path */
		path = malloc(token.len + 1);
		memcpy(path, token.ptr, token.len);
		path[token.len] = '\0';

		/* load and register IMC instance */
		imc = tnc_imc_create(name, path);
		if (!imc)
		{
			free(name);
			free(path);
			return FALSE;
		}
		if (!charon->imcs->add(charon->imcs, imc))
		{
			if (imc->terminate &&
				imc->terminate(imc->get_id(imc)) != TNC_RESULT_SUCCESS)
			{
				DBG1(DBG_TNC, "IMC \"%s\" not terminated successfully",
							   imc->get_name(imc));
			}
			imc->destroy(imc);
			return FALSE;
		}
		DBG1(DBG_TNC, "IMC %u \"%s\" loaded from '%s'", imc->get_id(imc),
														name, path);
	}
	munmap(addr, sb.st_size);
	close(fd);
	return TRUE;
}

METHOD(plugin_t, get_name, char*,
	tnc_imc_plugin_t *this)
{
	return "tnc-imc";
}

METHOD(plugin_t, destroy, void,
	tnc_imc_plugin_t *this)
{
	charon->imcs->destroy(charon->imcs);
	free(this);
}

/*
 * see header file
 */
plugin_t *tnc_imc_plugin_create()
{
	char *tnc_config;
	tnc_imc_plugin_t *this;

	INIT(this,
		.plugin = {
			.get_name = _get_name,
				.reload = (void*)return_false,
			.destroy = _destroy,
		},
	);

	/* Create IMC manager */
	charon->imcs = tnc_imc_manager_create();

	/* Load IMCs and abort if not all instances initalize successfully */
	tnc_config = lib->settings->get_str(lib->settings,
					"charon.plugins.tnc-imc.tnc_config", "/etc/tnc_config");
	if (!load_imcs(tnc_config))
	{
		charon->imcs->destroy(charon->imcs);
		charon->imcs = NULL;
		free(this);
		return NULL;
	}
	return &this->plugin;
}

