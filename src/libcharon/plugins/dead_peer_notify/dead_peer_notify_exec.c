/* vim: set ts=4 sw=4 noexpandtab: */
/*
 * Copyright (C) 2015 Pavel Balaev.
 * Copyright (C) 2015 InfoTeCS JSC.
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

#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <sys/stat.h>

#include <daemon.h>
#include "dead_peer_notify_exec.h"

typedef struct private_dead_peer_notify_exec_t private_dead_peer_notify_exec_t;

/**
 * Private data of an dead_peer_notify_exec_t object.
 */
struct private_dead_peer_notify_exec_t {

	/**
	 * Public dead_peer_notify_exec_t interface.
	 */
	dead_peer_notify_exec_t public;

	/**
	 * Enable/disable execute external command flag.
	 */
	bool script_enabled;

	/**
	 * External command path.
	 */
	char *script_path;
};

METHOD(dead_peer_notify_exec_t, run, void,
	private_dead_peer_notify_exec_t *this, const char *peer, const char *host)
{
	FILE *shell;
	char command[1024];
	int cmd_len;

	memset(command, 0, sizeof(command));

	if (!this->script_enabled)
	{
		return;
	}

	cmd_len = snprintf(command, sizeof(command), "%s '%s' '%s'",
					   this->script_path, peer, host);
	if (cmd_len >= sizeof(command) || cmd_len < 0)
	{
		DBG1(DBG_LIB, "external script path was truncated due to length limitation "
					  "of %lu characters", sizeof(command));
		DBG1(DBG_LIB, "could not execute external script");
		return;
	}
	DBG2(DBG_LIB, "trying to run external script: '%s'...", command);

	shell = popen(command, "r");
	if (shell == NULL)
	{
		DBG1(DBG_LIB, "could not execute external script");
		return;
	}
	if (pclose(shell) == -1)
	{
		DBG1(DBG_LIB, "pclose error: %s", strerror(errno));
	}
}

METHOD(dead_peer_notify_exec_t, destroy, void,
	private_dead_peer_notify_exec_t *this)
{
	free(this);
}

/**
 * See header
 */
dead_peer_notify_exec_t *dead_peer_notify_exec_create()
{
	private_dead_peer_notify_exec_t *this;
	bool script_ok = true;
	struct stat script_info;

	INIT(this,
		.public = {
			.run = _run,
			.destroy = _destroy,
		},
	);

	this->script_enabled = lib->settings->get_bool(lib->settings,
								"%s.plugins.dead-peer-notify.run_command", FALSE,
								lib->ns);
	if (this->script_enabled)
	{
		this->script_path = lib->settings->get_str(lib->settings,
								"%s.plugins.dead-peer-notify.command_path", NULL,
								lib->ns);

		if (!this->script_path)
		{
			DBG1(DBG_CFG, "no exetrnal command path set");
			script_ok = false;
		}
		else
		{
			if (stat(this->script_path, &script_info) == -1)
			{
				DBG1(DBG_CFG, "failed to read external command: %s", strerror(errno));
				script_ok = false;
			}
			else if (!(script_info.st_mode & S_IXUSR))
			{
				DBG1(DBG_CFG, "script has no execute permission for owner");
				script_ok = false;
			}
		}

		if (!script_ok)
		{
			this->script_enabled = false;
			DBG1(DBG_CFG, "execution of the external command is disabled");
		}
	}

	return &this->public;
}
