/* strongSwan Pluto launcher
 * Copyright (C) 2001-2002 Mathieu Lafon - Arkoon Network Security
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

#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <signal.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>
#include <fcntl.h>

#include <freeswan.h>

#include "../pluto/constants.h"
#include "../pluto/defs.h"
#include "../pluto/log.h"

#include "confread.h"
#include "invokepluto.h"
#include "files.h"
#include "starterwhack.h"
#
static int _pluto_pid = 0;
static int _stop_requested;

pid_t
starter_pluto_pid(void)
{
	return _pluto_pid;
}

void
starter_pluto_sigchild(pid_t pid, int status)
{
	if (pid == _pluto_pid)
	{
		_pluto_pid = 0;
		if (status == SS_RC_LIBSTRONGSWAN_INTEGRITY ||
			status == SS_RC_DAEMON_INTEGRITY)
		{
			plog("pluto has quit: integrity test of %s failed",
				  (status == 64) ? "libstrongswan" : "pluto");
			_stop_requested = 1;
		}
		else if (status == SS_RC_INITIALIZATION_FAILED)
		{
			plog("pluto has quit: initialization failed");
			_stop_requested = 1;
		}
		if (!_stop_requested)
		{
			plog("pluto has died -- restart scheduled (%dsec)"
				, PLUTO_RESTART_DELAY);
			alarm(PLUTO_RESTART_DELAY);   // restart in 5 sec
		}
		unlink(PLUTO_PID_FILE);
	}
}

int
starter_stop_pluto (void)
{
	int i;
	pid_t pid = _pluto_pid;

	if (pid)
	{
		_stop_requested = 1;

		if (starter_whack_shutdown() == 0)
		{
			for (i = 0; i < 400; i++)
			{
				usleep(20000); /* sleep for 20 ms */
				if (_pluto_pid == 0)
				{
					plog("pluto stopped after %d ms", 20*(i+1));
					return 0;
				}
			}
		}
		/* be more and more aggressive */
		for (i = 0; i < 20 && (pid = _pluto_pid) != 0; i++)
		{

			if (i < 10)
			{
				kill(pid, SIGTERM);
			}
			if (i == 10)
			{
				kill(pid, SIGKILL);
				plog("starter_stop_pluto(): pluto does not respond, sending KILL");
			}
			else
			{
				kill(pid, SIGKILL);
			}
			usleep(100000); /* sleep for 100 ms */
		}
		if (_pluto_pid == 0)
		{
			plog("pluto stopped after %d ms", 8000 + 100*i);
			return 0;
		}
		plog("starter_stop_pluto(): can't stop pluto !!!");
		return -1;
	}
	else
	{
		plog("stater_stop_pluto(): pluto is not started...");
	}
	return -1;
}

#define ADD_DEBUG(v) { \
		for (l = cfg->setup.plutodebug; l && *l; l++) if (streq(*l, v)) \
				arg[argc++] = "--debug-" v; \
		}

int
starter_start_pluto (starter_config_t *cfg, bool no_fork, bool attach_gdb)
{
	struct stat stb;
	int i;
	pid_t pid;
	char **l;
	int argc = 2;
	char *arg[] = {
			  PLUTO_CMD, "--nofork"
			, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL
			, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL
			, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL
			, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL
		};

	printf ("starter_start_pluto entered\n");

	if (attach_gdb)
	{
		argc = 0;
		arg[argc++] = "/usr/bin/gdb";
		arg[argc++] = "--args";
		arg[argc++] = PLUTO_CMD;
		arg[argc++] = "--nofork";
		}
	if (cfg->setup.plutostderrlog || no_fork)
	{
		arg[argc++] = "--stderrlog";
	}
	if (cfg->setup.uniqueids)
	{
		arg[argc++] = "--uniqueids";
	}
	ADD_DEBUG("none")
	ADD_DEBUG("all")
	ADD_DEBUG("raw")
	ADD_DEBUG("crypt")
	ADD_DEBUG("parsing")
	ADD_DEBUG("emitting")
	ADD_DEBUG("control")
	ADD_DEBUG("lifecycle")
	ADD_DEBUG("klips")
	ADD_DEBUG("kernel")
	ADD_DEBUG("dns")
	ADD_DEBUG("natt")
	ADD_DEBUG("oppo")
	ADD_DEBUG("controlmore")
	ADD_DEBUG("private")
	if (cfg->setup.crlcheckinterval > 0)
	{
		static char buf1[15];

		arg[argc++] = "--crlcheckinterval";
		snprintf(buf1, sizeof(buf1), "%d", (int)cfg->setup.crlcheckinterval);
		arg[argc++] = buf1;
	}
	if (cfg->setup.cachecrls)
	{
		arg[argc++] = "--cachecrls";
	}
	if (cfg->setup.strictcrlpolicy)
	{
		arg[argc++] = "--strictcrlpolicy";
	}
	if (cfg->setup.nocrsend)
	{
		arg[argc++] = "--nocrsend";
	}
	if (cfg->setup.nat_traversal)
	{
		arg[argc++] = "--nat_traversal";
	}
	if (cfg->setup.force_keepalive)
	{
		arg[argc++] = "--force_keepalive";
	}
	if (cfg->setup.keep_alive)
	{
		static char buf2[15];

		arg[argc++] = "--keep_alive";
		snprintf(buf2, sizeof(buf2), "%d", (int)cfg->setup.keep_alive);
		arg[argc++] = buf2;
	}
	if (cfg->setup.virtual_private)
	{
		arg[argc++] = "--virtual_private";
		arg[argc++] = cfg->setup.virtual_private;
	}
	if (cfg->setup.pkcs11module)
	{
		arg[argc++] = "--pkcs11module";
		arg[argc++] = cfg->setup.pkcs11module;
	}
	if (cfg->setup.pkcs11initargs)
	{
		arg[argc++] = "--pkcs11initargs";
		arg[argc++] = cfg->setup.pkcs11initargs;
	}
	if (cfg->setup.pkcs11keepstate)
	{
		arg[argc++] = "--pkcs11keepstate";
	}
	if (cfg->setup.pkcs11proxy)
	{
		arg[argc++] = "--pkcs11proxy";
	}

	if (_pluto_pid)
	{
		plog("starter_start_pluto(): pluto already started...");
		return -1;
	}
	else
	{
		unlink(PLUTO_CTL_FILE);
		_stop_requested = 0;

		if (cfg->setup.prepluto)
			ignore_result(system(cfg->setup.prepluto));

		pid = fork();
		switch (pid)
		{
		case -1:
			plog("can't fork(): %s", strerror(errno));
			return -1;
		case 0:
			/* child */
			if (cfg->setup.plutostderrlog)
			{
				int f = creat(cfg->setup.plutostderrlog, 00644);

				/* redirect stderr to file */
				if (f < 0)
				{
					plog("couldn't open stderr redirection file '%s'",
						  cfg->setup.plutostderrlog);
				}
				else
				{
					dup2(f, 2);
				}
			}
			setsid();
			sigprocmask(SIG_SETMASK, 0, NULL);
			/* disable glibc's malloc checker, conflicts with leak detective */
			setenv("MALLOC_CHECK_", "0", 1);
			execv(arg[0], arg);
			plog("can't execv(%s,...): %s", arg[0], strerror(errno));
			exit(1);
		default:
			/* father */
			_pluto_pid = pid;
			for (i = 0; i < 500 && _pluto_pid; i++)
			{
				/* wait for pluto for a maximum of 500 x 20 ms = 10 s */
				usleep(20000);
				if (stat(PLUTO_CTL_FILE, &stb) == 0)
				{
					plog("pluto (%d) started after %d ms", _pluto_pid, 20*(i+1));
					if (cfg->setup.postpluto)
					{
						ignore_result(system(cfg->setup.postpluto));
					}
					return 0;
				}
			}
			if (_pluto_pid)
			{
				/* If pluto is started but with no ctl file, stop it */
				plog("pluto too long to start... - kill kill");
				for (i = 0; i < 20 && (pid = _pluto_pid) != 0; i++)
				{
					if (i < 10)
					{
						kill(pid, SIGTERM);
					}
					else
					{
						kill(pid, SIGKILL);
					}
					usleep(20000); /* sleep for 20 ms */
				}
			}
			else
			{
				plog("pluto refused to be started");
			}
			return -1;
		}
	}
	return -1;
}
