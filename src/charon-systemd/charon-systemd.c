/*
 * Copyright (C) 2006-2012 Tobias Brunner
 * Copyright (C) 2005-2009 Martin Willi
 * Copyright (C) 2006 Daniel Roethlisberger
 * Copyright (C) 2005 Jan Hutter
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

#include <signal.h>
#include <stdio.h>
#include <pthread.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/utsname.h>
#include <unistd.h>
#include <errno.h>
#include <systemd/sd-daemon.h>

#include <hydra.h>
#include <daemon.h>

#include <library.h>
#include <utils/backtrace.h>
#include <threading/thread.h>

/**
 * hook in library for debugging messages
 */
extern void (*dbg) (debug_t group, level_t level, char *fmt, ...);

/**
 * Logging hook for library logs, using stderr output
 */
static void dbg_stderr(debug_t group, level_t level, char *fmt, ...)
{
	va_list args;

	if (level <= 1)
	{
		va_start(args, fmt);
		fprintf(stderr, "00[%N] ", debug_names, group);
		vfprintf(stderr, fmt, args);
		fprintf(stderr, "\n");
		va_end(args);
	}
}

/**
 * Run the daemon and handle unix signals
 */
static int run()
{
	sigset_t set;

	sigemptyset(&set);
	sigaddset(&set, SIGTERM);
	sigprocmask(SIG_BLOCK, &set, NULL);

	sd_notify(0, "READY=1\n");

	while (TRUE)
	{
		int sig, error;

		error = sigwait(&set, &sig);
		if (error)
		{
			DBG1(DBG_DMN, "waiting for signal failed: %s", strerror(error));
			return SS_RC_INITIALIZATION_FAILED;
		}
		switch (sig)
		{
			case SIGTERM:
			{
				DBG1(DBG_DMN, "SIGTERM received, shutting down");
				charon->bus->alert(charon->bus, ALERT_SHUTDOWN_SIGNAL, sig);
				return 0;
			}
			default:
			{
				DBG1(DBG_DMN, "unknown signal %d received. Ignored", sig);
				break;
			}
		}
	}
}

/**
 * lookup UID and GID
 */
static bool lookup_uid_gid()
{
#ifdef IPSEC_USER
	if (!lib->caps->resolve_uid(lib->caps, IPSEC_USER))
	{
		return FALSE;
	}
#endif /* IPSEC_USER */
#ifdef IPSEC_GROUP
	if (!lib->caps->resolve_gid(lib->caps, IPSEC_GROUP))
	{
		return FALSE;
	}
#endif /* IPSEC_GROUP */
	return TRUE;
}

/**
 * Handle SIGSEGV/SIGILL signals raised by threads
 */
static void segv_handler(int signal)
{
	backtrace_t *backtrace;

	DBG1(DBG_DMN, "thread %u received %d", thread_current_id(), signal);
	backtrace = backtrace_create(2);
	backtrace->log(backtrace, NULL, TRUE);
	backtrace->log(backtrace, stderr, TRUE);
	backtrace->destroy(backtrace);

	DBG1(DBG_DMN, "killing ourself, received critical signal");
	abort();
}

/**
 * Main function, starts the daemon.
 */
int main(int argc, char *argv[])
{
	struct sigaction action;
	struct utsname utsname;

	dbg = dbg_stderr;

	if (uname(&utsname) != 0)
	{
		memset(&utsname, 0, sizeof(utsname));
	}

	sd_notifyf(0, "STATUS=Starting charon-systemd, strongSwan %s, %s %s, %s",
			   VERSION, utsname.sysname, utsname.release, utsname.machine);

	atexit(library_deinit);
	if (!library_init(NULL, "charon-systemd"))
	{
		sd_notifyf(0, "STATUS=libstrongswan initialization failed");
		return SS_RC_INITIALIZATION_FAILED;
	}
	if (lib->integrity &&
		!lib->integrity->check_file(lib->integrity, "charon-systemd", argv[0]))
	{
		sd_notifyf(0, "STATUS=integrity check of charon-systemd failed");
		return SS_RC_INITIALIZATION_FAILED;
	}
	atexit(libhydra_deinit);
	if (!libhydra_init())
	{
		sd_notifyf(0, "STATUS=libhydra initialization failed");
		return SS_RC_INITIALIZATION_FAILED;
	}
	atexit(libcharon_deinit);
	if (!libcharon_init())
	{
		sd_notifyf(0, "STATUS=libcharon initialization failed");
		return SS_RC_INITIALIZATION_FAILED;
	}
	if (!lookup_uid_gid())
	{
		sd_notifyf(0, "STATUS=unkown uid/gid");
		return SS_RC_INITIALIZATION_FAILED;
	}
	charon->load_loggers(charon, NULL, FALSE);

	if (!charon->initialize(charon, PLUGINS))
	{
		sd_notifyf(0, "STATUS=charon initialization failed");
		return SS_RC_INITIALIZATION_FAILED;
	}
	lib->plugins->status(lib->plugins, LEVEL_CTRL);

	if (!lib->caps->drop(lib->caps))
	{
		sd_notifyf(0, "STATUS=dropping capabilities failed");
		return SS_RC_INITIALIZATION_FAILED;
	}

	/* add handler for SEGV and ILL,
	 * INT, TERM and HUP are handled by sigwait() in run() */
	action.sa_handler = segv_handler;
	action.sa_flags = 0;
	sigemptyset(&action.sa_mask);
	sigaddset(&action.sa_mask, SIGINT);
	sigaddset(&action.sa_mask, SIGTERM);
	sigaddset(&action.sa_mask, SIGHUP);
	sigaction(SIGSEGV, &action, NULL);
	sigaction(SIGILL, &action, NULL);
	sigaction(SIGBUS, &action, NULL);
	action.sa_handler = SIG_IGN;
	sigaction(SIGPIPE, &action, NULL);

	pthread_sigmask(SIG_SETMASK, &action.sa_mask, NULL);

	charon->start(charon);

	sd_notifyf(0, "STATUS=charon-systemd running, strongSwan %s, %s %s, %s",
			   VERSION, utsname.sysname, utsname.release, utsname.machine);

	return run();
}
