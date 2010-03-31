/*
 * Copyright (C) 2006-2010 Tobias Brunner
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

#include <stdio.h>
#ifdef HAVE_PRCTL
#include <sys/prctl.h>
#endif
#define _POSIX_PTHREAD_SEMANTICS /* for two param sigwait on OpenSolaris */
#include <signal.h>
#undef _POSIX_PTHREAD_SEMANTICS
#include <pthread.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
#include <getopt.h>
#include <pwd.h>
#include <grp.h>

#include <hydra.h>
#include <daemon.h>

#include <library.h>
#include <utils/backtrace.h>
#include <threading/thread.h>

/**
 * PID file, in which charon stores its process id
 */
#define PID_FILE IPSEC_PIDDIR "/charon.pid"

/**
 * hook in library for debugging messages
 */
extern void (*dbg) (int level, char *fmt, ...);

/**
 * Logging hook for library logs, using stderr output
 */
static void dbg_stderr(int level, char *fmt, ...)
{
	va_list args;

	if (level <= 1)
	{
		va_start(args, fmt);
		fprintf(stderr, "00[LIB] ");
		vfprintf(stderr, fmt, args);
		fprintf(stderr, "\n");
		va_end(args);
	}
}

/**
 * Run the daemon and handle unix signals
 */
static void run()
{
	sigset_t set;

	/* handle SIGINT, SIGHUP ans SIGTERM in this handler */
	sigemptyset(&set);
	sigaddset(&set, SIGINT);
	sigaddset(&set, SIGHUP);
	sigaddset(&set, SIGTERM);
	sigprocmask(SIG_BLOCK, &set, NULL);

	while (TRUE)
	{
		int sig;
		int error;

		error = sigwait(&set, &sig);
		if (error)
		{
			DBG1(DBG_DMN, "error %d while waiting for a signal", error);
			return;
		}
		switch (sig)
		{
			case SIGHUP:
			{
				DBG1(DBG_DMN, "signal of type SIGHUP received. Ignored");
				break;
			}
			case SIGINT:
			{
				DBG1(DBG_DMN, "signal of type SIGINT received. Shutting down");
				charon->bus->alert(charon->bus, ALERT_SHUTDOWN_SIGNAL, sig);
				return;
			}
			case SIGTERM:
			{
				DBG1(DBG_DMN, "signal of type SIGTERM received. Shutting down");
				charon->bus->alert(charon->bus, ALERT_SHUTDOWN_SIGNAL, sig);
				return;
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
 * drop daemon capabilities
 */
static bool drop_capabilities()
{
#ifdef HAVE_PRCTL
	prctl(PR_SET_KEEPCAPS, 1, 0, 0, 0);
#endif

	if (setgid(charon->gid) != 0)
	{
		DBG1(DBG_DMN, "change to unprivileged group failed");
		return FALSE;
	}
	if (setuid(charon->uid) != 0)
	{
		DBG1(DBG_DMN, "change to unprivileged user failed");
		return FALSE;
	}
	if (!charon->drop_capabilities(charon))
	{
		DBG1(DBG_DMN, "unable to drop daemon capabilities");
		return FALSE;
	}
	return TRUE;
}

/**
 * lookup UID and GID
 */
static bool lookup_uid_gid()
{
#ifdef IPSEC_USER
	{
		char buf[1024];
		struct passwd passwd, *pwp;

		if (getpwnam_r(IPSEC_USER, &passwd, buf, sizeof(buf), &pwp) != 0 ||
			pwp == NULL)
		{
			DBG1(DBG_DMN, "resolving user '"IPSEC_USER"' failed");
			return FALSE;
		}
		charon->uid = pwp->pw_uid;
	}
#endif
#ifdef IPSEC_GROUP
	{
		char buf[1024];
		struct group group, *grp;

		if (getgrnam_r(IPSEC_GROUP, &group, buf, sizeof(buf), &grp) != 0 ||
			grp == NULL)
		{
			DBG1(DBG_DMN, "resolving group '"IPSEC_GROUP"' failed");
			return FALSE;
		}
		charon->gid = grp->gr_gid;
	}
#endif
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
	backtrace->log(backtrace, stderr);
	backtrace->destroy(backtrace);

	DBG1(DBG_DMN, "killing ourself, received critical signal");
	abort();
}

/**
 * Check/create PID file, return TRUE if already running
 */
static bool check_pidfile()
{
	struct stat stb;
	FILE *file;

	if (stat(PID_FILE, &stb) == 0)
	{
		file = fopen(PID_FILE, "r");
		if (file)
		{
			char buf[64];
			pid_t pid = 0;

			memset(buf, 0, sizeof(buf));
			if (fread(buf, 1, sizeof(buf), file))
			{
				pid = atoi(buf);
			}
			fclose(file);
			if (pid && kill(pid, 0) == 0)
			{	/* such a process is running */
				return TRUE;
			}
		}
		DBG1(DBG_DMN, "removing pidfile '"PID_FILE"', process not running");
		unlink(PID_FILE);
	}

	/* create new pidfile */
	file = fopen(PID_FILE, "w");
	if (file)
	{
		fprintf(file, "%d\n", getpid());
		ignore_result(fchown(fileno(file), charon->uid, charon->gid));
		fclose(file);
	}
	return FALSE;
}

/**
 * print command line usage and exit
 */
static void usage(const char *msg)
{
	if (msg != NULL && *msg != '\0')
	{
		fprintf(stderr, "%s\n", msg);
	}
	fprintf(stderr, "Usage: charon\n"
					"         [--help]\n"
					"         [--version]\n"
					"         [--use-syslog]\n"
					"         [--debug-<type> <level>]\n"
					"           <type>:  log context type (dmn|mgr|ike|chd|job|cfg|knl|net|enc|lib)\n"
					"           <level>: log verbosity (-1 = silent, 0 = audit, 1 = control,\n"
					"                                    2 = controlmore, 3 = raw, 4 = private)\n"
					"\n"
		   );
	exit(msg == NULL? 0 : 1);
}

/**
 * Main function, starts the daemon.
 */
int main(int argc, char *argv[])
{
	struct sigaction action;
	bool use_syslog = FALSE;
	level_t levels[DBG_MAX];
	int group, status = SS_RC_INITIALIZATION_FAILED;

	/* logging for library during initialization, as we have no bus yet */
	dbg = dbg_stderr;

	/* initialize library */
	if (!library_init(NULL))
	{
		library_deinit();
		exit(SS_RC_LIBSTRONGSWAN_INTEGRITY);
	}

	if (lib->integrity &&
		!lib->integrity->check_file(lib->integrity, "charon", argv[0]))
	{
		dbg_stderr(1, "integrity check of charon failed");
		library_deinit();
		exit(SS_RC_DAEMON_INTEGRITY);
	}

	if (!libhydra_init("charon"))
	{
		dbg_stderr(1, "initialization failed - aborting charon");
		libhydra_deinit();
		library_deinit();
		exit(SS_RC_INITIALIZATION_FAILED);
	}

	if (!libcharon_init())
	{
		dbg_stderr(1, "initialization failed - aborting charon");
		goto deinit;
	}

	/* use CTRL loglevel for default */
	for (group = 0; group < DBG_MAX; group++)
	{
		levels[group] = LEVEL_CTRL;
	}

	/* handle arguments */
	for (;;)
	{
		struct option long_opts[] = {
			{ "help", no_argument, NULL, 'h' },
			{ "version", no_argument, NULL, 'v' },
			{ "use-syslog", no_argument, NULL, 'l' },
			/* TODO: handle "debug-all" */
			{ "debug-dmn", required_argument, &group, DBG_DMN },
			{ "debug-mgr", required_argument, &group, DBG_MGR },
			{ "debug-ike", required_argument, &group, DBG_IKE },
			{ "debug-chd", required_argument, &group, DBG_CHD },
			{ "debug-job", required_argument, &group, DBG_JOB },
			{ "debug-cfg", required_argument, &group, DBG_CFG },
			{ "debug-knl", required_argument, &group, DBG_KNL },
			{ "debug-net", required_argument, &group, DBG_NET },
			{ "debug-enc", required_argument, &group, DBG_ENC },
			{ "debug-lib", required_argument, &group, DBG_LIB },
			{ 0,0,0,0 }
		};

		int c = getopt_long(argc, argv, "", long_opts, NULL);
		switch (c)
		{
			case EOF:
				break;
			case 'h':
				usage(NULL);
				break;
			case 'v':
				printf("Linux strongSwan %s\n", VERSION);
				status = 0;
				goto deinit;
			case 'l':
				use_syslog = TRUE;
				continue;
			case 0:
				/* option is in group */
				levels[group] = atoi(optarg);
				continue;
			default:
				usage("");
				break;
		}
		break;
	}

	if (!lookup_uid_gid())
	{
		dbg_stderr(1, "invalid uid/gid - aborting charon");
		goto deinit;
	}

	/* initialize daemon */
	if (!charon->initialize(charon, use_syslog, levels))
	{
		DBG1(DBG_DMN, "initialization failed - aborting charon");
		goto deinit;
	}

	if (check_pidfile())
	{
		DBG1(DBG_DMN, "charon already running (\""PID_FILE"\" exists)");
		status = -1;
		goto deinit;
	}

	if (!drop_capabilities())
	{
		DBG1(DBG_DMN, "capability dropping failed - aborting charon");
		goto deinit;
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

	/* start daemon (i.e. the threads in the thread-pool) */
	charon->start(charon);

	/* main thread goes to run loop */
	run();

	/* normal termination, cleanup and exit */
	unlink(PID_FILE);
	status = 0;

deinit:
	libcharon_deinit();
	libhydra_deinit();
	library_deinit();
	return status;
}

