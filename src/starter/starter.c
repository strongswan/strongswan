/* strongSwan IPsec starter
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
 *
 * RCSID $Id: starter.c,v 1.23 2006/02/15 18:37:46 as Exp $
 */

#include <sys/types.h>
#include <sys/wait.h>
#include <sys/stat.h>
#include <stdlib.h>
#include <stdio.h>
#include <signal.h>
#include <unistd.h>
#include <sys/time.h>
#include <time.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>

#include <freeswan.h>

#include "../pluto/constants.h"
#include "../pluto/defs.h"
#include "../pluto/log.h"

#include "confread.h"
#include "files.h"
#include "starterwhack.h"
#include "starterstroke.h"
#include "invokepluto.h"
#include "invokecharon.h"
#include "netkey.h"
#include "cmp.h"
#include "interfaces.h"

#define FLAG_ACTION_START_PLUTO   0x01
#define FLAG_ACTION_UPDATE        0x02
#define FLAG_ACTION_RELOAD        0x04
#define FLAG_ACTION_QUIT          0x08
#define FLAG_ACTION_LISTEN        0x10
#define FLAG_ACTION_START_CHARON  0x20

static unsigned int _action_ = 0;

static void
fsig(int signal)
{
    switch (signal)
    {
	case SIGCHLD:
	{
	    int status;
	    pid_t pid;
	    char *name = NULL;

	    while ((pid = waitpid(-1, &status, WNOHANG)) > 0)
	    {
		if (pid == starter_pluto_pid())
		    name = " (Pluto)";
		if (pid == starter_charon_pid())
		    name = " (Charon)";
		if (WIFSIGNALED(status))
		    DBG(DBG_CONTROL,
			DBG_log("child %d%s has been killed by sig %d\n",
				pid, name?name:"", WTERMSIG(status))
		       )
		else if (WIFSTOPPED(status))
		    DBG(DBG_CONTROL,
			DBG_log("child %d%s has been stopped by sig %d\n",
				pid, name?name:"", WSTOPSIG(status))
		       )
		else if (WIFEXITED(status))
		    DBG(DBG_CONTROL,
			DBG_log("child %d%s has quit (exit code %d)\n",
				pid, name?name:"", WEXITSTATUS(status))
		       )
		else
		    DBG(DBG_CONTROL,
			DBG_log("child %d%s has quit", pid, name?name:"")
		       )
		if (pid == starter_pluto_pid())
		    starter_pluto_sigchild(pid);
		if (pid == starter_charon_pid())
		    starter_charon_sigchild(pid);
	    }
	}
	break;

	case SIGPIPE:
	    /** ignore **/
	    break;

	case SIGALRM:
	    _action_ |= FLAG_ACTION_START_PLUTO;
	    _action_ |= FLAG_ACTION_START_CHARON;
	    break;

	case SIGHUP:
	    _action_ |= FLAG_ACTION_UPDATE;
	    break;

	case SIGTERM:
	case SIGQUIT:
	case SIGINT:
	    _action_ |= FLAG_ACTION_QUIT;
	    break;

	case SIGUSR1:
	    _action_ |= FLAG_ACTION_RELOAD;
	    _action_ |= FLAG_ACTION_UPDATE;
	    break;

	default:
	    plog("fsig(): unknown signal %d -- investigate", signal);
	    break;
    }
}

static void
usage(char *name)
{
    fprintf(stderr, "Usage: starter [--nofork] [--auto-update <sec>] "
	    "[--debug|--debug-more|--debug-all]\n");
    exit(1);
}

int main (int argc, char **argv)
{
    starter_config_t *cfg = NULL;
    starter_config_t *new_cfg;
    starter_conn_t *conn, *conn2;
    starter_ca_t *ca, *ca2;

    struct stat stb;

    char *err = NULL;
    int i;
    int id = 1;
    struct timeval tv;
    unsigned long auto_update = 0;
    time_t last_reload;
    bool no_fork = FALSE;

    /* global variables defined in log.h */
    log_to_stderr = TRUE;
    base_debugging = DBG_NONE;

    /* parse command line */
    for (i = 1; i < argc; i++)
    {
	if (streq(argv[i], "--debug"))
	{
	    base_debugging |= DBG_CONTROL;
	}
	else if (streq(argv[i], "--debug-more"))
	{
	    base_debugging |= DBG_CONTROLMORE;
	}
	else if (streq(argv[i], "--debug-all"))
	{
	    base_debugging |= DBG_ALL;
	}
	else if (streq(argv[i], "--nofork"))
	{
	    no_fork = TRUE;
	}
	else if (streq(argv[i], "--auto-update") && i+1 < argc)
	{
	    auto_update = atoi(argv[++i]);
	    if (!auto_update)
		usage(argv[0]);
	}
	else
	{
	    usage(argv[0]);
	}
    }

    /* Init */
    init_log("ipsec_starter");
    cur_debugging = base_debugging;

    signal(SIGHUP,  fsig);
    signal(SIGCHLD, fsig);
    signal(SIGPIPE, fsig);
    signal(SIGINT,  fsig);
    signal(SIGTERM, fsig);
    signal(SIGQUIT, fsig);
    signal(SIGALRM, fsig);
    signal(SIGUSR1, fsig);

    plog("Starting strongSwan %s IPsec [starter]...", ipsec_version_code());

    /* verify that we can start */
    if (getuid() != 0)
    {
	plog("permission denied (must be superuser)");
	exit(1);
    }

    if (stat(PLUTO_PID_FILE, &stb) == 0)
    {
	plog("pluto is already running (%s exists) -- skipping pluto start", PLUTO_PID_FILE);
    }
    else
    {
	_action_ |= FLAG_ACTION_START_PLUTO;
    }
    if (stat(CHARON_PID_FILE, &stb) == 0)
    {
	plog("charon is already running (%s exists) -- skipping charon start", CHARON_PID_FILE);
    }
    else
    {
	_action_ |= FLAG_ACTION_START_CHARON;
    }
    if (stat(DEV_RANDOM, &stb) != 0)
    {
	plog("unable to start strongSwan IPsec -- no %s!", DEV_RANDOM);
	exit(1);
    }

    if (stat(DEV_URANDOM, &stb)!= 0)
    {
	plog("unable to start strongSwan IPsec -- no %s!", DEV_URANDOM);
	exit(1);
    }

    cfg = confread_load(CONFIG_FILE);
    if (!cfg)
    {
	plog("unable to start strongSwan -- errors in config");
	exit(1);
    }

    /* determine if we have a native netkey IPsec stack */
    if (!starter_netkey_init())
    {
	plog("nor netkey IPSec stack detected");
	exit(1);
    }

    last_reload = time(NULL);

    if (stat(STARTER_PID_FILE, &stb) == 0)
    {
	plog("starter is already running (%s exists) -- no fork done", STARTER_PID_FILE);
	exit(0);
    }

    /* fork if we're not debugging stuff */
    if (!no_fork)
    {
	log_to_stderr = FALSE;

	switch (fork())
	{
	    case 0:
	    {
		int fnull = open("/dev/null", O_RDWR);

		if (fnull >= 0)
		{
		    dup2(fnull, STDIN_FILENO);
		    dup2(fnull, STDOUT_FILENO);
		    dup2(fnull, STDERR_FILENO);
		    close(fnull);
		}
	    }
	    break;
	    case -1:
		plog("can't fork: %s", strerror(errno));
		break;
	    default:
		exit(0);
	}
    }

    /* save pid file in /var/run/starter.pid */
    {
	FILE *fd = fopen(STARTER_PID_FILE, "w");

	if (fd)
	{
	    fprintf(fd, "%u\n", getpid());
	    fclose(fd);
	}
    }

    for (;;)
    {
	/*
	 * Stop pluto/charon (if started) and exit
	 */
	if (_action_ & FLAG_ACTION_QUIT)
	{
	    if (starter_pluto_pid())
		starter_stop_pluto();
	    if (starter_charon_pid())
		starter_stop_charon();
	    starter_netkey_cleanup();
	    confread_free(cfg);
	    unlink(STARTER_PID_FILE);
	    unlink(INFO_FILE);
#ifdef LEAK_DETECTIVE
	    report_leaks();
#endif /* LEAK_DETECTIVE */
	    close_log();
	    plog("ipsec starter stopped");
	    exit(0);
	}

	/*
	 * Delete all connections. Will be added below
	 */
	if (_action_ & FLAG_ACTION_RELOAD)
	{
	    if (starter_pluto_pid() || starter_charon_pid())
	    {
		for (conn = cfg->conn_first; conn; conn = conn->next)
		{
		    if (conn->state == STATE_ADDED)
		    {
			if (starter_charon_pid())
			{
			    starter_stroke_del_conn(conn);
			}
			if (starter_pluto_pid())
			{
			    starter_whack_del_conn(conn);
			}
			conn->state = STATE_TO_ADD;
		    }
		}
		for (ca = cfg->ca_first; ca; ca = ca->next)
		{
		    if (ca->state == STATE_ADDED)
		    {
			if (starter_pluto_pid())
			{
			    starter_whack_del_ca(ca);
			    ca->state = STATE_TO_ADD;
			}
		    }
		}
	    }
	    _action_ &= ~FLAG_ACTION_RELOAD;
	}

	/*
	 * Update configuration
	 */
	if (_action_ & FLAG_ACTION_UPDATE)
	{
	    err = NULL;
	    DBG(DBG_CONTROL,
		DBG_log("Reloading config...")
	       );
	    new_cfg = confread_load(CONFIG_FILE);

	    if (new_cfg)
	    {
		/* Switch to new config. New conn will be loaded below */
		if (!starter_cmp_defaultroute(&new_cfg->defaultroute
				   , &cfg->defaultroute))
		{
		    _action_ |= FLAG_ACTION_LISTEN;
		}

		if (!starter_cmp_pluto(cfg, new_cfg)) 
		{
		    plog("Pluto has changed");
		    if (starter_pluto_pid())
			starter_stop_pluto();
		    _action_ &= ~FLAG_ACTION_LISTEN;
		    _action_ |= FLAG_ACTION_START_PLUTO;
		}
		else
		{
		    /* Only reload conn and ca sections if pluto is not killed */

		    /* Look for new connections that are already loaded */
		    for (conn = cfg->conn_first; conn; conn = conn->next)
		    {
			if (conn->state == STATE_ADDED)
			{
			    for (conn2 = new_cfg->conn_first; conn2; conn2 = conn2->next)
			    {
				if (conn2->state == STATE_TO_ADD && starter_cmp_conn(conn, conn2))
				{
				    conn->state = STATE_REPLACED;
				    conn2->state = STATE_ADDED;
				    conn2->id = conn->id;
				    break;
				}
			    }
			}
		    }

		    /* Remove conn sections that have become unused */
		    for (conn = cfg->conn_first; conn; conn = conn->next)
		    {
			if (conn->state == STATE_ADDED)
			{
			    if (starter_charon_pid())
			    {
				starter_stroke_del_conn(conn);
			    }
			    if (starter_pluto_pid())
			    {
				starter_whack_del_conn(conn);
			    }
			}
		    }

		    /* Look for new ca sections that are already loaded */
		    for (ca = cfg->ca_first; ca; ca = ca->next)
		    {
			if (ca->state == STATE_ADDED)
			{
			    for (ca2 = new_cfg->ca_first; ca2; ca2 = ca2->next)
			    {
				if (ca2->state == STATE_TO_ADD && starter_cmp_ca(ca, ca2))
				{
				    ca->state = STATE_REPLACED;
				    ca2->state = STATE_ADDED;
				    break;
				}
			    }
			}
		    }

		    /* Remove ca sections that have become unused */
		    for (ca = cfg->ca_first; ca; ca = ca->next)
		    {
			if (ca->state == STATE_ADDED)
			{
			    if (starter_pluto_pid())
			    {
				starter_whack_del_ca(ca);
			    }
			}
		    }
		}
		confread_free(cfg);
		cfg = new_cfg;
	    }
	    else
	    {
		plog("can't reload config file: %s -- keeping old one");
	    }
	    _action_ &= ~FLAG_ACTION_UPDATE;
	    last_reload = time(NULL);
	}

	/*
	 * Start pluto
	 */
	if (_action_ & FLAG_ACTION_START_PLUTO)
	{
	    if (cfg->setup.plutostart && !starter_pluto_pid())
	    {
		DBG(DBG_CONTROL,
		    DBG_log("Attempting to start pluto...")
		   );

		if (starter_start_pluto(cfg, no_fork) == 0)
		{
		    starter_whack_listen();
		}
		else
		{
		    /* schedule next try */
		    alarm(PLUTO_RESTART_DELAY);
		}
	    }
	    _action_ &= ~FLAG_ACTION_START_PLUTO;

	    for (ca = cfg->ca_first; ca; ca = ca->next)
	    {
		if (ca->state == STATE_ADDED)
		    ca->state = STATE_TO_ADD;
	    }

	    for (conn = cfg->conn_first; conn; conn = conn->next)
	    {
		if (conn->state == STATE_ADDED)
		    conn->state = STATE_TO_ADD;
	    }
	}
	
	/*
	 * Start charon
	 */
	if (_action_ & FLAG_ACTION_START_CHARON)
	{
	    if (cfg->setup.charonstart && !starter_charon_pid())
	    {
		DBG(DBG_CONTROL,
		    DBG_log("Attempting to start charon...")
		   );
		if (starter_start_charon(cfg, no_fork))
		{
		    /* schedule next try */
		    alarm(PLUTO_RESTART_DELAY);
		}
	    }
	    _action_ &= ~FLAG_ACTION_START_CHARON;
	}

	/*
	 * Tell pluto to reread its interfaces
	 */
	if (_action_ & FLAG_ACTION_LISTEN)
	{
	    if (starter_pluto_pid())
	    {
		starter_whack_listen();
		_action_ &= ~FLAG_ACTION_LISTEN;
	    }
	}

	/*
	 * Add stale conn and ca sections
	 */
	if (starter_pluto_pid() || starter_charon_pid())
	{
	    for (ca = cfg->ca_first; ca; ca = ca->next)
	    {
		if (ca->state == STATE_TO_ADD)
		{
		    if (starter_pluto_pid())
		    {
			starter_whack_add_ca(ca);
			ca->state = STATE_ADDED;
		    }
		}
	    }

	    for (conn = cfg->conn_first; conn; conn = conn->next)
	    {
		if (conn->state == STATE_TO_ADD)
		{
		    if (conn->id == 0)
		    {
			/* affect new unique id */
			conn->id = id++;
		    }
		    if (starter_charon_pid())
		    {
			starter_stroke_add_conn(conn);
		    }
		    if (starter_pluto_pid())
		    {
			starter_whack_add_conn(conn);
		    }
		    conn->state = STATE_ADDED;

		    if (conn->startup == STARTUP_START)
		    {
			if (starter_charon_pid())
			{
			    starter_stroke_initiate_conn(conn);
			}
			if (conn->keyexchange != KEY_EXCHANGE_IKEV2)
			{
			    /* currently not initiated, until pluto handles the keyexchange flag */
			    if (starter_pluto_pid())
			    {
				starter_whack_initiate_conn(conn);
			    }
			}
		    }
		    else if (conn->startup == STARTUP_ROUTE)
		    {
			if (starter_charon_pid())
			{
			    starter_stroke_route_conn(conn);
			}
			if (conn->keyexchange != KEY_EXCHANGE_IKEV2)
			{
			    /* currently not routed, until pluto handles the keyexchange flag */
			    if (starter_pluto_pid())
			    {
				starter_whack_route_conn(conn);
			    }
			}
		    }
		}
	    }
	}

	/*
	 * If auto_update activated, when to stop select
	 */
	if (auto_update)
	{
	    time_t now = time(NULL);

	    tv.tv_sec = (now < last_reload + auto_update)
		    ? (last_reload + auto_update-now) : 0;
	    tv.tv_usec = 0;
	}

	/*
	 * Wait for something to happen
	 */
	if (select(0, NULL, NULL, NULL, auto_update ? &tv : NULL) == 0)
	{
	    /* timeout -> auto_update */
	    _action_ |= FLAG_ACTION_UPDATE;
	}
    }

    return 0;
}

