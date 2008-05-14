/*
 * Copyright (C) 2008 Martin Willi
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
#include <signal.h>
#include <unistd.h>
#include <fcntl.h>

#include <library.h>
#include <dumm.h>

/**
 * number of running guests
 */
static int running = 0;

/**
 * Guest invocation callback
 */
static pid_t invoke(void *vte, guest_t *guest,
					char *args[], int argc)
{
	pid_t pid;
	
	args[argc] = "con0=xterm";
	
	pid = fork();
	switch (pid)
	{
		case 0: /* child */
			dup2(open("/dev/null", 0), 1);
			dup2(open("/dev/null", 0), 2);
			execvp(args[0], args);
			exit(-1);
		case -1:
			fprintf(stderr, "starting guest '%s' failed\n", guest->get_name(guest));
			return 0;
		default:
			printf("started guest '%s', pid: %d\n", guest->get_name(guest), pid);
			running++;
			return pid;
	}
}

/**
 * main routine, parses args and reads from console
 */
int main(int argc, char *argv[])
{
	dumm_t *dumm;
	enumerator_t *enumerator;
	guest_t *guest;
	bridge_t *switch0, *switch1, *switch2;
	iface_t *iface;
	sigset_t set;
	siginfo_t info;
	
	library_init(NULL);
	
	dumm = dumm_create(NULL);
	
	switch0 = dumm->create_bridge(dumm, "switch0");
	switch1 = dumm->create_bridge(dumm, "switch1");
	switch2 = dumm->create_bridge(dumm, "switch2");
	
	if (switch0 && switch1 && switch2)
	{
		enumerator = dumm->create_guest_enumerator(dumm);
		while (enumerator->enumerate(enumerator, &guest))
		{
			if (!guest->start(guest, invoke, NULL, NULL))
			{
				continue;
			}
			if (streq(guest->get_name(guest), "alice"))
			{
				iface = guest->create_iface(guest, "eth0");
				if (iface)
				{
					switch1->connect_iface(switch1, iface);
				}
				iface = guest->create_iface(guest, "eth1");
				if (iface)
				{
					switch0->connect_iface(switch0, iface);
				}
			}
			else if (streq(guest->get_name(guest), "moon") ||
					 streq(guest->get_name(guest), "sun"))
			{
				iface = guest->create_iface(guest, "eth0");
				if (iface)
				{
					switch0->connect_iface(switch0, iface);
				}
				iface = guest->create_iface(guest, "eth1");
				if (iface)
				{
					switch1->connect_iface(switch1, iface);
				}
			}
			else if (streq(guest->get_name(guest), "bob"))
			{
				iface = guest->create_iface(guest, "eth0");
				if (iface)
				{
					switch2->connect_iface(switch2, iface);
				}
			}
			else if (streq(guest->get_name(guest), "venus"))
			{
				iface = guest->create_iface(guest, "eth0");
				if (iface)
				{
					switch1->connect_iface(switch1, iface);
				}
			}
			else if (streq(guest->get_name(guest), "carol") ||
					 streq(guest->get_name(guest), "winnetou") ||
					 streq(guest->get_name(guest), "dave"))
			{
				iface = guest->create_iface(guest, "eth0");
				if (iface)
				{
					switch0->connect_iface(switch0, iface);
				}
			}
		}
		enumerator->destroy(enumerator);
	
		sigemptyset(&set);
		sigaddset(&set, SIGINT); 
		sigaddset(&set, SIGHUP); 
		sigaddset(&set, SIGTERM);
		sigaddset(&set, SIGCHLD);
		sigprocmask(SIG_SETMASK, &set, NULL);
		while (running)
		{
			if (sigwaitinfo(&set, &info) == SIGCHLD)
			{
				enumerator = dumm->create_guest_enumerator(dumm);
				while (enumerator->enumerate(enumerator, &guest))
				{
					if (guest->get_pid(guest) == info.si_pid)
					{
						running--;
						guest->sigchild(guest);
						break;
					}
				}
				enumerator->destroy(enumerator);
			}
		}
	}
	dumm->destroy(dumm);
	
	library_deinit();
	return 0;
}
