/*
 * Copyright (C) 2007 Martin Willi
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

#define _GNU_SOURCE

#include <stdio.h>
#include <unistd.h>
#include <getopt.h>
#include <library.h>
#include <readline/readline.h>
#include <readline/history.h>

#include "dumm.h"

/**
 * global set of UMLs guests
 */
dumm_t *dumm;

/**
 * show usage information (program arguments)
 */
static void usage()
{
	printf("Usage:\n");
	printf("  --dir|-d <path>            set working dir to <path>\n");
	printf("  --help|-h                  show this help\n");
}

/**
 * help for dumm root shell
 */
static void help()
{
	printf("create name=<name>            start a guest named <name>\n");
	printf("       [master=<dir>]         read only master root filesystem\n");
	printf("       [memory=<MB>]          guest main memory in megabyte\n");
	printf("list                          list running guests\n");
	printf("guest <name>                  open guest menu for <name>\n");
	printf("help                          show this help\n");
	printf("quit                          kill quests and exit\n");
}

/**
 * help for guest shell
 */
static void help_guest()
{
	printf("start [kernel=<uml-kernel>]   start a stopped guest\n");
	printf("stop                          stop a started guest\n");
	printf("addif <name>                  add an interface to the guest\n");
	printf("delif <name>                  remove the interface\n");
	printf("listif                        list guests interfaces\n");
	printf("help                          show this help\n");
	printf("quit                          quit the guest menu\n");
}

/**
 * add an iface to a guest
 */
static void add_if(guest_t *guest, char *name)
{
	iface_t *iface;
	
	iface = guest->create_iface(guest, name);
	if (iface)
	{
		printf("created guest interface '%s' connected to '%s'\n",
			   iface->get_guestif(iface), iface->get_hostif(iface));
	}
	else
	{
		printf("failed to create guest interface\n");
	}
}

/**
 * delete an iface from a guest
 */
static void del_if(guest_t *guest, char *name)
{
	iface_t *iface;
	iterator_t *iterator;
	bool found = FALSE;
	
	iterator = guest->create_iface_iterator(guest);
	while (iterator->iterate(iterator, (void**)&iface))
	{
		if (streq(name, iface->get_guestif(iface)))
		{
			iterator->remove(iterator);
			printf("removing interface '%s' ('%s') from %s\n",
				   iface->get_guestif(iface), iface->get_hostif(iface),
				   guest->get_name(guest));
			iface->destroy(iface);
			found = TRUE;
			break;
		}
	}
	iterator->destroy(iterator);
	if (!found)
	{
		printf("guest '%s' has no interface named '%s'\n",
			   guest->get_name(guest), name);
	}
}

/**
 * list interfaces on a guest
 */
static void list_if(guest_t *guest)
{
	iface_t *iface;
	iterator_t *iterator;
	
	iterator = guest->create_iface_iterator(guest);
	while (iterator->iterate(iterator, (void**)&iface))
	{
		printf("'%s' => '%s'\n", iface->get_guestif(iface), iface->get_hostif(iface));

	}
	iterator->destroy(iterator);
}

/**
 * start an UML guest
 */
static void start_guest(guest_t *guest, char *line)
{
	enum {
		KERNEL = 0,
	};
	char *const opts[] = {
		[KERNEL] = "kernel",
		NULL
	};
	char *value;
	char *kernel = NULL;
	
	while (TRUE)
	{
		switch (getsubopt(&line, opts, &value))
		{
			case KERNEL:
				kernel = value;
				continue;
			default:
				break;
		}
		break;
	}
	if (kernel == NULL)
	{
		kernel = "./linux";
	}
	
	printf("starting guest '%s'... \n", guest->get_name(guest));
	if (guest->start(guest, kernel))
	{
		printf("guest '%s' is up\n", guest->get_name(guest));
	}
	else
	{
		printf("failed to start guest '%s'!\n", guest->get_name(guest));
	}
}

/**
 * stop (kill) an UML guest
 */
static void stop_guest(guest_t *guest, char *line)
{	
	printf("stopping guest '%s'...\n", guest->get_name(guest));
	guest->stop(guest);
	printf("guest '%s' is down\n", guest->get_name(guest));
}

/**
 * subshell for guests
 */
static void guest(char *name)
{
	char *line = NULL;
	char prompt[32];
	int len;
	iterator_t *iterator;
	guest_t *guest;
	bool found = FALSE;
	
	iterator = dumm->create_guest_iterator(dumm);
	while (iterator->iterate(iterator, (void**)&guest))
	{
		if (streq(name, guest->get_name(guest)))
		{
			found = TRUE;
			break;
		}
	}
	iterator->destroy(iterator);
	if (!found)
	{
		printf("guest '%s' not found\n", name);
		return;
	}
	
	len = snprintf(prompt, sizeof(prompt), "dumm@%s# ", name);
	if (len < 0 || len >= sizeof(prompt))
	{
		return;
	}

	while (TRUE)
	{
		enum {
			QUIT = 0,
			HELP,
			START,
			STOP,
			ADDIF,
			DELIF,
			LISTIF,
		};
		char *const opts[] = {
			[QUIT] = "quit",
			[HELP] = "help",
			[START] = "start",
			[STOP] = "stop",
			[ADDIF] = "addif",
			[DELIF] = "delif",
			[LISTIF] = "listif",
			NULL
		};
		char *pos, *value;
		
		free(line);
		line = readline(prompt);
		if (line == NULL || *line == '\0')
		{
			continue;
		}
		add_history(line);
		pos = line;
		while (*pos != '\0')
		{
			if (*pos == ' ')
			{
				*pos = ',';
			}
			pos++;
		}
		pos = line;
		switch (getsubopt(&pos, opts, &value))
		{
			case QUIT:
				free(line);
				break;
			case HELP:
				help_guest();
				continue;
			case START:
				start_guest(guest, pos);
				continue;
			case STOP:
				stop_guest(guest, pos);
				continue;
			case ADDIF:
				add_if(guest, pos);
				continue;
			case DELIF:
				del_if(guest, pos);
				continue;
			case LISTIF:
				list_if(guest);
				continue;
			default:
				printf("command unknown: '%s'\n", line);
				continue;
		}
		break;
	}
}

/**
 * create an UML guest
 */
static void create_guest(char *line)
{
	enum {
		NAME = 0,
		MASTER,
		MEMORY,
	};
	char *const opts[] = {
		[NAME] = "name",
		[MASTER] = "master",
		[MEMORY] = "memory",
		NULL
	};
	char *value;
	char *name = NULL;
	char *master = NULL;
	int mem = 0;
	
	while (TRUE)
	{
		switch (getsubopt(&line, opts, &value))
		{
			case NAME:
				name = value;
				continue;
			case MASTER:
				master = value;
				continue;
			case MEMORY:
				if (value)
				{
					mem = atoi(value);
				}
				continue;
			default:
				break;
		}
		break;
	}
	if (name == NULL)
	{
		printf("option 'name' is required.\n");
		help();
		return;
	}
	if (master == NULL)
	{
		master = "master";
	}
	if (mem == 0)
	{
		mem = 128;
	}
	if (dumm->create_guest(dumm, name, master, mem))
	{
		printf("guest '%s' created\n", name);
		guest(name);
	}
	else
	{
		printf("failed to create guest '%s'!\n", name);
	}
}

/**
 * list running UML guests
 */
static void list()
{
	iterator_t *guests, *ifaces;
	guest_t *guest;
	iface_t *iface;
	
	guests = dumm->create_guest_iterator(dumm);
	while (guests->iterate(guests, (void**)&guest))
	{
		printf("%s (%N)\n", guest->get_name(guest),
			   guest_state_names, guest->get_state(guest));
		ifaces = guest->create_iface_iterator(guest);
		while (ifaces->iterate(ifaces, (void**)&iface))
		{
			printf("  '%s' => '%s'\n",
				   iface->get_guestif(iface), iface->get_hostif(iface));
		}
		ifaces->destroy(ifaces);
	}
	guests->destroy(guests);
}

/**
 * Signal handler 
 */
void signal_action(int sig, siginfo_t *info, void *ucontext)
{
	if (sig == SIGCHLD)
	{
		dumm->sigchild_handler(dumm, info);
	}
	else
	{
		dumm->destroy(dumm);
		clear_history();
		printf("\n");
		exit(0);
	}
}

/**
 * main routine, parses args and reads from console
 */
int main(int argc, char *argv[])
{
	char *line = NULL;
	struct sigaction action;

	while (TRUE)
	{
		struct option options[] = {
			{"dir", 1, 0, 0},
			{"help", 0, 0, 0},
			{0, 0, 0, 0}
		};
		
		switch (getopt_long(argc, argv, "d:h", options, NULL)) 
		{
			case -1:
				break;
			case 'd':
				if (chdir(optarg))
				{
					printf("changing to directory '%s' failed.\n", optarg);
					return 1;
				}
				continue;
			case 'h':
				usage();
				return 0;
			default:
				usage();
				return 1;
		}
		break;
	}
	
	dumm = dumm_create();
	
	memset(&action, 0, sizeof(action));
	action.sa_sigaction = signal_action;
	action.sa_flags = SA_SIGINFO;
	if (sigaction(SIGCHLD, &action, NULL) != 0 ||
		sigaction(SIGINT, &action, NULL) != 0 ||
		sigaction(SIGQUIT, &action, NULL) != 0 ||
		sigaction(SIGTERM, &action, NULL) != 0)
	{
		printf("signal handler setup failed: %m.\n");
		return 1;
	}

	while (TRUE)
	{
		enum {
			QUIT = 0,
			HELP,
			CREATE,
			LIST,
			GUEST,
		};
		char *const opts[] = {
			[QUIT] = "quit",
			[HELP] = "help",
			[CREATE] = "create",
			[LIST] = "list",
			[GUEST] = "guest",
			NULL
		};
		char *pos, *value;
		
		free(line);
		line = readline("dumm# ");
		if (line == NULL || *line == '\0')
		{
			continue;
		}
		
		add_history(line);
		pos = line;
		while (*pos != '\0')
		{
			if (*pos == ' ')
			{
				*pos = ',';
			}
			pos++;
		}
		pos = line;
		switch (getsubopt(&pos, opts, &value))
		{
			case QUIT:
				free(line);
				break;
			case HELP:
				help();
				continue;
			case CREATE:
				create_guest(pos);
				continue;
			case LIST:
				list();
				continue;
			case GUEST:
				guest(pos);
				continue;
			default:
				printf("command unknown: '%s'\n", line);
				continue;
		}
		break;
	}
	dumm->destroy(dumm);
	clear_history();
	return 0;
}

