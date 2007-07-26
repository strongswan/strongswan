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
	printf("start name=<name> [options]   start a guest named <name>\n");
	printf("                              additional options:\n");
	printf("                                kernel=<uml-kernel>\n");
	printf("                                master=<read-only root files>\n");
	printf("                                memory=<guest memory in MB>\n");
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
	printf("addif <name>                  add an interface to the guest\n");
	printf("delif <name>                  remove the interface\n");
	printf("listif                        list guests interfaces\n");
	printf("help                          show this help\n");
	printf("quit                          quit the guest menu\n");
}

/**
 * start an UML guest
 */
static void start(dumm_t *dumm, char *line)
{
	enum {
		NAME = 0,
		MASTER,
		KERNEL,
		MEMORY,
	};
	char *const opts[] = {
		[NAME] = "name",
		[MASTER] = "master",
		[KERNEL] = "kernel",
		[MEMORY] = "memory",
		NULL
	};
	char *value;
	char *name = NULL;
	char *kernel = NULL;
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
			case KERNEL:
				kernel = value;
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
	if (kernel == NULL)
	{
		kernel = "./linux";
	}
	if (master == NULL)
	{
		master = "master";
	}
	if (mem == 0)
	{
		mem = 128;
	}
	
	if (dumm->start_guest(dumm, name, kernel, master, mem))
	{
		printf("starting guest '%s'\n", name);
	}
	else
	{
		printf("starting guest '%s' failed\n", name);
	}
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
 * subshell for guests
 */
static void guest(dumm_t *dumm, char *name)
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
			ADDIF,
			DELIF,
			LISTIF,
		};
		char *const opts[] = {
			[QUIT] = "quit",
			[HELP] = "help",
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
 * list running UML guests
 */
static void list(dumm_t *dumm)
{
	iterator_t *guests, *ifaces;
	guest_t *guest;
	iface_t *iface;
	
	guests = dumm->create_guest_iterator(dumm);
	while (guests->iterate(guests, (void**)&guest))
	{
		printf("%s\n", guest->get_name(guest));
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
 * main routine, parses args and reads from console
 */
int main(int argc, char *argv[])
{
	dumm_t *dumm;
	char *line = NULL;

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

	while (TRUE)
	{
		enum {
			QUIT = 0,
			HELP,
			START,
			LIST,
			GUEST,
		};
		char *const opts[] = {
			[QUIT] = "quit",
			[HELP] = "help",
			[START] = "start",
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
			case START:
				start(dumm, pos);
				continue;
			case LIST:
				list(dumm);
				continue;
			case GUEST:
				guest(dumm, pos);
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

