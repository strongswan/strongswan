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
 * readline() wrapper
 */
static char* get_line(char *format, ...)
{
	char *line = NULL;
	char *prompt = "";
	va_list args;
	
	va_start(args, format);
	vasprintf(&prompt, format, args);
	va_end(args);
	
	while (TRUE)
	{
		line = readline(prompt);
		if (line == NULL)
		{
			continue;
		}
		if (*line == '\0')
		{
			free(line);
			continue;
		}
		add_history(line);
		break;
	}
	free(prompt);
	return line;
}

/**
 * get a guest by name
 */
static guest_t* get_guest(char *name)
{
	iterator_t *iterator;
	guest_t *guest = NULL;
	
	iterator = dumm->create_guest_iterator(dumm);
	while (iterator->iterate(iterator, (void**)&guest))
	{
		if (streq(guest->get_name(guest), name))
		{
			break;
		}
		guest = NULL;
	}
	iterator->destroy(iterator);
	return guest;
}

/**
 * get a bridge by name
 */
static bridge_t* get_bridge(char *name)
{
	iterator_t *iterator;
	bridge_t *bridge = NULL;
	
	iterator = dumm->create_bridge_iterator(dumm);
	while (iterator->iterate(iterator, (void**)&bridge))
	{
		if (streq(bridge->get_name(bridge), name))
		{
			break;
		}
		bridge = NULL;
	}
	iterator->destroy(iterator);
	return bridge;
}

/**
 * get an interface by guest name
 */
static iface_t* get_iface(char *name, char *ifname)
{
	iterator_t *guests, *ifaces;
	guest_t *guest;
	iface_t *iface;
	
	guests = dumm->create_guest_iterator(dumm);
	while (guests->iterate(guests, (void**)&guest))
	{
		if (streq(guest->get_name(guest), name))
		{
			iface = NULL;
			ifaces = guest->create_iface_iterator(guest);
			while (ifaces->iterate(ifaces, (void**)&iface))
			{
				if (streq(iface->get_guestif(iface), ifname))
				{
					break;
				}
				iface = NULL;
			}
			ifaces->destroy(ifaces);
			if (iface)
			{
				break;
			}
		}
	}
	guests->destroy(guests);
	return iface;
}

static void guest_addif_menu(guest_t *guest)
{
	char *name;
	
	name = get_line("interface name: ");
	
	if (!guest->create_iface(guest, name))
	{
		printf("creating interface failed\n");
	}
	free(name);
}

static void guest_delif_menu(guest_t *guest)
{
	char *name;
	iface_t *iface;
	iterator_t *iterator;
	bool found = FALSE;
	
	name = get_line("interface name: ");
	
	iterator = guest->create_iface_iterator(guest);
	while (iterator->iterate(iterator, (void**)&iface))
	{
		if (streq(iface->get_guestif(iface), name))
		{
			iterator->remove(iterator);
			iface->destroy(iface);
			found = TRUE;
			break;
		}
	}
	iterator->destroy(iterator);
	
	if (!found)
	{
		printf("interface '%s' not found\n");
	}
	free(name);
}

static void guest_menu(guest_t *guest)
{
	while (TRUE)
	{
		char *line = get_line("guest/%s# ", guest->get_name(guest));
		
		if (streq(line, "back"))
		{
			free(line);
			break;
		}
		else if (streq(line, "start"))
		{
			if (guest->start(guest))
			{
				printf("guest '%s' is booting\n", guest->get_name(guest));
			}
			else
			{
				printf("failed to start guest '%s'\n", guest->get_name(guest));
			}
		}
		else if (streq(line, "stop"))
		{
			printf("stopping guest '%s'...\n", guest->get_name(guest));
			guest->stop(guest);
			printf("guest '%s' is down\n", guest->get_name(guest));
		}
		else if (streq(line, "addif"))
		{
			guest_addif_menu(guest);
		}
		else if (streq(line, "delif"))
		{
			guest_delif_menu(guest);
		}
		else
		{
			printf("back|start|stop|addif|delif\n");
		}
		free(line);
	}
}

static void guest_create_menu()
{
	char *name, *kernel, *master, *mem;
	guest_t *guest;
	
	name = get_line("guest name: ");
	kernel = get_line("kernel image: ");
	master = get_line("master filesystem: ");
	mem = get_line("amount of memory in MB: ");
	
	guest = dumm->create_guest(dumm, name, kernel, master, atoi(mem));
	if (guest)
	{
		printf("guest '%s' created\n", guest->get_name(guest));
		guest_menu(guest);
	}
	else
	{
		printf("failed to create guest '%s'\n", name);
	}
	free(name);
	free(kernel);
	free(master);
	free(mem);
}

static void guest_list_menu()
{
	while (TRUE)
	{
		iterator_t *iterator;
		guest_t *guest;
		char *line = get_line("guest# ");
		
		if (streq(line, "back"))
		{
			free(line);
			break;
		}
		else if (streq(line, "list"))
		{
			iterator = dumm->create_guest_iterator(dumm);
			while (iterator->iterate(iterator, (void**)&guest))
			{
				printf("%s\n", guest->get_name(guest));
			}
			iterator->destroy(iterator);
		}
		else if (streq(line, "create"))
		{
			guest_create_menu();
		}
		else
		{
			guest = get_guest(line);
			if (guest)
			{
				guest_menu(guest);
			}
			else
			{
				printf("back|list|create|<guest>\n");
			}
		}
		free(line);
	}
}

static void bridge_addif_menu(bridge_t *bridge)
{
	char *name, *ifname;
	iface_t *iface;
	
	name = get_line("guest name: ");
	ifname = get_line("interface name: ");
	
	iface = get_iface(name, ifname);
	if (!iface)
	{
		printf("guest '%s' has no interface named '%s'\n", name, ifname);
	}
	else if (!bridge->connect_iface(bridge, iface))
	{
		printf("failed to add interface '%s' to bridge '%s'\n", ifname,
			   bridge->get_name(bridge));
	}
	free(name);
	free(ifname);
}

static void bridge_delif_menu(bridge_t *bridge)
{
	char *name, *ifname;
	iface_t *iface;
	
	name = get_line("guest name: ");
	ifname = get_line("interface name: ");
	
	iface = get_iface(name, ifname);
	if (!iface)
	{
		printf("guest '%s' has no interface named '%s'\n", name, ifname);
	}
	else if (!bridge->disconnect_iface(bridge, iface))
	{
		printf("failed to remove interface '%s' from bridge '%s'\n", ifname,
			   bridge->get_name(bridge));
	}
	free(name);
	free(ifname);
}

static void bridge_menu(bridge_t *bridge)
{
	while (TRUE)
	{
		char *line = get_line("bridge/%s# ", bridge->get_name(bridge));
		
		if (streq(line, "back"))
		{
			free(line);
			break;
		}
		else if (streq(line, "list"))
		{
			iterator_t *iterator;
			iface_t *iface;

			iterator = bridge->create_iface_iterator(bridge);
			while (iterator->iterate(iterator, (void**)&iface))
			{
				printf("%s (%s)\n", iface->get_guestif(iface), iface->get_hostif(iface));
			}
			iterator->destroy(iterator);
		}
		else if (streq(line, "addif"))
		{
			bridge_addif_menu(bridge);
		}
		else if (streq(line, "delif"))
		{
			bridge_delif_menu(bridge);
		}
		else
		{
			printf("back|list|addif|delif\n");
		}
		free(line);
	}
}

static void bridge_create_menu()
{
	char *name;
	bridge_t *bridge;
	
	name = get_line("bridge name: ");
	
	bridge = dumm->create_bridge(dumm, name);
	if (bridge)
	{
		printf("bridge '%s' created\n", bridge->get_name(bridge));
		bridge_menu(bridge);
	}
	else
	{
		printf("failed to create bridge '%s'\n", name);
	}
	free(name);
}

static void bridge_list_menu()
{
	while (TRUE)
	{
		iterator_t *iterator;
		bridge_t *bridge;
		char *line = get_line("bridge# ");
		
		if (streq(line, "back"))
		{
			free(line);
			break;
		}
		else if (streq(line, "list"))
		{
			iterator = dumm->create_bridge_iterator(dumm);
			while (iterator->iterate(iterator, (void**)&bridge))
			{
				printf("%s\n", bridge->get_name(bridge));
			}
			iterator->destroy(iterator);
		}
		else if (streq(line, "create"))
		{
			bridge_create_menu();
		}
		else
		{
			bridge = get_bridge(line);
			if (bridge)
			{
				bridge_menu(bridge);
			}
			else
			{
				printf("back|list|create|<bridge>\n");
			}
		}
		free(line);
	}
}

static void scenario_menu()
{
	char *name;
	
	name = get_line("scenario name (or 'none'): ");
	
	dumm->load_scenario(dumm, streq(name, "none") ? NULL : name);
	
	free(name);
}

/**
 * Signal handler 
 */
void signal_action(int sig, siginfo_t *info, void *ucontext)
{
	dumm->destroy(dumm);
	clear_history();
	exit(0);
}

/**
 * main routine, parses args and reads from console
 */
int main(int argc, char *argv[])
{
	struct sigaction action;
	char *dir = ".";

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
				dir = optarg;
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
	
	memset(&action, 0, sizeof(action));
	action.sa_sigaction = signal_action;
	action.sa_flags = SA_SIGINFO;
	if (sigaction(SIGINT, &action, NULL) != 0 ||
		sigaction(SIGQUIT, &action, NULL) != 0 ||
		sigaction(SIGTERM, &action, NULL) != 0)
	{
		printf("signal handler setup failed: %m.\n");
		return 1;
	}
	
	dumm = dumm_create(dir);
	while (TRUE)
	{
		char *line = get_line("# ");
		
		if (streq(line, "quit"))
		{
			free(line);
			break;
		}
		else if (streq(line, "guest"))
		{
			guest_list_menu();
		}
		else if (streq(line, "bridge"))
		{
			bridge_list_menu();
		}
		else if (streq(line, "scenario"))
		{
			scenario_menu();
		}
		else
		{
			printf("quit|guest|bridge|scenario\n");
		}
		free(line);
	}
	dumm->destroy(dumm);
	clear_history();
	return 0;
}

