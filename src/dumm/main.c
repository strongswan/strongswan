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
 * show usage information (commandline arguments)
 */
static void help()
{
	printf("start name=<name> [options]   start a guest named <name>\n");
	printf("                              additional options:\n");
	printf("                                kernel=<uml-kernel>\n");
	printf("                                master=<read-only root files>\n");
	printf("                                memory=<guest memory in MB>\n");
	printf("guests                        list running guests\n");
	printf("help                          show this help\n");
	printf("quit                          kill quests and exit\n");
}

/**
 * start an UML guest
 */
static void start(umli_t *umli, char *line)
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
	
	if (umli->start_guest(umli, name, kernel, master, mem))
	{
		printf("starting guest '%s'\n", name);
	}
	else
	{
		printf("starting guest '%s' failed\n", name);
	}
}

/**
 * list running UML guests
 */
static void guests(umli_t *umli)
{
	iterator_t *iterator;
	guest_t *guest;
	
	iterator = umli->create_guest_iterator(umli);
	while (iterator->iterate(iterator, (void**)&guest))
	{
		printf("%s\n", guest->get_name(guest));
	}
	iterator->destroy(iterator);
}

/**
 * main routine, parses args and reads from console
 */
int main(int argc, char *argv[])
{
	umli_t *umli;
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
	
	umli = umli_create();

	while (TRUE)
	{
		enum {
			QUIT = 0,
			HELP,
			START,
			GUESTS,
		};
		char *const opts[] = {
			[QUIT] = "quit",
			[HELP] = "help",
			[START] = "start",
			[GUESTS] = "guests",
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
				start(umli, pos);
				continue;
			case GUESTS:
				guests(umli);
				continue;
			default:
				printf("command unknown: '%s'\n", line);
				continue;
		}
		break;
	}
	umli->destroy(umli);
	clear_history();
	return 0;
}

