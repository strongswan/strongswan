/*
 * Copyright (C) 2009 Martin Willi
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

#include "command.h"


#include <stdlib.h>
#include <string.h>
#include <stdio.h>

/**
 * Registered commands.
 */
command_t cmds[CMD_MAX];

/**
 * Global options used by all subcommands
 */
struct option command_opts[CMD_MAX > MAX_OPTIONS ?: MAX_OPTIONS];

/**
 * Build long_opts for a specific command
 */
static void build_opts(command_type_t cmd)
{
	int i;

	memset(command_opts, 0, sizeof(command_opts));
	if (cmd == CMD_HELP)
	{
		for (i = 0; i < CMD_MAX; i++)
		{
			command_opts[i].name = cmds[i].cmd;
			command_opts[i].val = cmds[i].op;
		}
	}
	else
	{
		for (i = 0; cmds[cmd].options[i].name; i++)
		{
			command_opts[i].name = cmds[cmd].options[i].name;
			command_opts[i].has_arg = cmds[cmd].options[i].arg;
			command_opts[i].val = cmds[cmd].options[i].op;
		}
	}
}

/**
 * Register a command
 */
void command_register(command_type_t type, command_t command)
{
	cmds[type] = command;
}

/**
 * Print usage text, with an optional error
 */
int command_usage(command_type_t cmd, char *error)
{
	FILE *out = stdout;
	int i;

	if (error)
	{
		out = stderr;
		fprintf(out, "Error: %s\n", error);
	}
	fprintf(out, "strongSwan %s PKI tool\n", VERSION);
	fprintf(out, "usage:\n");
	if (cmd == CMD_HELP)
	{
		for (i = 0; i < CMD_MAX; i++)
		{
			fprintf(out, "  pki --%-6s %s\n", cmds[i].cmd, cmds[i].description);
		}
	}
	else
	{
		for (i = 0; cmds[cmd].line[i]; i++)
		{
			if (i == 0)
			{
				fprintf(out, "  pki --%s %s\n", cmds[cmd].cmd, cmds[cmd].line[i]);
			}
			else
			{
				fprintf(out, "               %s\n", cmds[cmd].line[i]);
			}
		}
		for (i = 0; cmds[cmd].options[i].name; i++)
		{
			fprintf(out, "        --%-8s %s\n",
					cmds[cmd].options[i].name, cmds[cmd].options[i].desc);
		}
	}
	return error != NULL;
}



/**
 * Show usage information
 */
static int help(int argc, char *argv[])
{
	return command_usage(CMD_HELP, NULL);
}

/**
 * Dispatch commands.
 */
int command_dispatch(int argc, char *argv[])
{
	int op, i;

	command_register(CMD_HELP, (command_t) {
					 help, 'h', "help", "show usage information"});
	build_opts(CMD_HELP);
	op = getopt_long(argc, argv, "", command_opts, NULL);
	for (i = 0; i < CMD_MAX; i++)
	{
		if (cmds[i].op == op)
		{
			build_opts(i);
			return cmds[i].call(argc, argv);
		}
	}
	return command_usage(CMD_HELP, "invalid operation");
}

