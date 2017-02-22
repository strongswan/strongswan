/*
 * Copyright (C) 2016 Michael Schmoock
 * COCUS Next GmbH <mschmoock@cocus.com>
 *
 * Copyright (C) 2013 Tobias Brunner
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

#define _GNU_SOURCE
#include <stdio.h>
#include <unistd.h>

#include "quota_invoke.h"

#include <utils/process.h>
#include <hydra.h>
#include <daemon.h>
#include <config/child_cfg.h>

/**
 * Allocate and push a format string to the environment
 */
static bool push_env(char *envp[], u_int count, char *fmt, ...)
{
	int i = 0;
	char *str;
	va_list args;

	while (envp[i])
	{
		if (++i + 1 >= count)
		{
			return FALSE;
		}
	}
	va_start(args, fmt);
	if (vasprintf(&str, fmt, args) >= 0)
	{
		envp[i] = str;
	}
	va_end(args);
	return envp[i] != NULL;
}

/**
 * Free all allocated environment strings
 */
static void free_env(char *envp[])
{
	int i;

	for (i = 0; envp[i]; i++)
	{
		free(envp[i]);
	}
}

/**
 * Push variables for local/remote virtual IPs
 */
static void push_vip_env( ike_sa_t *ike_sa,
						 char *envp[], u_int count, bool local)
{
	enumerator_t *enumerator;
	host_t *host;
	int v4 = 0, v6 = 0;
	bool first = TRUE;

	enumerator = ike_sa->create_virtual_ip_enumerator(ike_sa, local);
	while (enumerator->enumerate(enumerator, &host))
	{
		if (first)
		{	/* legacy variable for first VIP */
			first = FALSE;
			push_env(envp, count, "QUOTA_%s_SOURCEIP=%H",
					 local ? "MY" : "PEER", host);
		}
		switch (host->get_family(host))
		{
			case AF_INET:
				push_env(envp, count, "QUOTA_%s_SOURCEIP4_%d=%H",
						 local ? "MY" : "PEER", ++v4, host);
				break;
			case AF_INET6:
				push_env(envp, count, "QUOTA_%s_SOURCEIP6_%d=%H",
						 local ? "MY" : "PEER", ++v6, host);
				break;
			default:
				continue;
		}
	}
	enumerator->destroy(enumerator);
}

/**
 * Invoke the quota script once for given traffic selectors
 */
void quota_invoke(ike_sa_t *ike_sa, quota_event_t status, quota_accounting_entry_t* entry)
{
	host_t *me, *other;
	int out;
	FILE *shell;
	process_t *process;
	char *envp[128] = {};

	me = ike_sa->get_my_host(ike_sa);
	other = ike_sa->get_other_host(ike_sa);

	push_env(envp, countof(envp), "QUOTA_VERSION=1.0");
	push_env(envp, countof(envp), "QUOTA_EVENT=%s",
			status == QUOTA_START ? "start" :
			status == QUOTA_STOP ? "stop" :
			status == QUOTA_UPDATE ? "update" : "");
	push_env(envp, countof(envp), "QUOTA_UNIQUEID=%u", ike_sa->get_unique_id(ike_sa));
	push_env(envp, countof(envp), "QUOTA_ME=%H", me);
	push_env(envp, countof(envp), "QUOTA_MY_ID=%Y", ike_sa->get_my_id(ike_sa));
	push_env(envp, countof(envp), "QUOTA_PEER=%H", other);
	push_env(envp, countof(envp), "QUOTA_PEER_ID=%Y", ike_sa->get_other_id(ike_sa));
	push_vip_env(ike_sa, envp, countof(envp), TRUE);
	push_vip_env(ike_sa, envp, countof(envp), FALSE);

	// Push Accounting data
	if (status != QUOTA_START)
	{
		push_env(envp, countof(envp), "QUOTA_BYTES_IN=%llu", entry->usage.bytes.received);
		push_env(envp, countof(envp), "QUOTA_PACKETS_IN=%llu", entry->usage.packets.received);
		push_env(envp, countof(envp), "QUOTA_BYTES_OUT=%llu", entry->usage.bytes.sent);
		push_env(envp, countof(envp), "QUOTA_PACKETS_OUT=%llu", entry->usage.packets.sent);
		push_env(envp, countof(envp), "QUOTA_DURATION=%u", time_monotonic(NULL) - entry->created);
		if (status == QUOTA_STOP)
		{
			push_env(envp, countof(envp), "QUOTA_TERMINATE_CAUSE=%u", entry->cause);
		}
	}

	char* script;
	script = lib->settings->get_str(lib->settings, "%s.plugins.quota.script", NULL, lib->ns);
	DBG2(DBG_CHD, "quota calling script: %s", script);

	process = process_start_shell(envp, NULL, &out, NULL, "2>&1 %s", script);
	if (process)
	{
		shell = fdopen(out, "r");
		if (shell)
		{
			while (TRUE)
			{
				char resp[128];

				if (fgets(resp, sizeof(resp), shell) == NULL)
				{
					if (ferror(shell))
					{
						DBG1(DBG_CHD, "error reading from quota script %s", script);
					}
					break;
				}
				else
				{
					char *e = resp + strlen(resp);
					if (e > resp && e[-1] == '\n')
					{
						e[-1] = '\0';
					}
					DBG1(DBG_CHD, "quota: %s", resp);
				}
			}
			fclose(shell);
		}
		else
		{
			close(out);
		}
		process->wait(process, NULL);
	}
	free_env(envp);
}

