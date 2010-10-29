/*
 * Copyright (C) 2010 Martin Willi
 * Copyright (C) 2010 revosec AG
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
#include <unistd.h>
#include <stdio.h>
#include <errno.h>
#include <signal.h>
#include <getopt.h>
#include <dlfcn.h>
#include <libgen.h>

#include "conftest.h"
#include "config.h"
#include "hooks/hook.h"

#include <threading/thread.h>

/**
 * Conftest globals struct
 */
conftest_t *conftest;

/**
 * Print usage information
 */
static void usage(FILE *out)
{
	fprintf(out, "Usage:\n");
	fprintf(out, "  --help           show usage information\n");
	fprintf(out, "  --version        show conftest version\n");
	fprintf(out, "  --suite <file>   global testsuite configuration "
									 "(default: ./suite.conf)\n");
	fprintf(out, "  --test <file>    test specific configuration\n");
}

/**
 * Handle SIGSEGV/SIGILL signals raised by threads
 */
static void segv_handler(int signal)
{
	fprintf(stderr, "thread %u received %d\n", thread_current_id(), signal);
	abort();
}

/**
 * Load suite and test specific configurations
 */
static bool load_configs(char *suite_file, char *test_file)
{
	if (!test_file)
	{
		fprintf(stderr, "Missing test configuration file.\n");
		return FALSE;
	}
	if (access(suite_file, R_OK) != 0)
	{
		fprintf(stderr, "Reading suite configuration file '%s' failed: %s.\n",
				suite_file, strerror(errno));
		return FALSE;
	}
	if (access(test_file, R_OK) != 0)
	{
		fprintf(stderr, "Reading test configuration file '%s' failed: %s.\n",
				test_file, strerror(errno));
		return FALSE;
	}
	conftest->suite = settings_create(suite_file);
	conftest->test = settings_create(test_file);
	suite_file = dirname(suite_file);
	test_file = dirname(test_file);
	conftest->suite_dir = strdup(suite_file);
	conftest->test_dir = strdup(test_file);
	return TRUE;
}

/**
 * Load certificates from the confiuguration file
 */
static bool load_certs(settings_t *settings, char *dir)
{
	enumerator_t *enumerator;
	char *key, *value, wd[PATH_MAX];
	certificate_t *cert;

	if (getcwd(wd, sizeof(wd)) == NULL)
	{
		fprintf(stderr, "getting cwd failed: %s\n", strerror(errno));
		return FALSE;
	}
	if (chdir(dir) != 0)
	{
		fprintf(stderr, "opening directory '%s' failed: %s\n",
				dir, strerror(errno));
		return FALSE;
	}

	enumerator = settings->create_key_value_enumerator(settings, "certs.trusted");
	while (enumerator->enumerate(enumerator, &key, &value))
	{
		cert = lib->creds->create(lib->creds, CRED_CERTIFICATE, CERT_X509,
								  BUILD_FROM_FILE, value, BUILD_END);
		if (!cert)
		{
			fprintf(stderr, "loading trusted certificate "
					"'%s' from '%s' failed\n", key, value);
			enumerator->destroy(enumerator);
			return FALSE;
		}
		conftest->creds->add_cert(conftest->creds, TRUE, cert);
	}
	enumerator->destroy(enumerator);

	enumerator = settings->create_key_value_enumerator(settings, "certs.untrusted");
	while (enumerator->enumerate(enumerator, &key, &value))
	{
		cert = lib->creds->create(lib->creds, CRED_CERTIFICATE, CERT_X509,
								  BUILD_FROM_FILE, value, BUILD_END);
		if (!cert)
		{
			fprintf(stderr, "loading untrusted certificate "
					"'%s' from '%s' failed\n", key, value);
			enumerator->destroy(enumerator);
			return FALSE;
		}
		conftest->creds->add_cert(conftest->creds, FALSE, cert);
	}
	enumerator->destroy(enumerator);

	if (chdir(wd) != 0)
	{
		fprintf(stderr, "opening directory '%s' failed: %s\n",
				wd, strerror(errno));
		return FALSE;
	}
	return TRUE;
}

/**
 * Load configured hooks
 */
static bool load_hooks()
{
	enumerator_t *enumerator;
	char *name, buf[64];
	hook_t *(*create)(void);
	hook_t *hook;

	enumerator = conftest->test->create_section_enumerator(conftest->test,
														   "hooks");
	while (enumerator->enumerate(enumerator, &name))
	{
		snprintf(buf, sizeof(buf), "%s_hook_create", name);
		create = dlsym(RTLD_DEFAULT, buf);
		if (create)
		{
			hook = create();
			if (hook)
			{
				conftest->hooks->insert_last(conftest->hooks, hook);
				charon->bus->add_listener(charon->bus, &hook->listener);
			}
		}
		else
		{
			fprintf(stderr, "dlsym() for hook '%s' failed: %s\n", name, dlerror());
			enumerator->destroy(enumerator);
			return FALSE;
		}
	}
	enumerator->destroy(enumerator);
	return TRUE;
}

/**
 * atexit() cleanup handler
 */
static void cleanup()
{
	hook_t *hook;

	DESTROY_IF(conftest->suite);
	DESTROY_IF(conftest->test);
	lib->credmgr->remove_set(lib->credmgr, &conftest->creds->set);
	conftest->creds->destroy(conftest->creds);
	while (conftest->hooks->remove_last(conftest->hooks,
										(void**)&hook) == SUCCESS)
	{
		charon->bus->remove_listener(charon->bus, &hook->listener);
		hook->destroy(hook);
	}
	conftest->hooks->destroy(conftest->hooks);
	if (conftest->config)
	{
		charon->backends->remove_backend(charon->backends,
										 &conftest->config->backend);
		conftest->config->destroy(conftest->config);
	}
	free(conftest->suite_dir);
	free(conftest->test_dir);
	free(conftest);
	libcharon_deinit();
	libhydra_deinit();
	library_deinit();
}

/**
 * Main function, starts the conftest daemon.
 */
int main(int argc, char *argv[])
{
	struct sigaction action;
	int status = 0;
	sigset_t set;
	int sig;
	char *suite_file = "suite.conf", *test_file = NULL;
	file_logger_t *logger;

	if (!library_init(NULL))
	{
		library_deinit();
		return SS_RC_LIBSTRONGSWAN_INTEGRITY;
	}
	if (!libhydra_init("conftest"))
	{
		libhydra_deinit();
		library_deinit();
		return SS_RC_INITIALIZATION_FAILED;
	}
	if (!libcharon_init())
	{
		libcharon_deinit();
		libhydra_deinit();
		library_deinit();
		return SS_RC_INITIALIZATION_FAILED;
	}

	INIT(conftest,
		.creds = mem_cred_create(),
	);
	logger = file_logger_create(stdout, NULL, FALSE);
	logger->set_level(logger, DBG_ANY, LEVEL_CTRL);
	charon->bus->add_listener(charon->bus, &logger->listener);
	charon->file_loggers->insert_last(charon->file_loggers, logger);

	lib->credmgr->add_set(lib->credmgr, &conftest->creds->set);
	conftest->hooks = linked_list_create();
	conftest->config = config_create();

	atexit(cleanup);

	while (TRUE)
	{
		struct option long_opts[] = {
			{ "help", no_argument, NULL, 'h' },
			{ "version", no_argument, NULL, 'v' },
			{ "suite", required_argument, NULL, 's' },
			{ "test", required_argument, NULL, 't' },
			{ 0,0,0,0 }
		};
		switch (getopt_long(argc, argv, "", long_opts, NULL))
		{
			case EOF:
				break;
			case 'h':
				usage(stdout);
				return 0;
			case 'v':
				printf("strongSwan %s conftest\n", VERSION);
				return 0;
			case 's':
				suite_file = optarg;
				continue;
			case 't':
				test_file = optarg;
				continue;
			default:
				usage(stderr);
				return 1;
		}
		break;
	}

	if (!load_configs(suite_file, test_file))
	{
		return 1;
	}
	if (!charon->initialize(charon))
	{
		return 1;
	}
	if (!load_certs(conftest->suite, suite_file) ||
		!load_certs(conftest->test, test_file))
	{
		return 1;
	}
	if (!load_hooks())
	{
		return 1;
	}
	charon->backends->add_backend(charon->backends, &conftest->config->backend);
	conftest->config->load(conftest->config, conftest->suite);
	conftest->config->load(conftest->config, conftest->test);

	/* set up thread specific handlers */
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

	/* start thread pool */
	charon->start(charon);

	/* handle SIGINT/SIGTERM in main thread */
	sigemptyset(&set);
	sigaddset(&set, SIGINT);
	sigaddset(&set, SIGHUP);
	sigaddset(&set, SIGTERM);
	sigprocmask(SIG_BLOCK, &set, NULL);

	while (sigwait(&set, &sig) == 0)
	{
		switch (sig)
		{
			case SIGINT:
			case SIGTERM:
				fprintf(stderr, "\nshutting down...\n");
				break;
			default:
				continue;
		}
		break;
	}
	return status;
}
