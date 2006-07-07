/**
 * @file logger_manager.c
 *
 * @brief Implementation of logger_manager_t.
 *
 */

/*
 * Copyright (C) 2005-2006 Martin Willi
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
 
 
#include "logger_manager.h"

#include <definitions.h>
#include <utils/linked_list.h>

/**
 * String mappings for logger_context_t
 */
mapping_t logger_context_t_mappings[] = {
	{PARSER, "PARSER"},
	{GENERATOR, "GENERATOR"},
	{IKE_SA, "IKE_SA"},
	{IKE_SA_MANAGER, "IKE_SA_MANAGER"},
	{CHILD_SA, "CHILD_SA"},
	{MESSAGE, "MESSAGE"},
	{THREAD_POOL, "THREAD_POOL"},
	{WORKER, "WORKER"},
	{SCHEDULER, "SCHEDULER"},
	{SENDER, "SENDER"},
	{RECEIVER, "RECEIVER"},
	{SOCKET, "SOCKET"},
	{TESTER, "TESTER"},
	{DAEMON, "DAEMON"},
	{CONFIG, "CONFIG"},
	{ENCRYPTION_PAYLOAD, "ENCRYPTION_PAYLOAD"},
	{PAYLOAD, "PAYLOAD"},
	{DER_DECODER, "DER_DECODER"},
	{DER_ENCODER, "DER_ENCODER"},
	{ASN1, "ASN1"},
	{XFRM, "XFRM"},
	{LEAK_DETECT, "LEAK_DETECT"},
	{MAPPING_END, NULL},
};

struct {
	char *name;
	log_level_t level;
	bool log_thread_ids;
} logger_defaults[] = {
	{ "PARSR", ERROR|CONTROL|AUDIT|LEVEL0,	TRUE }, /* PARSER */
	{ "GNRAT", ERROR|CONTROL|AUDIT|LEVEL0,	TRUE }, /* GENERATOR */
	{ "IKESA", ERROR|CONTROL|AUDIT|LEVEL0,	TRUE }, /* IKE_SA */
	{ "SAMGR", ERROR|CONTROL|AUDIT|LEVEL0,	TRUE }, /* IKE_SA_MANAGER */
	{ "CHDSA", ERROR|CONTROL|AUDIT|LEVEL0,	TRUE }, /* CHILD_SA */
	{ "MESSG", ERROR|CONTROL|AUDIT|LEVEL0,	TRUE }, /* MESSAGE */
	{ "TPOOL", ERROR|CONTROL|AUDIT|LEVEL0,	TRUE }, /* THREAD_POOL */
	{ "WORKR", ERROR|CONTROL|AUDIT|LEVEL0,	TRUE }, /* WORKER */
	{ "SCHED", ERROR|CONTROL|AUDIT|LEVEL0,	TRUE }, /* SCHEDULER */
	{ "SENDR", ERROR|CONTROL|AUDIT|LEVEL0,	TRUE }, /* SENDER */
	{ "RECVR", ERROR|CONTROL|AUDIT|LEVEL0,	TRUE }, /* RECEIVER */
	{ "SOCKT", ERROR|CONTROL|AUDIT|LEVEL0,	TRUE }, /* SOCKET */
	{ "TESTR", ERROR|CONTROL|AUDIT|LEVEL0,	TRUE }, /* TESTER */
	{ "DAEMN", ERROR|CONTROL|AUDIT|LEVEL0,	TRUE }, /* DAEMON */
	{ "CONFG", ERROR|CONTROL|AUDIT|LEVEL0,	TRUE }, /* CONFIG */
	{ "ENCPL", ERROR|CONTROL|AUDIT|LEVEL0,	TRUE }, /* ENCRYPTION_PAYLOAD */
	{ "PAYLD", ERROR|CONTROL|AUDIT|LEVEL0,	TRUE }, /* PAYLOAD */
	{ "DERDC", ERROR|CONTROL|AUDIT|LEVEL0,	TRUE }, /* DER_DECODER */
	{ "DEREC", ERROR|CONTROL|AUDIT|LEVEL0,	TRUE }, /* DER_ENCODER */
	{ "ASN_1", ERROR|CONTROL|AUDIT|LEVEL0,	TRUE }, /* ASN1 */
	{ "XFRM ", ERROR|CONTROL|AUDIT|LEVEL0,	TRUE }, /* XFRM */
	{ "LEAKD", ERROR|CONTROL|AUDIT|LEVEL0,	TRUE }, /* LEAK_DETECT */
};


typedef struct private_logger_manager_t private_logger_manager_t;

/** 
 * Private data of logger_manager_t object.
 */
struct private_logger_manager_t { 	
	/**
	 * Public data.
	 */
	logger_manager_t public;

	/**
	 * Array of loggers, one for each context
	 */
	logger_t *loggers[LOGGER_CONTEXT_ROOF];
};

/**
 * The one and only instance of the logger manager
 */
static private_logger_manager_t private_logger_manager;

/**
 * Exported pointer for the logger manager
 */
logger_manager_t *logger_manager = (logger_manager_t *)&private_logger_manager;

/**
 * Implementation of logger_manager_t.get_logger.
 */
static logger_t *get_logger(private_logger_manager_t *this, logger_context_t context)
{
	return this->loggers[context];
}

/**
 * Implementation of logger_manager_t.get_log_level.
 */
static log_level_t get_log_level (private_logger_manager_t *this, logger_context_t context)
{
	return this->loggers[context]->get_level(this->loggers[context]);
}

/**
 * Implementation of private_logger_manager_t.enable_log_level.
 */
static void enable_log_level(private_logger_manager_t *this, logger_context_t context, log_level_t level)
{	
	if (context == ALL_LOGGERS)
	{
		for (context = 0; context < LOGGER_CONTEXT_ROOF; context++)
		{
			this->loggers[context]->enable_level(this->loggers[context], level);
		}
	}
	else
	{
		this->loggers[context]->enable_level(this->loggers[context], level);
	}
}

/**
 * Implementation of private_logger_manager_t.disable_log_level.
 */
static void disable_log_level(private_logger_manager_t *this, logger_context_t context, log_level_t level)
{	
	if (context == ALL_LOGGERS)
	{
		for (context = 0; context < LOGGER_CONTEXT_ROOF; context++)
		{
			this->loggers[context]->disable_level(this->loggers[context], level);
		}
	}
	else
	{
		this->loggers[context]->disable_level(this->loggers[context], level);
	}
}

/**
 * Implementation of private_logger_manager_t.set_output.
 */
static void set_output(private_logger_manager_t *this, logger_context_t context, FILE *output)
{
	if (context == ALL_LOGGERS)
	{
		for (context = 0; context < LOGGER_CONTEXT_ROOF; context++)
		{
			this->loggers[context]->set_output(this->loggers[context], output);
		}
	}
	else
	{
		this->loggers[context]->set_output(this->loggers[context], output);
	}
}


/**
 * Creates the instance of the logger manager at library startup
 */
void logger_manager_init()
{
	int i;
	
	logger_manager->get_logger = (logger_t *(*)(logger_manager_t*,logger_context_t context))get_logger;
	logger_manager->get_log_level = (log_level_t (*)(logger_manager_t *, logger_context_t)) get_log_level;
	logger_manager->enable_log_level = (void (*)(logger_manager_t *, logger_context_t, log_level_t)) enable_log_level;
	logger_manager->disable_log_level = (void (*)(logger_manager_t *, logger_context_t, log_level_t)) disable_log_level;
	logger_manager->set_output = (void (*)(logger_manager_t *, logger_context_t, FILE*)) set_output;
	
	for (i = 0; i < LOGGER_CONTEXT_ROOF; i++)
	{
		private_logger_manager.loggers[i] = logger_create(logger_defaults[i].name,
														  logger_defaults[i].level, 
														  logger_defaults[i].log_thread_ids, 
														  INITIAL_LOG_OUTPUT);
	}
	
}

/**
 * Destroy the logger manager at library exit
 */
void logger_manager_cleanup()
{
	int i;
	for (i = 0; i < LOGGER_CONTEXT_ROOF; i++)
	{
		private_logger_manager.loggers[i]->destroy(private_logger_manager.loggers[i]);
	}
}
