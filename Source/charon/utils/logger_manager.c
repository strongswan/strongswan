/**
 * @file logger_manager.c
 *
 * @brief Implementation of logger_manager_t.
 *
 */

/*
 * Copyright (C) 2005 Jan Hutter, Martin Willi
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

#include <daemon.h>
#include <definitions.h>
#include <utils/allocator.h>
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
	{MAPPING_END, NULL},
};

struct {
	char *name;
	log_level_t level;
	bool log_thread_ids;
	FILE *output;
} logger_defaults[] = {
	{ "PARSR", ERROR|CONTROL|AUDIT|LEVEL0,	TRUE,  NULL}, /* PARSER */
	{ "GNRAT", ERROR|CONTROL|AUDIT|LEVEL0,	TRUE,  NULL}, /* GENERATOR */
	{ "IKESA", ERROR|CONTROL|AUDIT|LEVEL0,	TRUE,  NULL}, /* IKE_SA */
	{ "SAMGR", ERROR|CONTROL|AUDIT|LEVEL0,	TRUE,  NULL}, /* IKE_SA_MANAGER */
	{ "CHDSA", ERROR|CONTROL|AUDIT|LEVEL0,	TRUE,  NULL}, /* CHILD_SA */
	{ "MESSG", ERROR|CONTROL|AUDIT|LEVEL0,	TRUE,  NULL}, /* MESSAGE */
	{ "TPOOL", ERROR|CONTROL|AUDIT|LEVEL0,	FALSE, NULL}, /* THREAD_POOL */
	{ "WORKR", ERROR|CONTROL|AUDIT|LEVEL0,	TRUE,  NULL}, /* WORKER */
	{ "SCHED", ERROR|CONTROL|AUDIT|LEVEL0,	FALSE, NULL}, /* SCHEDULER */
	{ "SENDR", ERROR|CONTROL|AUDIT|LEVEL0,	FALSE, NULL}, /* SENDER */
	{ "RECVR", ERROR|CONTROL|AUDIT|LEVEL0,	FALSE, NULL}, /* RECEIVER */
	{ "SOCKT", ERROR|CONTROL|AUDIT|LEVEL0,	FALSE, NULL}, /* SOCKET */
	{ "TESTR", ERROR|CONTROL|AUDIT|LEVEL0,	FALSE, NULL}, /* TESTER */
	{ "DAEMN", ERROR|CONTROL|AUDIT|LEVEL0,	FALSE, NULL}, /* DAEMON */
	{ "CONFG", ERROR|CONTROL|AUDIT|LEVEL0,	TRUE,  NULL}, /* CONFIG */
	{ "ENCPL", ERROR|CONTROL|AUDIT|LEVEL0,	TRUE,  NULL}, /* ENCRYPTION_PAYLOAD */
	{ "PAYLD", ERROR|CONTROL|AUDIT|LEVEL0,	TRUE,  NULL}, /* PAYLOAD */
	{ "DERDC", ERROR|CONTROL|AUDIT|LEVEL0,	TRUE,  NULL}, /* DER_DECODER */
	{ "DEREC", ERROR|CONTROL|AUDIT|LEVEL0,	TRUE,  NULL}, /* DER_ENCODER */
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
 * Implementation of logger_manager_t.destroy.
 */
static void destroy(private_logger_manager_t *this)
{
	int i;
	for (i = 0; i < LOGGER_CONTEXT_ROOF; i++)
	{
		this->loggers[i]->destroy(this->loggers[i]);
	}
	allocator_free(this);
}

/*
 * Described in header.
 */
logger_manager_t *logger_manager_create(log_level_t default_log_level)
{
	private_logger_manager_t *this = allocator_alloc_thing(private_logger_manager_t);
	int i;
	
	this->public.get_logger = (logger_t *(*)(logger_manager_t*,logger_context_t context))get_logger;
	this->public.get_log_level = (log_level_t (*)(logger_manager_t *, logger_context_t)) get_log_level;
	this->public.enable_log_level = (void (*)(logger_manager_t *, logger_context_t, log_level_t)) enable_log_level;
	this->public.disable_log_level = (void (*)(logger_manager_t *, logger_context_t, log_level_t)) disable_log_level;
	this->public.set_output = (void (*)(logger_manager_t *, logger_context_t, FILE*)) set_output;
	this->public.destroy = (void(*)(logger_manager_t*))destroy;
	
	for (i = 0; i < LOGGER_CONTEXT_ROOF; i++)
	{
		this->loggers[i] = logger_create(logger_defaults[i].name, logger_defaults[i].level, 
										 logger_defaults[i].log_thread_ids, logger_defaults[i].output);
	}
	
	return &this->public;
}

