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
 
#include <definitions.h>
#include <utils/allocator.h>
#include <utils/linked_list.h>

mapping_t logger_context_t_mappings[] = {
	{PARSER, "PARSER"},
	{GENERATOR, "GENRAT"},
	{IKE_SA, "IKE_SA"},
	{IKE_SA_MANAGER, "ISAMGR"},
	{MESSAGE, "MESSAG"},
	{THREAD_POOL, "THPOOL"},
	{WORKER, "WORKER"},
	{SCHEDULER, "SCHEDU"},
	{SENDER, "SENDER"},
	{RECEIVER, "RECEVR"},
	{SOCKET, "SOCKET"},
	{TESTER, "TESTER"},
	{DAEMON, "DAEMON"},
	{CONFIGURATION_MANAGER, "CONFIG"},
	{ENCRYPTION_PAYLOAD, "ENCPLD"},
};

/** 
 * Maximum length of a logger name
 */
#define MAX_LOGGER_NAME 45


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
	 * Managed loggers.
	 */
	linked_list_t *loggers;
	
	/**
	 * Log Levels.
	 */
	linked_list_t *logger_levels;
	
	/**
	 * Used to manage logger list.
	 */
	pthread_mutex_t mutex;
	
	/**
	 * Default logger level for a created logger used 
	 * if no specific logger_level is set.
	 */
	logger_level_t default_log_level;
	
	/**
	 * Sets set logger_level of a specific context.
	 * 
	 * @param this 			calling object
	 * @param context 		context to set level
 	 * @param logger_level 	logger_level to set
 	 * @param enable 		enable specific level or disable it
	 */
	void (*set_logger_level) (private_logger_manager_t *this, logger_context_t context,logger_level_t logger_level,bool enable);
	
};


typedef struct logger_levels_entry_t logger_levels_entry_t;

/**
 * Entry in the logger_levels linked list.
 * 
 * This entry specifies the current log level for 
 * logger_t objects in specific context.
 */
struct logger_levels_entry_t {
	logger_context_t context;
	logger_level_t level;
};

typedef struct loggers_entry_t loggers_entry_t;

/**
 * Entry in the loggers linked list.
 */
struct loggers_entry_t {
	logger_context_t context;
	logger_t *logger;
};

/**
 * Implementation of logger_manager_t.create_logger.
 */
static logger_t *create_logger(private_logger_manager_t *this, logger_context_t context, char * name)
{
	
	char * context_name;
	bool log_thread_ids = TRUE;
	FILE * output = NULL;
	char buffer[MAX_LOGGER_NAME];
	loggers_entry_t *entry;
	logger_t *logger;
	logger_level_t logger_level = 0;
	
	context_name = mapping_find(logger_context_t_mappings,context);
	
	/* output to stdout, since we are debugging all days */
	output = stdout;

	switch(context)
	{
		case TESTER:
			log_thread_ids = FALSE;
			output = stdout;
			logger_level |= FULL;
			break;
		case IKE_SA:
			logger_level |= FULL;
		case IKE_SA_MANAGER:
		case MESSAGE:
		case ENCRYPTION_PAYLOAD:
		case WORKER:
		case CONFIGURATION_MANAGER:
			logger_level |= ALL;
		case PARSER:
		case GENERATOR:
		case THREAD_POOL:
		case SCHEDULER:
		case SENDER:
		case RECEIVER:
		case SOCKET:
		case DAEMON:
			log_thread_ids = FALSE;
			logger_level |= ERROR|CONTROL;
			break;
	}
	
	/* reduce to global definiton of loglevel */
	logger_level &= this->public.get_logger_level(&(this->public),context);
	
	/* logger manager is thread save */
	pthread_mutex_lock(&(this->mutex));
	if (name != NULL)
	{
		snprintf(buffer, MAX_LOGGER_NAME, "%s - %s",context_name,name);
			/* create logger with default log_level */
		logger = logger_create(buffer,logger_level,log_thread_ids,output);
	}
	else
	{
		logger = logger_create(context_name,logger_level,log_thread_ids,output);
	}
	

	entry = allocator_alloc_thing(loggers_entry_t);

	entry->context = context;
	entry->logger = logger;

	this->loggers->insert_last(this->loggers,entry);

	pthread_mutex_unlock(&(this->mutex));
	return logger;
	
}

/**
 * Implementation of logger_manager_t.get_logger_level.
 */
static logger_level_t get_logger_level (private_logger_manager_t *this, logger_context_t context)
{
	iterator_t *iterator;
	/* set logger_level to default logger_level */
	logger_level_t logger_level = this->default_log_level;

	pthread_mutex_lock(&(this->mutex));

	iterator = this->logger_levels->create_iterator(this->logger_levels,TRUE);
	/* check for existing logger_level entry */
	while (iterator->has_next(iterator))
	{
		logger_levels_entry_t * entry;
		iterator->current(iterator,(void **)&entry);
		if (entry->context == context)
		{
			logger_level = entry->level;
			break;
		}
	}
	iterator->destroy(iterator);

	pthread_mutex_unlock(&(this->mutex));
	return logger_level;
}

/**
 * Implementation of logger_manager_t.destroy_logger.
 */
static void destroy_logger(private_logger_manager_t *this,logger_t *logger)
{
	iterator_t *iterator;
	
	pthread_mutex_lock(&(this->mutex));
	
	iterator = this->loggers->create_iterator(this->loggers,TRUE);
	while (iterator->has_next(iterator))
	{
		loggers_entry_t * entry;
		iterator->current(iterator,(void **)&entry);
		if (entry->logger == logger)
		{
			iterator->remove(iterator);
			allocator_free(entry);
			logger->destroy(logger);
			break; 
		}
	}
	iterator->destroy(iterator);
	pthread_mutex_unlock(&(this->mutex));
}

/**
 * Implementation of private_logger_manager_t.set_logger_level.
 */
static void set_logger_level(private_logger_manager_t *this, logger_context_t context,logger_level_t logger_level,bool enable)
{
	iterator_t *iterator;
	bool found = FALSE;
	
	pthread_mutex_lock(&(this->mutex));
	iterator = this->logger_levels->create_iterator(this->logger_levels,TRUE);

	/* find existing logger_level entry */
	while (iterator->has_next(iterator))
	{	
		logger_levels_entry_t * entry;
		iterator->current(iterator,(void **)&entry);
		if (entry->context == context)
		{
			if (enable)
			{
				entry->level |= logger_level;
			}
			else
			{
				entry->level &= ~logger_level;
			}
			found = TRUE;
			break; 
		}
	}
	iterator->destroy(iterator);
	
	if (!found)
	{
		/* logger_levels entry not existing for current context */
		logger_levels_entry_t *entry = allocator_alloc_thing(logger_levels_entry_t);

		entry->context = context;
		entry->level = 	(enable) ? logger_level : (this->default_log_level & (~logger_level));

		this->logger_levels->insert_last(this->logger_levels,entry);
	}
	
	iterator = this->loggers->create_iterator(this->loggers,TRUE);
	while (iterator->has_next(iterator))
	{
		loggers_entry_t * entry;
		iterator->current(iterator,(void **)&entry);

		if (entry->context == context)
		{
			if (enable)
			{
				entry->logger->enable_level(entry->logger,logger_level);
			}
			else
			{
				entry->logger->disable_level(entry->logger,logger_level);
			}
			
		}
	}
	iterator->destroy(iterator);
	
	pthread_mutex_unlock(&(this->mutex));
}

/**
 * Implementation of logger_manager_t.enable_logger_level.
 */
static void enable_logger_level(private_logger_manager_t *this, logger_context_t context,logger_level_t logger_level)
{
	return set_logger_level(this,context,logger_level,TRUE);
}

/**
 * Implementation of logger_manager_t.disable_logger_level.
 */
static void disable_logger_level(private_logger_manager_t *this, logger_context_t context,logger_level_t logger_level)
{
	return set_logger_level(this,context,logger_level,FALSE);
}

/**
 * Implementation of logger_manager_t.destroy.
 */
static void destroy(private_logger_manager_t *this)
{

	while (this->loggers->get_count(this->loggers) > 0)
	{
		loggers_entry_t *current_entry;
		
		this->loggers->remove_first(this->loggers,(void **)&current_entry);
		
		/* destroy logger object */
		current_entry->logger->destroy(current_entry->logger);
		
		/* entry can be destroyed */
		allocator_free(current_entry);	
	}
	
	while (this->logger_levels->get_count(this->logger_levels) > 0)
	{
		logger_levels_entry_t *current_entry;
		
		this->logger_levels->remove_first(this->logger_levels,(void **)&current_entry);
		
		/* entry can be destroyed */
		allocator_free(current_entry);
	}
	
	this->loggers->destroy(this->loggers);
	this->logger_levels->destroy(this->logger_levels);
	pthread_mutex_destroy(&(this->mutex));
	
	allocator_free(this);
}

/*
 * Described in header.
 */
logger_manager_t *logger_manager_create(logger_level_t default_log_level)
{
	private_logger_manager_t *this = allocator_alloc_thing(private_logger_manager_t);
	
	this->public.create_logger = (logger_t *(*)(logger_manager_t*,logger_context_t context, char *))create_logger;
	this->public.destroy_logger = (void(*)(logger_manager_t*,logger_t *logger))destroy_logger;
	this->public.destroy = (void(*)(logger_manager_t*))destroy;
	this->public.get_logger_level = (logger_level_t (*)(logger_manager_t *, logger_context_t)) get_logger_level;
	this->public.enable_logger_level = (void (*)(logger_manager_t *, logger_context_t,logger_level_t)) enable_logger_level;
	this->public.disable_logger_level = (void (*)(logger_manager_t *, logger_context_t,logger_level_t)) disable_logger_level;
	this->set_logger_level = (void (*)(private_logger_manager_t *, logger_context_t,logger_level_t,bool)) set_logger_level;
	
	/* private variables */
	this->loggers = linked_list_create();
	this->logger_levels = linked_list_create();
	this->default_log_level = default_log_level;
	
	pthread_mutex_init(&(this->mutex), NULL);

	return (logger_manager_t*)this;
}

