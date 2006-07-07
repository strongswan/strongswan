/**
 * @file logger_manager.h
 *
 * @brief Interface of logger_manager_t.
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

#ifndef LOGGER_MANAGER_H_
#define LOGGER_MANAGER_H_

#include <pthread.h>

#include <utils/logger.h>

#define INITIAL_LOG_OUTPUT stdout

typedef enum logger_context_t logger_context_t;

/**
 * @brief Context of a specific logger.
 * 
 * @ingroup utils
 */
enum logger_context_t {
	ALL_LOGGERS = -1,
	PARSER = 0,
	GENERATOR,
	IKE_SA,
	IKE_SA_MANAGER,
	CHILD_SA,
	MESSAGE,
	THREAD_POOL,
	WORKER,
	SCHEDULER,
	SENDER,
	RECEIVER,
	SOCKET,
	TESTER,
	DAEMON,
	CONFIG,
	ENCRYPTION_PAYLOAD,
	PAYLOAD,
	DER_DECODER,
	DER_ENCODER,
	ASN1,
	XFRM,
	LEAK_DETECT,
	LOGGER_CONTEXT_ROOF,
};


typedef struct logger_manager_t logger_manager_t;

/**
 * @brief Class to manage logger_t objects.
 * 
 * The logger manager manages all logger_t object in a list and
 * allows their manipulation. Via a logger_context_t, the loglevel
 * of a specific logging type can be adjusted at runtime.
 * This class differs from others, as it has no constructor or destroy
 * function. The one and only instance "logger_manager" is created at
 * library start and destroyed at exit.
 * 
 * @b Constructors:
 *  - none, logger_manager is the single instance
 *    use logger_manager_init/logger_manager_cleanup
 * 
 * @see logger_t
 * 
 * @ingroup utils
 */
struct logger_manager_t {
	
	/**
	 * @brief Gets a logger_t object for a specific logger context.
	 *
	 * @param this			logger_manager_t object
	 * @param context		logger_context to use the logger for
	 * @param name			name for the new logger. Context name is already included 
	 * 						and has not to be specified (so NULL is allowed)
	 * @return				logger_t object
	 */
	logger_t *(*get_logger) (logger_manager_t *this, logger_context_t context);
	
	/**
	 * @brief Returns the set log_level of a specific context.
	 * 
	 * @param this 			calling object
	 * @param context 		context to check level
	 * @return				log_level for the given logger_context
	 */
	log_level_t (*get_log_level) (logger_manager_t *this, logger_context_t context);
	
	/**
	 * @brief Enables a logger level of a specific context.
	 * 
	 * Use context ALL_LOGGERS to manipulate all loggers.
	 * 
	 * @param this 			calling object
	 * @param context 		context to set level
 	 * @param log_level 	logger level to eanble
	 */
	void (*enable_log_level) (logger_manager_t *this, logger_context_t context,log_level_t log_level);
	
	/**
	 * @brief Disables a logger level of a specific context.
	 * 
	 * Use context ALL_LOGGERS to manipulate all loggers.
	 * 
	 * @param this 			calling object
	 * @param context 		context to set level
	 * @param log_level 	logger level to disable
	 */
	void (*disable_log_level) (logger_manager_t *this, logger_context_t context,log_level_t log_level);
	
	/**
	 * @brief Sets the output of a logger.
	 * 
	 * Use context ALL_LOGGERS to redirect all loggers.
	 * 
	 * @param this 			calling object
	 * @param context 		context to set output
	 * @param log_level 	logger level to disable
	 */
	void (*set_output) (logger_manager_t *this, logger_context_t context, FILE *output);
};

/**
 * The single and global instance of the logger_manager
 */
extern logger_manager_t *logger_manager;

/**
 * Initialize the logger manager with all its logger.
 * Has to be called before logger_manager is accessed.
 */
void logger_manager_init(void);

/**
 * Free any resources hold by the logger manager. Do
 * not access logger_manager after this call.
 */
void logger_manager_cleanup(void);

#endif /*LOGGER_MANAGER_H_*/
