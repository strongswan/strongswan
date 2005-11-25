/**
 * @file logger_manager.h
 *
 * @brief Interface of logger_manager_t.
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

#ifndef LOGGER_MANAGER_H_
#define LOGGER_MANAGER_H_

#include <pthread.h>

#include <utils/logger.h>

typedef enum logger_context_t logger_context_t;

/**
 * @brief Context of a specific logger 
 * 
 * @ingroup utils
 */
enum logger_context_t {
	PARSER,
	GENERATOR,
	IKE_SA,
	IKE_SA_MANAGER,
	MESSAGE,
	THREAD_POOL,
	WORKER,
	SCHEDULER,
	SENDER,
	RECEIVER,
	SOCKET,
	TESTER,
	DAEMON,
	CONFIGURATION_MANAGER,
};

typedef struct logger_manager_t logger_manager_t;

/**
 * Class to manage logger_t objects.
 * 
 * @ingroup utils
 */
struct logger_manager_t {
	
	/**
	 * @brief Gets a logger_t object for a specific logger context.
	 * 
	 * @warning Objects of type logger_t which are not destroyed over function
	 * #logger_manager_t.destroy_logger are destroyed in logger_managers 
	 * destroy function. Don't use logger_t's own destroy function with 
	 * managed logger_t objects.
	 *
	 * @param this			logger_manager_t object
	 * @param context		logger_context to use the logger for
	 * @param[out] logger	pointer to a a place where the new logger is stored
	 * @param name			name for the new logger. Context name is already included 
	 * 						and has not to be specified (so NULL is allowed)
	 * @return				
	 * 						- logger_t object
	 * 						- NULL if out of ressources
	 */
	logger_t *(*create_logger) (logger_manager_t *this, logger_context_t context, char *name);
	
	
	/**
	 * @brief Destroys a logger_t object which is not used anymore.
	 * 
	 * @warning Objects of type logger_t which are not destroyed over function
	 * #logger_manager_t.destroy_logger are destroyed in logger_managers 
	 * destroy function.
	 *
	 * @param this		logger_manager_t object
	 * @param logger		pointer to the logger which has to be destroyed
	 * @return			- SUCCESS
	 * 					- OUT_OF_RES (when searching the specific logger_t object)
	 * 					- NOT_FOUND
	 */
	status_t (*destroy_logger) (logger_manager_t *this,logger_t *logger);
	
	/**
	 * Returns the set logger_level of a specific context or 0.
	 * 
	 * @param this 			calling object
	 * @param context 		context to check level
	 * @return				logger_level for the given logger_context
	 */
	logger_level_t (*get_logger_level) (logger_manager_t *this, logger_context_t context);
	
	/**
	 * Enables a logger_level of a specific context.
	 * 
	 * @param this 			calling object
	 * @param context 		context to set level
 	 * @param logger_level 	logger_level to eanble
 	 * @return 				
 	 * 						- SUCCESS
 	 * 						- OUT_OF_RES
	 */
	status_t (*enable_logger_level) (logger_manager_t *this, logger_context_t context,logger_level_t logger_level);
		

	/**
	 * Disables a logger_level of a specific context.
	 * 
	 * @param this 			calling object
	 * @param context 		context to set level
 	 * @param logger_level 	logger_level to disable
 	 * @return
 	 * 						- SUCCESS
 	 * 						- OUT_OF_RES
	 */
	status_t (*disable_logger_level) (logger_manager_t *this, logger_context_t context,logger_level_t logger_level);


	/**
	 * @brief Destroys a logger_manager_t object.
	 * 
	 * All remaining managed logger_t objects are also destroyed.
	 *
	 * @param this		logger_manager_t object
	 * @return
	 * 		 			- SUCCESS in any case
	 */
	status_t (*destroy) (logger_manager_t *this);
};

/**
 * @brief Constructor to create a logger_manager_t object.
 *
 * @param default_log_level 	default log level for a context
 * @return 					
 * 							- logger_manager_t object
 * 							- NULL if out of ressources
 * 
 * @ingroup utils
 */
logger_manager_t *logger_manager_create(logger_level_t default_log_level);


#endif /*LOGGER_MANAGER_H_*/
