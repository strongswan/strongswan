/*
 * Copyright (C) 2008 Tobias Brunner
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

#ifndef GUEST_H
#define GUEST_H

#include <library.h>
#include <utils/enumerator.h>

typedef enum guest_state_t guest_state_t;
typedef struct guest_t guest_t;

#include "iface.h"

/**
 * @brief State of a guest (started, stopped, ...)
 */
enum guest_state_t {
	/** guest kernel not running at all */
	GUEST_STOPPED,
	/** kernel started, but not yet available */
	GUEST_STARTING,
	/** guest is up and running */
	GUEST_RUNNING,
	/** guest has been paused */
	GUEST_PAUSED,
	/** guest is stopping (shutting down) */
	GUEST_STOPPING,
};

/**
 * string mappings for guest_state_t
 */
extern enum_name_t *guest_state_names;

/**
 * Invoke function which lauches the UML guest.
 *
 * Consoles are all set to NULL, you may change them by adding additional UML
 * options to args before invocation.
 *
 * @param data		callback data
 * @param guest		guest to start
 * @param args		args to use for guest invocation, args[0] is kernel
 * @param argc		number of elements in args
 * @param idle		
 * @return			PID of child, 0 if failed
 */
typedef pid_t (*invoke_function_t)(void *data, guest_t *guest, 
								   char *args[], int argc);

/**
 * Idle function to pass to start().
 */
typedef void (*idle_function_t)(void);

/**
 * @brief A guest is a UML instance running on the host.
 **/
struct guest_t {
	
	/**
	 * @brief Get the name of this guest.
	 *
	 * @return		name of the guest
	 */
	char* (*get_name) (guest_t *this);
	
	/**
	 * @brief Get the process ID of the guest child process.
	 *
	 * @return		name of the guest
	 */
	pid_t (*get_pid) (guest_t *this);
	
	/**
	 * @brief Get the state of the guest (stopped, started, etc.).
	 *
	 * @return		guests state
	 */
	guest_state_t (*get_state)(guest_t *this);	
	
	/**
	 * @brief Start the guest.
	 *
	 * @param invoke	UML guest invocation function
	 * @param data		data to pass back to invoke function
	 * @param idle		idle function to call while waiting on child
	 * @return			TRUE if guest successfully started
	 */
	bool (*start) (guest_t *this, invoke_function_t invoke, void *data,
				   idle_function_t idle);
	
	/**
	 * @brief Kill the guest.
	 *
	 * @param idle		idle function to call while waiting to termination
	 */
	void (*stop) (guest_t *this, idle_function_t idle);
	
	/**
	 * @brief Create a new interface in the current scenario.
	 *
	 * @param name	name of the interface in the guest
	 * @return		created interface, or NULL if failed
	 */
	iface_t* (*create_iface)(guest_t *this, char *name);
	
	/**
	 * @brief Destroy an interface on guest.
	 *
	 * @param iface	interface to destroy
	 */
	void (*destroy_iface)(guest_t *this, iface_t *iface);
	
	/**
	 * @brief Create an enumerator over all guest interfaces.
	 *
	 * @return		enumerator over iface_t's
	 */
	enumerator_t* (*create_iface_enumerator)(guest_t *this);
	
	/**
	 * @brief Set the template COWFS overlay to use.
	 *
	 * @param parent	parent directory where template diff should point to
	 * @return			FALSE if failed
	 */
	bool (*load_template)(guest_t *this, char *parent);
	
	/**
	 * Execute a command in the guest.
	 *
	 * @param cb		callback to call for each read block
	 * @param data		data to pass to callback
	 * @param cmd		command to execute
	 * @param ...		printf style argument list for cmd
	 * @return			return value
	 */
	int (*exec)(guest_t *this, void(*cb)(void*,char*,size_t), void *data,
				char *cmd, ...);
	
	/**
	 * Execute a command in the guest and return the output by lines or as combined
	 * string.
	 * 
	 * @note This function does not work with binary output (i.e. containing 0 bytes).
	 * 
	 * @param cb		callback to call for each line or for the complete output
	 * @param lines		TRUE if the callback should be called for each line (instead of for the combined output)
	 * @param data		data to pass to callback
	 * @param cmd		command to execute
	 * @param ...		printf style argument list for cmd
	 * @return			return value
	 */
	int (*exec_str)(guest_t *this, void(*cb)(void*,char*), bool lines,
				void *data, char *cmd, ...);
	
	/**
	 * @brief Called whenever a SIGCHILD for the guests PID is received.
	 */
	void (*sigchild)(guest_t *this);
	
	/**
	 * @brief Close and destroy a guest with all interfaces
	 */	
	void (*destroy) (guest_t *this);
};

/**
 * @brief Create a new, unstarted guest.
 *
 * @param parent	parent directory to create the guest in
 * @param name		name of the guest to create
 * @param kernel	kernel this guest uses
 * @param master	read-only master filesystem for guest
 * @param mem		amount of memory to give the guest
 */
guest_t *guest_create(char *parent, char *name, char *kernel,
					  char *master, int mem);

/**
 * @brief Load a guest created with guest_create().
 *
 * @param parent	parent directory to look for a guest
 * @param name		name of the guest directory
 */
guest_t *guest_load(char *parent, char *name);

#endif /* GUEST_H */

