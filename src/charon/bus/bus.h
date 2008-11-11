/*
 * Copyright (C) 2006 Martin Willi
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
 *
 * $Id$
 */

/**
 * @defgroup bus bus
 * @{ @ingroup charon
 */

#ifndef BUS_H_
#define BUS_H_

typedef enum debug_t debug_t;
typedef enum level_t level_t;
typedef struct listener_t listener_t;
typedef struct bus_t bus_t;

#include <stdarg.h>

#include <sa/ike_sa.h>
#include <sa/child_sa.h>
#include <processing/jobs/job.h>

/**
 * Debug message group.
 */
enum debug_t {
	/** daemon main loop */
	DBG_DMN,
	/** IKE_SA_MANAGER */
	DBG_MGR,
	/** IKE_SA */
	DBG_IKE,
	/** CHILD_SA */
	DBG_CHD,
	/** job processing */
	DBG_JOB,
	/** configuration backends */
	DBG_CFG,
	/** kernel interface */
	DBG_KNL,
	/** networking/sockets */
	DBG_NET,
	/** message encoding/decoding */
	DBG_ENC,
	/** libstrongswan via logging hook */
	DBG_LIB,
	/** number of groups */
	DBG_MAX,
	/** pseudo group with all groups */
	DBG_ANY = DBG_MAX,
};

/**
 * short names of debug message group.
 */
extern enum_name_t *debug_names;

/**
 * short names of debug message group, lower case.
 */
extern enum_name_t *debug_lower_names;

/**
 * Debug levels used to control output verbosity.
 */
enum level_t {
	/** absolutely silent */
	LEVEL_SILENT = 	-1,
	/** most important auditing logs */
	LEVEL_AUDIT = 	 0,
	/** control flow */
	LEVEL_CTRL = 	 1,
	/** diagnose problems */
	LEVEL_DIAG = 	 2,
	/** raw binary blobs */
	LEVEL_RAW = 	 3,
	/** including sensitive data (private keys) */
	LEVEL_PRIVATE =  4,
};

#ifndef DEBUG_LEVEL
# define DEBUG_LEVEL 4
#endif /* DEBUG_LEVEL */

#if DEBUG_LEVEL >= 0
#define DBG0(group, format, ...) charon->bus->log(charon->bus, group, 0, format, ##__VA_ARGS__)
#endif /* DEBUG_LEVEL >= 0 */
#if DEBUG_LEVEL >= 1
#define DBG1(group, format, ...) charon->bus->log(charon->bus, group, 1, format, ##__VA_ARGS__)
#endif /* DEBUG_LEVEL >= 1 */
#if DEBUG_LEVEL >= 2
#define DBG2(group, format, ...) charon->bus->log(charon->bus, group, 2, format, ##__VA_ARGS__)
#endif /* DEBUG_LEVEL >= 2 */
#if DEBUG_LEVEL >= 3
#define DBG3(group, format, ...) charon->bus->log(charon->bus, group, 3, format, ##__VA_ARGS__)
#endif /* DEBUG_LEVEL >= 3 */
#if DEBUG_LEVEL >= 4
#define DBG4(group, format, ...) charon->bus->log(charon->bus, group, 4, format, ##__VA_ARGS__)
#endif /* DEBUG_LEVEL >= 4 */

#ifndef DBG0
# define DBG0(...) {}
#endif /* DBG0 */
#ifndef DBG1
# define DBG1(...) {}
#endif /* DBG1 */
#ifndef DBG2
# define DBG2(...) {}
#endif /* DBG2 */
#ifndef DBG3
# define DBG3(...) {}
#endif /* DBG3 */
#ifndef DBG4
# define DBG4(...) {}
#endif /* DBG4 */


/**
 * Listener interface, listens to events if registered to the bus.
 */
struct listener_t {
	
	/**
	 * Log a debugging message.
	 *
	 * The implementing signal function returns TRUE to stay registered
	 * to the bus, or FALSE to unregister itself.
	 * Calling bus_t.log() inside of a registered listener is possible,
	 * but the bus does not invoke listeners recursively.
	 *
	 * @param singal	kind of the signal (up, down, rekeyed, ...)
	 * @param level		verbosity level of the signal
	 * @param thread	ID of the thread raised this signal
	 * @param ike_sa	IKE_SA associated to the event
	 * @param format	printf() style format string
	 * @param args		vprintf() style va_list argument list
	 " @return			TRUE to stay registered, FALSE to unregister
	 */
	bool (*log) (listener_t *this, debug_t group, level_t level, int thread,
				 ike_sa_t *ike_sa, char* format, va_list args);
	
	/**
	 * Handle state changes in an IKE_SA.
	 *
	 * @param ike_sa	IKE_SA which changes its state
	 * @param state		new IKE_SA state this IKE_SA changes to
	 * @return			TRUE to stay registered, FALSE to unregister
	 */
	bool (*ike_state_change)(listener_t *this, ike_sa_t *ike_sa,
							 ike_sa_state_t state);
	
	/**
	 * Handle state changes in a CHILD_SA.
	 *
	 * @param ike_sa	IKE_SA containing the affected CHILD_SA
	 * @param child_sa	CHILD_SA which changes its state
	 * @param state		new CHILD_SA state this CHILD_SA changes to
	 * @return			TRUE to stay registered, FALSE to unregister
	 */
	bool (*child_state_change)(listener_t *this, ike_sa_t *ike_sa,
							   child_sa_t *child_sa, child_sa_state_t state);
	
	/**
	 * Hook called for received/sent messages of an IKE_SA.
	 *
	 * @param ike_sa	IKE_SA sending/receving a message
	 * @param message	message object
	 * @param incoming	TRUE for incoming messages, FALSE for outgoing
	 * @return			TRUE to stay registered, FALSE to unregister
	 */
	bool (*message)(listener_t *this, ike_sa_t *ike_sa, message_t *message,
					bool incoming);
	
	/**
	 * Hook called with IKE_SA key material.
	 *
	 * @param ike_sa	IKE_SA this keymat belongs to
	 * @param dh		diffie hellman shared secret
	 * @param nonce_i	initiators nonce
	 * @param nonce_r	responders nonce
	 * @param rekey		IKE_SA we are rekeying, if any
	 * @return			TRUE to stay registered, FALSE to unregister
	 */
	bool (*ike_keys)(listener_t *this, ike_sa_t *ike_sa, diffie_hellman_t *dh,
					 chunk_t nonce_i, chunk_t nonce_r, ike_sa_t *rekey);
	
	/**
	 * Hook called with CHILD_SA key material.
	 *
	 * @param ike_sa	IKE_SA the child sa belongs to
	 * @param child_sa	CHILD_SA this keymat is used for
	 * @param dh		diffie hellman shared secret
	 * @param nonce_i	initiators nonce
	 * @param nonce_r	responders nonce
	 * @return			TRUE to stay registered, FALSE to unregister
	 */
	bool (*child_keys)(listener_t *this, ike_sa_t *ike_sa, child_sa_t *child_sa,
					   diffie_hellman_t *dh, chunk_t nonce_i, chunk_t nonce_r);
};

/**
 * The bus receives events and sends them to all registered listeners.
 *
 * Any events sent to are delivered to all registered listeners. Threads
 * may wait actively to events using the blocking listen() call.
 */
struct bus_t {
	
	/**
	 * Register a listener to the bus.
	 *
	 * A registered listener receives all events which are sent to the bus.
	 * The listener is passive; the thread which emitted the event
	 * processes the listener routine.
	 *
	 * @param listener	listener to register.
	 */
	void (*add_listener) (bus_t *this, listener_t *listener);
	
	/**
	 * Unregister a listener from the bus.
	 *
	 * @param listener	listener to unregister.
	 */
	void (*remove_listener) (bus_t *this, listener_t *listener);
	
	/**
	 * Register a listener and block the calling thread.
	 *
	 * This call registers a listener and blocks the calling thread until
	 * its listeners function returns FALSE. This allows to wait for certain
	 * events. The associated job is executed after the listener has been
	 * registered: This allows to listen on events we initiate with the job,
	 * without missing any events to job may fire.
	 *
	 * @param listener	listener to register
	 * @param job		job to execute asynchronously when registered, or NULL
	 */
	void (*listen)(bus_t *this, listener_t *listener, job_t *job);
	
	/**
	 * Set the IKE_SA the calling thread is using.
	 *
	 * To associate an received log message to an IKE_SA without passing it as
	 * parameter each time, the thread registers the currenlty used IKE_SA
	 * during check-out. Before check-in, the thread unregisters the IKE_SA. 
	 * This IKE_SA is stored per-thread, so each thread has its own IKE_SA
	 * registered.
	 * 
	 * @param ike_sa	ike_sa to register, or NULL to unregister
	 */
	void (*set_sa) (bus_t *this, ike_sa_t *ike_sa);
	
	/**
	 * Send a log message to the bus.
	 *
	 * The signal specifies the type of the event occured. The format string
	 * specifies an additional informational or error message with a
	 * printf() like variable argument list.
	 * Use the DBG() macros.
	 *
	 * @param group		debugging group
	 * @param level		verbosity level of the signal
	 * @param format	printf() style format string
	 * @param ...		printf() style argument list
	 */
	void (*log)(bus_t *this, debug_t group, level_t level, char* format, ...);
	
	/**
	 * Send a log message to the bus using va_list arguments.
	 *
	 * Same as bus_t.signal(), but uses va_list argument list.
	 *
	 * @param group		kind of the signal (up, down, rekeyed, ...)
	 * @param level		verbosity level of the signal
	 * @param format	printf() style format string
	 * @param args		va_list arguments
	 */
	void (*vlog)(bus_t *this, debug_t group, level_t level,
				 char* format, va_list args);
	/**
	 * Send a IKE_SA state change event to the bus.
	 *
	 * @param ike_sa	IKE_SA which changes its state
	 * @param state		new state IKE_SA changes to
	 */
	void (*ike_state_change)(bus_t *this, ike_sa_t *ike_sa,
							 ike_sa_state_t state);
	/**
	 * Send a CHILD_SA state change event to the bus.
	 *
	 * @param child_sa	CHILD_SA which changes its state
	 * @param state		new state CHILD_SA changes to
	 */
	void (*child_state_change)(bus_t *this, child_sa_t *child_sa,
							   child_sa_state_t state);
	/**
	 * Message send/receive hook.
	 *
	 * @param message	message to send/receive
	 * @param incoming	TRUE for incoming messages, FALSE for outgoing
	 */
	void (*message)(bus_t *this, message_t *message, bool incoming);
	
	/**
	 * IKE_SA keymat hook.
	 *
	 * @param ike_sa	IKE_SA this keymat belongs to
	 * @param dh		diffie hellman shared secret
	 * @param nonce_i	initiators nonce
	 * @param nonce_r	responders nonce
	 * @param rekey		IKE_SA we are rekeying, if any
	 */
	void (*ike_keys)(bus_t *this, ike_sa_t *ike_sa, diffie_hellman_t *dh,
					 chunk_t nonce_i, chunk_t nonce_r, ike_sa_t *rekey);
	/**
	 * CHILD_SA keymat hook.
	 *
	 * @param child_sa	CHILD_SA this keymat is used for
	 * @param dh		diffie hellman shared secret
	 * @param nonce_i	initiators nonce
	 * @param nonce_r	responders nonce
	 */
	void (*child_keys)(bus_t *this, child_sa_t *child_sa, diffie_hellman_t *dh,
					   chunk_t nonce_i, chunk_t nonce_r);
	/**
	 * Destroy the event bus.
	 */
	void (*destroy) (bus_t *this);
};

/**
 * Create the event bus which forwards events to its listeners.
 *
 * @return		event bus instance
 */
bus_t *bus_create();

#endif /* BUS_H_ @} */
