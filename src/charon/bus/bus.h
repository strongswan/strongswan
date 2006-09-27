/**
 * @file bus.h
 *
 * @brief Interface of bus_t.
 *
 */

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
 */

#ifndef BUS_H_
#define BUS_H_

#include <stdarg.h>

#include <sa/ike_sa.h>
#include <sa/child_sa.h>


/**
 * @brief Raise a signal for an occured event.
 *
 * @param sig		signal_t signal description
 * @param level		level for the signal
 * @param format	printf() style format string
 * @param ...		printf() style agument list
 */
#define SIG(sig, level, format, ...) charon->bus->signal(charon->bus, sig, level, format, ##__VA_ARGS__)

/**
 * @brief Set the IKE_SA the calling thread is using.
 *
 * @param ike_sa	ike_sa to register, or NULL to unregister
 */
#define SIG_SA(ike_sa) charon->bus->set_sa(charon->bus, ike_sa)

/**
 * @brief Log a debug message via the signal bus.
 *
 * @param signal	signal_t signal description
 * @param format	printf() style format string
 * @param ...		printf() style agument list
 */
#define DBG1(sig, format, ...) charon->bus->signal(charon->bus, sig, LEV_DBG1, format, ##__VA_ARGS__)
#define DBG2(sig, format, ...) charon->bus->signal(charon->bus, sig, LEV_DBG2, format, ##__VA_ARGS__)
#define DBG3(sig, format, ...) charon->bus->signal(charon->bus, sig, LEV_DBG3, format, ##__VA_ARGS__)
#define DBG4(sig, format, ...) charon->bus->signal(charon->bus, sig, LEV_DBG4, format, ##__VA_ARGS__)


typedef enum signal_t signal_t;

enum signal_t {
	/** an IKE_SA has been established */
	SIG_IKE_UP,
	/** an IKE_SA has been closed */
	SIG_IKE_DOWN,
	/** an IKE_SA has been rekeyed */
	SIG_IKE_REKEY,
	/** a CHILD_SA has been installed */
	SIG_CHILD_UP,
	/** a CHILD_SA has been closed */
	SIG_CHILD_DOWN,
	/** a CHILD_SA has been rekeyed */
	SIG_CHILD_REKEY,
	/** a CHILD_SA has been routed */
	SIG_CHILD_ROUTE,
	/** a CHILD_SA has been unrouted */
	SIG_CHILD_UNROUTE,
	/** a remote peer has been authenticated using RSA digital signature */
	SIG_AUTH_RSA,
	/** a remote peer has been authenticated using preshared keys */
	SIG_AUTH_PSK,
	
	/** debugging message printed from an IKE_SA */
	SIG_DBG_IKE,
	/** debugging message printed from a CHILD_SA */
	SIG_DBG_CHD,
	/** debugging message printed from job processing */
	SIG_DBG_JOB,
	/** debugging message printed from configuration backends */
	SIG_DBG_CFG,
	/** debugging message printed from kernel interface */
	SIG_DBG_KNL,
	/** debugging message printed from networking */
	SIG_DBG_NET,
	/** debugging message printed from message encoding/decoding */
	SIG_DBG_ENC,
	
	SIG_MAX,
};

typedef enum level_t level_t;

enum level_t {
	/** Signal indicates something has failed */
	LEV_FAILED,
	/** Signal indicates something was successful */
	LEV_SUCCESS,
	/** Debug level 1, control flow messages */
	LEV_DBG1,
	/** Debug level 2, more detail informational messages */
	LEV_DBG2,
	/** Debug level 3, RAW data output */
	LEV_DBG3,
	/** Debug level 4, RAW data with sensitive (private) data */
	LEV_DBG4,
};

typedef struct bus_listener_t bus_listener_t;

/**
 * @brief Interface for registering at the signal bus.
 *
 * To receive signals from the bus, the client implementing the
 * bus_listener_t interface registers itself at the signal bus.
 *
 * @ingroup bus
 */
struct bus_listener_t {
	
	/**
	 * @brief Send a signal to a bus listener.
	 *
	 * A numerical identification for the thread is included, as the
	 * associated IKE_SA, if any. Signal specifies the type of
	 * the event occured, with a verbosity level. The format string specifies
	 * an additional informational or error message with a printf() like
	 * variable argument list. This is in the va_list form, as forwarding
	 * a "..." parameters to functions is not (cleanly) possible.
	 *
	 * @param this		listener
	 * @param thread	ID of the thread raised this signal
	 * @param ike_sa	IKE_SA associated to the event
	 * @param singal	kind of the signal (up, down, rekeyed, ...)
	 * @param level		level for signal
	 * @param format	printf() style format string
	 * @param args		vprintf() style va_list argument list
	 */
	void (*signal) (bus_listener_t *this, int thread, ike_sa_t *ike_sa,
					signal_t signal, level_t level, char* format, va_list args);
};


typedef struct bus_t bus_t;

/**
 * @brief Signal bus which sends signals to registered listeners.
 *
 * The signal bus is not much more than a multiplexer. A listener interested
 * in receiving event signals registers at the bus. Any signals sent to
 * are delivered to all registered listeners.
 * 
 *
 * @ingroup bus
 */
struct bus_t {
	
	/**
	 * @brief Register a listener to the bus.
	 *
	 * A registered listener receives all signals which are sent to the bus.
	 *
	 * @param this		bus
	 * @param listener	listener to register.
	 */
	void (*add_listener) (bus_t *this, bus_listener_t *listener);
	
	/**
	 * @brief Set the IKE_SA the calling thread is using.
	 *
	 * To associate an received signal to an IKE_SA without passing it as
	 * parameter each time, the thread registers it's used IKE_SA each
	 * time it checked it out. Before checking it in, the thread unregisters
	 * the IKE_SA (by passing NULL). This IKE_SA is stored per-thread, so each
	 * thread has one IKE_SA registered (or not).
	 * There is a macro to simplify the call.
	 * @see SIG_SA()
	 * 
	 * @param this		bus
	 * @param ike_sa	ike_sa to register, or NULL to unregister
	 */
	void (*set_sa) (bus_t *this, ike_sa_t *ike_sa);
	
	/**
	 * @brief Send a signal to the bus.
	 *
	 * A signal may belong to an IKE_SA and a CHILD_SA. If so, these
	 * are supplied to the signal function. The signal specifies the type of
	 * the event occured. The format string specifies an additional
	 * informational or error message with a printf() like variable argument
	 * list.
	 * Some useful macros may be available to shorten this call.
	 * @see SIG(), DBG1()
	 *
	 * @param this		bus
	 * @param singal	kind of the signal (up, down, rekeyed, ...)
	 * @param level		status level of the signal to send
	 * @param format	printf() style format string
	 * @param ...		printf() style argument list
	 */
	void (*signal) (bus_t *this, signal_t signal, level_t level, char* format, ...);
	
	/**
	 * @brief Destroy the signal bus.
	 *
	 * @param this		bus to destroy
	 */
	void (*destroy) (bus_t *this);
};

/**
 * @brief Create the signal bus which multiplexes signals to its listeners.
 *
 * @return		signal bus instance
 * 
 * @ingroup bus
 */
bus_t *bus_create();

#endif /* BUS_H_ */
