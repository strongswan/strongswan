#ifndef EXTERNAL_AUTHORIZATION_LISTENER_H_
#define EXTERNAL_AUTHORIZATION_LISTENER_H_

#include <bus/listeners/listener.h>

typedef struct external_authorization_listener_t external_authorization_listener_t;

/**
 * Listener checking connecting peer against a whitelist.
 */
struct external_authorization_listener_t {

	/**
	 * Implements listener_t interface.
	 */
	listener_t listener;

	/**
	 * Enable/Disable external_authorization.
	 *
	 * @param enable	TRUE to enable, FALSE to disable
	 */
	void (*set_active)(external_authorization_listener_t *this, bool enable);

	/**
	 * Set path to authorization script.
	 *
	 * @param path		full path to script
	 */
	void (*set_path)(external_authorization_listener_t *this, char* path);
};

/**
 * Create a external_authorization_listener instance.
 */
external_authorization_listener_t *external_authorization_listener_create(char* program_path);

#endif /** EXTERNAL_AUTHORIZATION_LISTENER_H_ @}*/
