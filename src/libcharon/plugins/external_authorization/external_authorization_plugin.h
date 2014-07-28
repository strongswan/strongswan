#ifndef EXTERNAL_AUTHORIZATION_PLUGIN_H_
#define EXTERNAL_AUTHORIZATION_PLUGIN_H_

#include <plugins/plugin.h>

typedef struct external_authorization_plugin_t external_authorization_plugin_t;

/**
 * External authorization by script plugin.
 */
struct external_authorization_plugin_t {

	/**
	 * Implements plugin interface.
	 */
	plugin_t plugin;
};

#endif /** EXTERNAL_AUTHORIZATION_PLUGIN_H_ @}*/
