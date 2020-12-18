/* Copyright (C) 2019-2020 Marvell */

/**
 * @defgroup auth_els auth_els
 * @ingroup cplugins
 *
 * @defgroup auth_els_plugin auth_els_plugin
 * @{ @ingroup auth_els
 */

#ifndef AUTH_ELS_PLUGIN_H_
#define AUTH_ELS_PLUGIN_H_

#include <plugins/plugin.h>

#define AUTH_MAJOR_VERSION             1
#define AUTH_MINOR_VERSION             5
#define AUTH_BUILD_VERSION             3
#define AUTH_STRING_SUFFIX_VERSION     "-stub"
#define AUTH_MAX_STRING_VERSION_LEN    32

#define APIDEV_DEVICE	"/dev/ql2xapidev"
#define MEMTRACE_MAX_BACKTRACE_DEPTH   (64)
#define CHARON_EXECUTABLE   "charon"
#define SHELL_BUF_SIZE      512

#define HOST_NO_UNASSIGNED      0xffff

/**
 * Plugin to synchronize state in a high availability cluster.
 */
struct auth_els_plugin_t {

	/**
	 * implements plugin interface
	 */
	plugin_t plugin;
};
typedef struct auth_els_plugin_t auth_els_plugin_t;

#endif /** AUTH_ELS_PLUGIN_H_ @}*/
