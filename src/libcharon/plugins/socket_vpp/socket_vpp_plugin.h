/**
 * @defgroup socket_vpp socket_vpp
 * @ingroup cplugins
 *
 * @defgroup socket_vpp_plugin socket_vpp_plugin
 * @{ @ingroup socket_vpp
 */

#ifndef SOCKET_VPP_PLUGIN_H_
#define SOCKET_VPP_PLUGIN_H_

#include <plugins/plugin.h>

typedef struct socket_vpp_plugin_t socket_vpp_plugin_t;

/**
 * VPP socket implementation plugin.
 */
struct socket_vpp_plugin_t {

    /**
     * implements plugin interface
     */
    plugin_t plugin;
};

#endif /** SOCKET_VPP_PLUGIN_H_ @}*/
