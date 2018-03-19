#include "socket_vpp_plugin.h"
#include "socket_vpp_socket.h"

#include <daemon.h>

typedef struct private_socket_vpp_plugin_t private_socket_vpp_plugin_t;

/**
 * Private data of socket plugin
 */
struct private_socket_vpp_plugin_t {

    /**
     * Implements plugin interface
     */
    socket_vpp_plugin_t public;
};

METHOD(plugin_t, get_name, char*,
    private_socket_vpp_plugin_t *this)
{
    return "socket-vpp";
}

METHOD(plugin_t, destroy, void,
    private_socket_vpp_plugin_t *this)
{
    free(this);
}

METHOD(plugin_t, get_features, int,
    private_socket_vpp_plugin_t *this, plugin_feature_t *features[])
{
    static plugin_feature_t f[] = {
        PLUGIN_CALLBACK(socket_register, socket_vpp_socket_create),
            PLUGIN_PROVIDE(CUSTOM, "socket"),
                PLUGIN_DEPENDS(CUSTOM, "kernel-ipsec"),
    };
    *features = f;
    return countof(f);
}

/**
 * Create instance of socket-vpp plugin
 */
plugin_t *socket_vpp_plugin_create()
{
    private_socket_vpp_plugin_t *this;

    INIT(this,
        .public = {
            .plugin = {
                .get_name = _get_name,
                .get_features = _get_features,
                .destroy = _destroy,
            },
        },
    );

    return &this->public.plugin;
}
