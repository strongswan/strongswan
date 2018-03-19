#include <utils/debug.h>
#include <vlibapi/api.h>
#include <vlibmemory/api.h>
#include <vpp/api/vpe_msg_enum.h>

#define vl_typedefs
#define vl_endianfun
#include <vpp/api/vpe_all_api_h.h>
#undef vl_typedefs
#undef vl_endianfun

#include "kernel_vpp_plugin.h"
#include "kernel_vpp_shared.h"
#include "kernel_vpp_ipsec.h"
#include "kernel_vpp_net.h"

typedef struct private_kernel_vpp_plugin_t private_kernel_vpp_plugin_t;

/**
 * private data of kernel vpp plugin
 */
struct private_kernel_vpp_plugin_t {
    /**
     * implements plugin interface
     */
    kernel_vpp_plugin_t public;

    vac_t *vac;
};

METHOD(plugin_t, get_name, char*,
    private_kernel_vpp_plugin_t *this)
{
    return "kernel-vpp";
}

METHOD(plugin_t, get_features, int,
    private_kernel_vpp_plugin_t *this, plugin_feature_t *features[])
{
    static plugin_feature_t f[] = {
        PLUGIN_CALLBACK(kernel_ipsec_register, kernel_vpp_ipsec_create),
            PLUGIN_PROVIDE(CUSTOM, "kernel-ipsec"),
        PLUGIN_CALLBACK(kernel_net_register, kernel_vpp_net_create),
            PLUGIN_PROVIDE(CUSTOM, "kernel-net"),
    };
    *features = f;
    return countof(f);
}

METHOD(plugin_t, destroy, void,
    private_kernel_vpp_plugin_t *this)
{
    if (this->vac)
    {
        lib->set(lib, "kernel-vpp-vac", NULL);
        this->vac->destroy(this->vac);
    }
    free(this);
}

plugin_t *kernel_vpp_plugin_create()
{
    private_kernel_vpp_plugin_t *this;

    INIT(this,
        .public = {
            .plugin = {
                .get_name = _get_name,
                .get_features = _get_features,
                .destroy = _destroy,
            },
        },
    );

    this->vac = vac_create("strongswan");
    if (!this->vac)
    {
        DBG1(DBG_KNL, "vac_create failed");
        destroy(this);
        return NULL;
    }
    lib->set(lib, "kernel-vpp-vac", this->vac);

    return &this->public.plugin;
}
