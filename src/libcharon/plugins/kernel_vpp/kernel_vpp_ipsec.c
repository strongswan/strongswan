#include <daemon.h>
#include <utils/debug.h>
#include <vlibapi/api.h>
#include <vlibmemory/api.h>
#include <vpp/api/vpe_msg_enum.h>
#include <collections/hashtable.h>
#include <threading/mutex.h>

#define vl_typedefs
#define vl_endianfun
#include <vpp/api/vpe_all_api_h.h>
#undef vl_typedefs
#undef vl_endianfun

#include "kernel_vpp_ipsec.h"
#include "kernel_vpp_shared.h"

#define PRIO_BASE 384

typedef struct private_kernel_vpp_ipsec_t private_kernel_vpp_ipsec_t;

struct private_kernel_vpp_ipsec_t {

    /**
     * Public interface
     */
    kernel_vpp_ipsec_t public;

    refcount_t next_sad_id;

    refcount_t next_spd_id;

    mutex_t *mutex;

    hashtable_t *sas;

    hashtable_t *spds;

    linked_list_t *routes;

    refcount_t nextspi;

    uint32_t mixspi;

    bool install_routes;
};

typedef struct {
    uint32_t sa_id;
    vl_api_ipsec_sad_add_del_entry_t *mp;
} sa_t;

typedef struct {
    uint32_t spd_id;
    uint32_t sw_if_index;
    refcount_t policy_num;
} spd_t;

typedef struct {
    char *if_name;
    host_t *gateway;
    host_t *dst_net;
    uint8_t prefixlen;
    int refs;
} route_entry_t;

#define htonll(x) ((1==htonl(1)) ? (x) : ((uint64_t)htonl((x) & 0xFFFFFFFF) << 32) | htonl((x) >> 32))

CALLBACK(route_equals, bool, route_entry_t *a, va_list args)
{
    host_t *dst_net, *gateway;
    uint8_t *prefixlen;
    char *if_name;

    VA_ARGS_VGET(args, if_name, gateway, dst_net, prefixlen);

    return a->if_name && if_name && streq(a->if_name, if_name) &&
           a->gateway->ip_equals(a->gateway, gateway) &&
           a->dst_net->ip_equals(a->dst_net, dst_net) &&
           a->prefixlen == *prefixlen;
}

static void route_destroy(route_entry_t *this)
{
    this->dst_net->destroy(this->dst_net);
    this->gateway->destroy(this->gateway);
    free(this->if_name);
    free(this);
}

static void manage_route(private_kernel_vpp_ipsec_t *this, bool add,
                         traffic_selector_t *dst_ts, host_t *src, host_t *dst)
{
    host_t *dst_net, *gateway;
    uint8_t prefixlen;
    char *if_name;
    route_entry_t *route;
    bool route_exist = FALSE;

    if (dst->is_anyaddr(dst))
    {
        return;
    }
    gateway = charon->kernel->get_nexthop(charon->kernel, dst, -1, NULL, &if_name);
    dst_ts->to_subnet(dst_ts, &dst_net, &prefixlen);
    if (!if_name)
    {
        if (src->is_anyaddr(src))
        {
            return;
        }
        if (!charon->kernel->get_interface(charon->kernel, src, &if_name))
        {
            return;
        }
    }
    route_exist = this->routes->find_first(this->routes, route_equals,
        (void**)&route, if_name, gateway, dst_net, &prefixlen);
    if (add)
    {
        if (route_exist)
        {
            route->refs++;
        }
        else
        {
            DBG2(DBG_KNL, "installing route: %H/%d via %H dev %s",
                 dst_net, prefixlen, gateway, if_name);
            INIT(route,
                .if_name = strdup(if_name),
                .gateway = gateway->clone(gateway),
                .dst_net = dst_net->clone(dst_net),
                .prefixlen = prefixlen,
                .refs = 1,
            );
            this->routes->insert_last(this->routes, route);
            charon->kernel->add_route(charon->kernel,
                 dst_net->get_address(dst_net), prefixlen, dst, NULL, if_name);
        }
    }
    else
    {
        if (!route_exist || --route->refs > 0)
        {
            return;
        }
        DBG2(DBG_KNL, "uninstalling route: %H/%d via %H dev %s",
             dst_net, prefixlen, gateway, if_name);
        this->routes->remove(this->routes, route, NULL);
        route_destroy(route);
        charon->kernel->del_route(charon->kernel, dst_net->get_address(dst_net),
             prefixlen, dst, NULL, if_name);
    }
}

static u_int sa_hash(kernel_ipsec_sa_id_t *sa)
{
    return chunk_hash_inc(sa->src->get_address(sa->src),
                          chunk_hash_inc(sa->dst->get_address(sa->dst),
                          chunk_hash_inc(chunk_from_thing(sa->spi),
                          chunk_hash(chunk_from_thing(sa->proto)))));
}

static bool sa_equals(kernel_ipsec_sa_id_t *sa, kernel_ipsec_sa_id_t *other_sa)
{
    return sa->src->ip_equals(sa->src, other_sa->src) &&
            sa->dst->ip_equals(sa->dst, other_sa->dst) &&
            sa->spi == other_sa->spi && sa->proto == other_sa->proto;
}

static u_int interface_hash(char *interface)
{
    return chunk_hash(chunk_from_str(interface));
}

static bool interface_equals(char *interface1, char *interface2)
{
    return streq(interface1, interface2);
}

static u_int permute(u_int x, u_int p)
{
    u_int qr;

    x = x % p;
    qr = ((uint64_t)x * x) % p;
    if (x <= p / 2)
    {
        return qr;
    }
    return p - qr;
}

static bool init_spi(private_kernel_vpp_ipsec_t *this)
{
    bool ok = TRUE;
    rng_t *rng;

    rng = lib->crypto->create_rng(lib->crypto, RNG_STRONG);
    if (!rng)
    {
        return FALSE;
    }
    ok = rng->get_bytes(rng, sizeof(this->nextspi), (uint8_t*)&this->nextspi);
    if (ok)
    {
        ok = rng->get_bytes(rng, sizeof(this->mixspi), (uint8_t*)&this->mixspi);
    }
    rng->destroy(rng);
    return ok;
}

static uint32_t calculate_priority(policy_priority_t policy_priority,
                                   traffic_selector_t *src,
                                   traffic_selector_t *dst)
{
    uint32_t priority = PRIO_BASE;
    uint16_t port;
    uint8_t mask, proto;
    host_t *net;

    switch (policy_priority)
    {
        case POLICY_PRIORITY_FALLBACK:
            priority <<= 1;
            /* fall-through */
        case POLICY_PRIORITY_ROUTED:
            priority <<= 1;
            /* fall-through */
        case POLICY_PRIORITY_DEFAULT:
            priority <<= 1;
            /* fall-through */
        case POLICY_PRIORITY_PASS:
            break;
    }
    /* calculate priority based on selector size, small size = high prio */
    src->to_subnet(src, &net, &mask);
    priority -= mask;
    proto = src->get_protocol(src);
    port = net->get_port(net);
    net->destroy(net);

    dst->to_subnet(dst, &net, &mask);
    priority -= mask;
    proto = max(proto, dst->get_protocol(dst));
    port = max(port, net->get_port(net));
    net->destroy(net);

    priority <<= 2; /* make some room for the two flags */
    priority += port ? 0 : 2;
    priority += proto ? 0 : 1;
    return priority;
}

static uint32_t get_sw_if_index(char *interface)
{
    char *out = NULL;
    int out_len;
    vl_api_sw_interface_dump_t *mp;
    vl_api_sw_interface_details_t *rmp;
    uint32_t sw_if_index = ~0;

    mp = vl_msg_api_alloc (sizeof (*mp));
    memset(mp, 0, sizeof(*mp));
    mp->_vl_msg_id = ntohs(VL_API_SW_INTERFACE_DUMP);
    mp->name_filter_valid = 1;
    strcpy(mp->name_filter, interface);
    if (vac->send_dump(vac, (char *)mp, sizeof(*mp), &out, &out_len))
    {
        goto error;
    }
    if (!out_len)
    {
        goto error;
    }
    rmp = (void *)out;
    sw_if_index = ntohl(rmp->sw_if_index);

error:
    free(out);
    vl_msg_api_free(mp);
    return sw_if_index;
}

static status_t spd_add_del(bool add, uint32_t spd_id)
{
    char *out = NULL;
    int out_len;
    vl_api_ipsec_spd_add_del_t *mp;
    vl_api_ipsec_spd_add_del_reply_t *rmp;
    status_t rv = FAILED;

    mp = vl_msg_api_alloc (sizeof (*mp));
    memset(mp, 0, sizeof(*mp));
    mp->_vl_msg_id = ntohs(VL_API_IPSEC_SPD_ADD_DEL);
    mp->is_add = add;
    mp->spd_id = ntohl(spd_id);
    if (vac->send(vac, (char *)mp, sizeof(*mp), &out, &out_len))
    {
        DBG1(DBG_KNL, "vac %s SPD failed", add ? "adding" : "removing");
        goto error;
    }
    rmp = (void *)out;
    if (rmp->retval)
    {
        DBG1(DBG_KNL, "%s SPD failed rv:%d", add ? "add" : "remove", ntohl(rmp->retval));
        goto error;
    }
    rv = SUCCESS;

error:
    free(out);
    vl_msg_api_free(mp);
    return rv;
}

static status_t interface_add_del_spd(bool add, uint32_t spd_id, uint32_t sw_if_index)
{
    char *out = NULL;
    int out_len;
    vl_api_ipsec_interface_add_del_spd_t *mp;
    vl_api_ipsec_interface_add_del_spd_reply_t *rmp;
    status_t rv = FAILED;

    mp = vl_msg_api_alloc (sizeof (*mp));
    memset(mp, 0, sizeof(*mp));
    mp->_vl_msg_id = ntohs(VL_API_IPSEC_INTERFACE_ADD_DEL_SPD);
    mp->is_add = add;
    mp->spd_id = ntohl(spd_id);
    mp->sw_if_index = ntohl(sw_if_index);
    if (vac->send(vac, (char *)mp, sizeof(*mp), &out, &out_len))
    {
        DBG1(DBG_KNL, "vac %s interface SPD failed", add ? "adding" : "removing");
        goto error;
    }
    rmp = (void *)out;
    if (rmp->retval)
    {
        DBG1(DBG_KNL, "%s interface SPD failed rv:%d", add ? "add" : "remove", ntohl(rmp->retval));
        goto error;
    }
    rv = SUCCESS;

error:
    free(out);
    vl_msg_api_free(mp);
    return rv;
}

static status_t manage_bypass(bool add, uint32_t spd_id)
{
    vl_api_ipsec_spd_add_del_entry_t *mp;
    vl_api_ipsec_spd_add_del_entry_reply_t *rmp;
    char *out = NULL;
    int out_len;
    status_t rv = FAILED;
    uint16_t port;

    port = lib->settings->get_int(lib->settings, "%s.port", CHARON_UDP_PORT, lib->ns);

    mp = vl_msg_api_alloc (sizeof (*mp));
    memset(mp, 0, sizeof(*mp));

    mp->_vl_msg_id = ntohs(VL_API_IPSEC_SPD_ADD_DEL_ENTRY);
    mp->is_add = add;
    mp->spd_id = ntohl(spd_id);
    mp->priority = ntohl(INT_MAX - POLICY_PRIORITY_PASS);
    mp->is_outbound = 0;
    mp->policy = 0;
    mp->is_ip_any = 1;
    memset(mp->local_address_stop, 0xFF, 16);
    memset(mp->remote_address_stop, 0xFF, 16);
    mp->protocol = IPPROTO_ESP;
    if (vac->send(vac, (char *)mp, sizeof(*mp), &out, &out_len))
    {
        DBG1(DBG_KNL, "vac %s SPD entry failed", add ? "adding" : "removing");
        goto error;
    }
    rmp = (void *)out;
    if (rmp->retval)
    {
        DBG1(DBG_KNL, "%s SPD entry failed rv:%d", add ? "add" : "remove", ntohl(rmp->retval));
        goto error;
    }
    mp->is_outbound = 1;
    if (vac->send(vac, (char *)mp, sizeof(*mp), &out, &out_len))
    {
        DBG1(DBG_KNL, "vac %s SPD entry failed", add ? "adding" : "removing");
        goto error;
    }
    rmp = (void *)out;
    if (rmp->retval)
    {
        DBG1(DBG_KNL, "%s SPD entry failed rv:%d", add ? "add" : "remove", ntohl(rmp->retval));
        goto error;
    }
    mp->is_outbound = 0;
    mp->protocol = IPPROTO_AH;
    if (vac->send(vac, (char *)mp, sizeof(*mp), &out, &out_len))
    {
        DBG1(DBG_KNL, "vac %s SPD entry failed", add ? "adding" : "removing");
        goto error;
    }
    rmp = (void *)out;
    if (rmp->retval)
    {
        DBG1(DBG_KNL, "%s SPD entry failed rv:%d", add ? "add" : "remove", ntohl(rmp->retval));
        goto error;
    }
    mp->is_outbound = 1;
    if (vac->send(vac, (char *)mp, sizeof(*mp), &out, &out_len))
    {
        DBG1(DBG_KNL, "vac %s SPD entry failed", add ? "adding" : "removing");
        goto error;
    }
    rmp = (void *)out;
    if (rmp->retval)
    {
        DBG1(DBG_KNL, "%s SPD entry failed rv:%d", add ? "add" : "remove", ntohl(rmp->retval));
        goto error;
    }
    mp->is_outbound = 0;
    mp->protocol = IPPROTO_UDP;
    mp->local_port_start = mp->local_port_stop = ntohs(port);
    mp->remote_port_start = mp->remote_port_stop = ntohs(port);
    if (vac->send(vac, (char *)mp, sizeof(*mp), &out, &out_len))
    {
        DBG1(DBG_KNL, "vac %s SPD entry failed", add ? "adding" : "removing");
        goto error;
    }
    rmp = (void *)out;
    if (rmp->retval)
    {
        DBG1(DBG_KNL, "%s SPD entry failed rv:%d", add ? "add" : "remove", ntohl(rmp->retval));
        goto error;
    }
    mp->is_outbound = 1;
    if (vac->send(vac, (char *)mp, sizeof(*mp), &out, &out_len))
    {
        DBG1(DBG_KNL, "vac %s SPD entry failed", add ? "adding" : "removing");
        goto error;
    }
    rmp = (void *)out;
    if (rmp->retval)
    {
        DBG1(DBG_KNL, "%s SPD entry failed rv:%d", add ? "add" : "remove", ntohl(rmp->retval));
        goto error;
    }
    rv = SUCCESS;
error:
    free(out);
    vl_msg_api_free(mp);
    return rv;
}

static status_t manage_policy(private_kernel_vpp_ipsec_t *this, bool add,
                              kernel_ipsec_policy_id_t *id,
                              kernel_ipsec_manage_policy_t *data)
{
    spd_t *spd;
    char *out = NULL, *interface;
    int out_len;
    uint32_t sw_if_index, spd_id, *sad_id;
    status_t rv = FAILED;
    uint32_t priority, auto_priority;
    chunk_t src_from, src_to, dst_from, dst_to;
    host_t *src, *dst, *addr;
    vl_api_ipsec_spd_add_del_entry_t *mp;
    vl_api_ipsec_spd_add_del_entry_reply_t *rmp;

    mp = vl_msg_api_alloc (sizeof (*mp));
    memset(mp, 0, sizeof(*mp));

    this->mutex->lock(this->mutex);
    if (!id->interface)
    {
        addr = id->dir == POLICY_IN ? data->dst : data->src;
        if (!charon->kernel->get_interface(charon->kernel, addr, &interface))
        {
            DBG1(DBG_KNL, "policy no interface %H", addr);
            goto error;
        }
        id->interface = interface;
    }
    spd = this->spds->get(this->spds, id->interface);
    if (!spd)
    {
        if (!add)
        {
            DBG1(DBG_KNL, "SPD for %s not found", id->interface);
            goto error;
        }
        sw_if_index = get_sw_if_index(id->interface);
        if (sw_if_index == ~0)
        {
            DBG1(DBG_KNL, "sw_if_index for %s not found", id->interface);
            goto error;
        }
        spd_id = ref_get(&this->next_spd_id);
        if (spd_add_del(TRUE, spd_id))
        {
            goto error;
        }
        if (manage_bypass(TRUE, spd_id))
        {
            goto error;
        }
        if (interface_add_del_spd(TRUE, spd_id, sw_if_index))
        {
            goto error;
        }
        INIT(spd,
                .spd_id = spd_id,
                .sw_if_index = sw_if_index,
                .policy_num = 0,
        );
        this->spds->put(this->spds, id->interface, spd);
    }

    auto_priority = calculate_priority(data->prio, id->src_ts, id->dst_ts);
    priority = data->manual_prio ? data->manual_prio : auto_priority;

    mp->_vl_msg_id = ntohs(VL_API_IPSEC_SPD_ADD_DEL_ENTRY);
    mp->is_add = add;
    mp->spd_id = ntohl(spd->spd_id);
    mp->priority = ntohl(INT_MAX - priority);
    mp->is_outbound = id->dir == POLICY_OUT;
    switch (data->type)
    {
        case POLICY_IPSEC:
            mp->policy = 3;
            break;
        case POLICY_PASS:
            mp->policy = 0;
            break;
        case POLICY_DROP:
            mp->policy = 1;
            break;
    }
    if ((data->type == POLICY_IPSEC) && data->sa)
    {
        kernel_ipsec_sa_id_t id = {
                .src = data->src,
                .dst = data->dst,
                .proto = data->sa->esp.use ? IPPROTO_ESP : IPPROTO_AH,
                .spi = data->sa->esp.use ? data->sa->esp.spi : data->sa->ah.spi,
        };
        sad_id = this->sas->get(this->sas, &id);
        if (!sad_id)
        {
            DBG1(DBG_KNL, "SA ID not found");
            goto error;
        }
        mp->sa_id = ntohl(*sad_id);
    }

    mp->is_ipv6 = id->src_ts->get_type(id->src_ts) == TS_IPV6_ADDR_RANGE;
    mp->protocol = id->src_ts->get_protocol(id->src_ts);

    if (id->dir == POLICY_OUT)
    {
        src_from = id->src_ts->get_from_address(id->src_ts);
        src_to = id->src_ts->get_to_address(id->src_ts);
        src = host_create_from_chunk(mp->is_ipv6 ? AF_INET6 : AF_INET, src_to, 0);
        dst_from = id->dst_ts->get_from_address(id->dst_ts);
        dst_to = id->dst_ts->get_to_address(id->dst_ts);
        dst = host_create_from_chunk(mp->is_ipv6 ? AF_INET6 : AF_INET, dst_to, 0);
    }
    else
    {
        dst_from = id->src_ts->get_from_address(id->src_ts);
        dst_to = id->src_ts->get_to_address(id->src_ts);
        dst = host_create_from_chunk(mp->is_ipv6 ? AF_INET6 : AF_INET, src_to, 0);
        src_from = id->dst_ts->get_from_address(id->dst_ts);
        src_to = id->dst_ts->get_to_address(id->dst_ts);
        src = host_create_from_chunk(mp->is_ipv6 ? AF_INET6 : AF_INET, dst_to, 0);
    }

    if (src->is_anyaddr(src) && dst->is_anyaddr(dst))
    {
        mp->is_ip_any = 1;
    }
    else
    {
        memcpy(mp->local_address_start, src_from.ptr, src_from.len);
        memcpy(mp->local_address_stop, src_to.ptr, src_to.len);
        memcpy(mp->remote_address_start, dst_from.ptr, dst_from.len);
        memcpy(mp->remote_address_stop, dst_to.ptr, dst_to.len);
    }
    mp->local_port_start = ntohs(id->src_ts->get_from_port(id->src_ts));
    mp->local_port_stop = ntohs(id->src_ts->get_to_port(id->src_ts));
    mp->remote_port_start = ntohs(id->dst_ts->get_from_port(id->dst_ts));
    mp->remote_port_stop = ntohs(id->dst_ts->get_to_port(id->dst_ts));

    if (vac->send(vac, (char *)mp, sizeof(*mp), &out, &out_len))
    {
        DBG1(DBG_KNL, "vac %s SPD entry failed", add ? "adding" : "removing");
        goto error;
    }
    rmp = (void *)out;
    if (rmp->retval)
    {
        DBG1(DBG_KNL, "%s SPD entry failed rv:%d", add ? "add" : "remove", ntohl(rmp->retval));
        goto error;
    }
    if (add)
    {
        ref_get(&spd->policy_num);
    }
    else
    {
        if (ref_put(&spd->policy_num))
        {
            interface_add_del_spd(FALSE, spd->spd_id, spd->sw_if_index);
            manage_bypass(FALSE, spd->spd_id);
            spd_add_del(FALSE, spd->spd_id);
            this->spds->remove(this->spds, id->interface);
        }
    }
    if (this->install_routes && id->dir == POLICY_OUT && !mp->protocol)
    {
        if (data->type == POLICY_IPSEC && data->sa->mode != MODE_TRANSPORT)
        {
            manage_route(this, add, id->dst_ts, data->src, data->dst);
        }
    }
    rv = SUCCESS;
error:
    free(out);
    vl_msg_api_free(mp);
    this->mutex->unlock(this->mutex);
    return rv;
}

METHOD(kernel_ipsec_t, get_features, kernel_feature_t,
    private_kernel_vpp_ipsec_t *this)
{
    return KERNEL_ESP_V3_TFC;
}

METHOD(kernel_ipsec_t, get_spi, status_t,
    private_kernel_vpp_ipsec_t *this, host_t *src, host_t *dst,
    uint8_t protocol, uint32_t *spi)
{
    static const u_int p = 268435399, offset = 0xc0000000;

    *spi = htonl(offset + permute(ref_get(&this->nextspi) ^ this->mixspi, p));
    return SUCCESS;
}

METHOD(kernel_ipsec_t, get_cpi, status_t,
    private_kernel_vpp_ipsec_t *this, host_t *src, host_t *dst,
    uint16_t *cpi)
{
    return NOT_SUPPORTED;
}

METHOD(kernel_ipsec_t, add_sa, status_t,
    private_kernel_vpp_ipsec_t *this, kernel_ipsec_sa_id_t *id,
    kernel_ipsec_add_sa_t *data)
{
    char *out = NULL;
    int out_len;
    vl_api_ipsec_sad_add_del_entry_t *mp;
    vl_api_ipsec_sad_add_del_entry_reply_t *rmp;
    uint32_t sad_id = ref_get(&this->next_sad_id);
    uint8_t ca = 0, ia = 0;
    status_t rv = FAILED;
    chunk_t src, dst;
    kernel_ipsec_sa_id_t *sa_id;
    sa_t *sa;

    mp = vl_msg_api_alloc(sizeof(*mp));
    memset(mp, 0, sizeof(*mp));
    mp->_vl_msg_id = ntohs(VL_API_IPSEC_SAD_ADD_DEL_ENTRY);
    mp->is_add = 1;
    mp->sad_id = ntohl(sad_id);
    mp->spi = id->spi;
    mp->protocol = id->proto == IPPROTO_ESP;
    switch (data->enc_alg)
    {
        case ENCR_NULL:
            ca = 0;
            break;
        case ENCR_AES_CBC:
            switch (data->enc_key.len * 8)
            {
                case 128:
                    ca = 1;
                    break;
                case 192:
                    ca = 2;
                    break;
                case 256:
                    ca = 3;
                    break;
                default:
                    goto error;
                    break;
            }
            break;
        case ENCR_3DES:
            ca = 4;
            break;
        default:
            DBG1(DBG_KNL, "algorithm %N not supported by VPP!",
                 encryption_algorithm_names, data->enc_alg);
            goto error;
            break;
    }
    mp->crypto_algorithm = ca;
    mp->crypto_key_length = data->enc_key.len;
    memcpy(mp->crypto_key, data->enc_key.ptr, data->enc_key.len);

    switch (data->int_alg)
    {
        case AUTH_UNDEFINED:
            ia = 0;
            break;
        case AUTH_HMAC_MD5_96:
            ia = 1;
            break;
        case AUTH_HMAC_SHA1_96:
            ia = 2;
            break;
        case AUTH_HMAC_SHA2_256_128:
            ia = 4;
            break;
        case AUTH_HMAC_SHA2_384_192:
            ia = 5;
            break;
        case AUTH_HMAC_SHA2_512_256:
            ia = 6;
            break;
        default:
            DBG1(DBG_KNL, "algorithm %N not supported by VPP!",
                 integrity_algorithm_names, data->int_alg);
            goto error;
            break;
    }
    mp->integrity_algorithm = ia;
    mp->integrity_key_length = data->int_key.len;
    memcpy(mp->integrity_key, data->int_key.ptr, data->int_key.len);

    mp->use_extended_sequence_number = data->esn;
    if (data->mode == MODE_TUNNEL)
    {
        mp->is_tunnel = 1;
        mp->is_tunnel_ipv6 = id->src->get_family(id->src) == AF_INET6;
    }
    src = id->src->get_address(id->src);
    memcpy(mp->tunnel_src_address, src.ptr, src.len);
    dst = id->dst->get_address(id->dst);
    memcpy(mp->tunnel_dst_address, dst.ptr, dst.len);
    if (vac->send(vac, (char *)mp, sizeof(*mp), &out, &out_len))
    {
        DBG1(DBG_KNL, "vac adding SA failed");
        goto error;
    }
    rmp = (void *)out;
    if (rmp->retval)
    {
        DBG1(DBG_KNL, "add SA failed rv:%d", ntohl(rmp->retval));
        goto error;
    }

    this->mutex->lock(this->mutex);
    INIT(sa_id,
            .src = id->src->clone(id->src),
            .dst = id->dst->clone(id->dst),
            .spi = id->spi,
            .proto = id->proto,
    );
    INIT(sa,
            .sa_id = sad_id,
            .mp = mp,
    );
    this->sas->put(this->sas, sa_id, sa);
    this->mutex->unlock(this->mutex);
    rv = SUCCESS;

error:
    free(out);
    return rv;
}

METHOD(kernel_ipsec_t, update_sa, status_t,
    private_kernel_vpp_ipsec_t *this, kernel_ipsec_sa_id_t *id,
    kernel_ipsec_update_sa_t *data)
{
    return NOT_SUPPORTED;
}

METHOD(kernel_ipsec_t, query_sa, status_t,
    private_kernel_vpp_ipsec_t *this, kernel_ipsec_sa_id_t *id,
    kernel_ipsec_query_sa_t *data, uint64_t *bytes, uint64_t *packets,
    time_t *time)
{
    char *out = NULL;
    int out_len;
    vl_api_ipsec_sa_dump_t *mp;
    vl_api_ipsec_sa_details_t *rmp;
    status_t rv = FAILED;
    sa_t *sa;

    this->mutex->lock(this->mutex);
    sa = this->sas->get(this->sas, id);
    this->mutex->unlock(this->mutex);
    if (!sa)
    {
        DBG1(DBG_KNL, "SA not found");
        return NOT_FOUND;
    }
    mp = vl_msg_api_alloc(sizeof(*mp));
    memset(mp, 0, sizeof(*mp));
    mp->_vl_msg_id = ntohs(VL_API_IPSEC_SA_DUMP);
    mp->sa_id = ntohl(sa->sa_id);
    if (vac->send_dump(vac, (char *)mp, sizeof(*mp), &out, &out_len))
    {
        DBG1(DBG_KNL, "vac SA dump failed");
        goto error;
    }
    if (!out_len)
    {
        DBG1(DBG_KNL, "SA ID %d no data", sa->sa_id);
        rv = NOT_FOUND;
        goto error;
    }
    rmp = (void*)out;

    if (bytes)
    {
        *bytes = htonll(rmp->total_data_size);
    }
    if (packets)
    {
        *packets = 0;
    }
    if (time)
    {
        *time = 0;
    }
    rv = SUCCESS;
error:
    free(out);
    vl_msg_api_free(mp);
    return rv;
}

METHOD(kernel_ipsec_t, del_sa, status_t,
    private_kernel_vpp_ipsec_t *this, kernel_ipsec_sa_id_t *id,
    kernel_ipsec_del_sa_t *data)
{
    char *out = NULL;
    int out_len;
    vl_api_ipsec_sad_add_del_entry_t *mp;
    vl_api_ipsec_sad_add_del_entry_reply_t *rmp;
    status_t rv = FAILED;
    sa_t *sa;

    this->mutex->lock(this->mutex);
    sa = this->sas->get(this->sas, id);
    if (!sa)
    {
        DBG1(DBG_KNL, "SA not found");
        rv = NOT_FOUND;
        goto error;
    }
    mp = sa->mp;
    mp->is_add = 0;

    if (vac->send(vac, (char *)mp, sizeof(*mp), &out, &out_len))
    {
        DBG1(DBG_KNL, "vac removing SA failed");
        goto error;
    }
    rmp = (void *)out;
    if (rmp->retval)
    {
        DBG1(DBG_KNL, "del SA failed rv:%d", ntohl(rmp->retval));
        goto error;
    }

    vl_msg_api_free(mp);
    this->sas->remove(this->sas, id);
    rv = SUCCESS;
error:
    free(out);
    this->mutex->unlock(this->mutex);
    return rv;
}

METHOD(kernel_ipsec_t, flush_sas, status_t,
    private_kernel_vpp_ipsec_t *this)
{
    enumerator_t *enumerator;
    int out_len;
    char *out;
    vl_api_ipsec_sad_add_del_entry_t *mp;
    sa_t *sa = NULL;

    this->mutex->lock(this->mutex);
    enumerator = this->sas->create_enumerator(this->sas);
    while (enumerator->enumerate(enumerator, sa, NULL))
    {
        mp = sa->mp;
        mp->is_add = 0;
        if (vac->send(vac, (char *)mp, sizeof(*mp), &out, &out_len))
        {
            break;
        }
        free(out);
        vl_msg_api_free(mp);
        this->sas->remove_at(this->sas, enumerator);
    }
    enumerator->destroy(enumerator);
    this->mutex->unlock(this->mutex);

    return SUCCESS;
}

METHOD(kernel_ipsec_t, add_policy, status_t,
    private_kernel_vpp_ipsec_t *this, kernel_ipsec_policy_id_t *id,
    kernel_ipsec_manage_policy_t *data)
{
    return manage_policy(this, TRUE, id, data);
}

METHOD(kernel_ipsec_t, query_policy, status_t,
    private_kernel_vpp_ipsec_t *this, kernel_ipsec_policy_id_t *id,
    kernel_ipsec_query_policy_t *data, time_t *use_time)
{
    return NOT_SUPPORTED;
}

METHOD(kernel_ipsec_t, del_policy, status_t,
    private_kernel_vpp_ipsec_t *this, kernel_ipsec_policy_id_t *id,
    kernel_ipsec_manage_policy_t *data)
{
    return manage_policy(this, FALSE, id, data);
}

METHOD(kernel_ipsec_t, flush_policies, status_t,
    private_kernel_vpp_ipsec_t *this)
{
    return NOT_SUPPORTED;
}

METHOD(kernel_ipsec_t, bypass_socket, bool,
    private_kernel_vpp_ipsec_t *this, int fd, int family)
{
    return FALSE;
}

METHOD(kernel_ipsec_t, enable_udp_decap, bool,
    private_kernel_vpp_ipsec_t *this, int fd, int family, u_int16_t port)
{
    return FALSE;
}

METHOD(kernel_ipsec_t, destroy, void,
    private_kernel_vpp_ipsec_t *this)
{
    this->mutex->destroy(this->mutex);
    this->sas->destroy(this->sas);
    this->spds->destroy(this->spds);
    this->routes->destroy(this->routes);
    free(this);
}

kernel_vpp_ipsec_t *kernel_vpp_ipsec_create()
{
    private_kernel_vpp_ipsec_t *this;

    INIT(this,
        .public = {
            .interface = {
                .get_features = _get_features,
                .get_spi = _get_spi,
                .get_cpi = _get_cpi,
                .add_sa  = _add_sa,
                .update_sa = _update_sa,
                .query_sa = _query_sa,
                .del_sa = _del_sa,
                .flush_sas = _flush_sas,
                .add_policy = _add_policy,
                .query_policy = _query_policy,
                .del_policy = _del_policy,
                .flush_policies = _flush_policies,
                .bypass_socket = _bypass_socket,
                .enable_udp_decap = _enable_udp_decap,
                .destroy = _destroy,
            },
        },
        .next_sad_id = 0,
        .next_spd_id = 0,
        .mutex = mutex_create(MUTEX_TYPE_DEFAULT),
        .sas = hashtable_create((hashtable_hash_t)sa_hash,
                                (hashtable_equals_t)sa_equals, 32),
        .spds = hashtable_create((hashtable_hash_t)interface_hash,
                                 (hashtable_equals_t)interface_equals, 4),
        .routes = linked_list_create(),
        .install_routes = lib->settings->get_bool(lib->settings,
                            "%s.install_routes", TRUE, lib->ns),
    );

    if (!init_spi(this))
    {
        destroy(this);
        return NULL;
    }

    return &this->public;
}
