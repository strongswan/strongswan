#include <utils/debug.h>
#include <vlibapi/api.h>
#include <vlibmemory/api.h>
#include <vpp/api/vpe_msg_enum.h>
#include <threading/thread.h>
#include <threading/mutex.h>

#define vl_typedefs
#define vl_endianfun
#include <vpp/api/vpe_all_api_h.h>
#undef vl_typedefs
#undef vl_endianfun

#include "kernel_vpp_net.h"
#include "kernel_vpp_shared.h"

typedef struct private_kernel_vpp_net_t private_kernel_vpp_net_t;

/**
 * Private data of kernel_vpp_net implementation.
 */
struct private_kernel_vpp_net_t {

    /**
     * Public interface.
     */
    kernel_vpp_net_t public;

    /**
     * Mutex to access interface list
     */
    mutex_t *mutex;

    /**
     * Known interfaces, as iface_t
     */
    linked_list_t *ifaces;

    thread_t *net_update;

    bool events_on;
};

typedef struct {
    uint32_t index;
    char if_name[64];
    linked_list_t *addrs;
    bool up;
} iface_t;

typedef struct {
    /** implements enumerator_t */
    enumerator_t public;
    /** what kind of address should we enumerate? */
    kernel_address_type_t which;
    /** enumerator over interfaces */
    enumerator_t *ifaces;
    /** current enumerator over addresses, or NULL */
    enumerator_t *addrs;
    /** mutex to unlock on destruction */
    mutex_t *mutex;
} addr_enumerator_t;

typedef struct {
    chunk_t next_hop;
    uint32_t sw_if_index;
    uint8_t preference;
} fib_path_t;

static iface_t* address2entry(private_kernel_vpp_net_t *this, host_t *ip)
{
    enumerator_t *ifaces, *addrs;
    iface_t *entry, *found = NULL;
    host_t *host;

    ifaces = this->ifaces->create_enumerator(this->ifaces);
    while (!found && ifaces->enumerate(ifaces, &entry))
    {
        addrs = entry->addrs->create_enumerator(entry->addrs);
        while (!found && addrs->enumerate(addrs, &host))
        {
            if (host->ip_equals(host, ip))
            {
                found = entry;
            }
        }
        addrs->destroy(addrs);
    }
    ifaces->destroy(ifaces);

    return found;
}

static status_t manage_route(private_kernel_vpp_net_t *this, bool add,
                             chunk_t dst, uint8_t prefixlen, host_t *gtw,
                             char *name)
{
    char *out;
    int out_len;
    enumerator_t *enumerator;
    iface_t *entry;
    vl_api_ip_add_del_route_t *mp;
    vl_api_ip_add_del_route_reply_t *rmp;
    bool exists = FALSE;

    this->mutex->lock(this->mutex);
    enumerator = this->ifaces->create_enumerator(this->ifaces);
    while (enumerator->enumerate(enumerator, &entry))
    {
        if (streq(name, entry->if_name))
        {
            exists = TRUE;
            break;
        }
    }
    enumerator->destroy(enumerator);
    this->mutex->unlock(this->mutex);

    if (!exists)
        return NOT_FOUND;

    mp = vl_msg_api_alloc(sizeof(*mp));
    memset(mp, 0, sizeof(*mp));
    mp->_vl_msg_id = ntohs(VL_API_IP_ADD_DEL_ROUTE);
    mp->is_add = add;
    mp->next_hop_sw_if_index = ntohl(entry->index);
    mp->dst_address_length = prefixlen;
    switch (dst.len)
    {
        case 4:
            mp->is_ipv6 = 0;
            memcpy(mp->dst_address, dst.ptr, dst.len);
            break;
        case 16:
            mp->is_ipv6 = 1;
            memcpy(mp->dst_address, dst.ptr, dst.len);
            break;
        default:
            vl_msg_api_free(mp);
            return FAILED;
    }
    if (gtw)
    {
        chunk_t addr = gtw->get_address(gtw);
        memcpy(mp->next_hop_address, addr.ptr, addr.len);
    }
    if (vac->send(vac, (char *)mp, sizeof(*mp), &out, &out_len))
    {
        DBG1(DBG_KNL, "vac %sing route failed", add ? "add" : "remov");
        vl_msg_api_free(mp);
        return FAILED;
    }
    rmp = (void *)out;
    vl_msg_api_free(mp);
    if (rmp->retval)
    {
        DBG1(DBG_KNL, "%s route failed %d", add ? "add" : "delete",
             ntohl(rmp->retval));
        free(out);
        return FAILED;
    }
    free(out);
    return SUCCESS;
}

static bool addr_in_subnet(chunk_t addr, int prefix, chunk_t net, int net_len)
{
    static const u_char mask[] = { 0x00, 0x80, 0xc0, 0xe0, 0xf0, 0xf8, 0xfc, 0xfe };
    int byte = 0;

    if (net_len == 0)
    {   /* any address matches a /0 network */
        return TRUE;
    }
    if (addr.len != net.len || net_len > 8 * net.len || prefix < net_len)
    {
        return FALSE;
    }
    /* scan through all bytes in network order */
    while (net_len > 0)
    {
        if (net_len < 8)
        {
            return (mask[net_len] & addr.ptr[byte]) == (mask[net_len] & net.ptr[byte]);
        }
        else
        {
            if (addr.ptr[byte] != net.ptr[byte])
            {
                return FALSE;
            }
            byte++;
            net_len -= 8;
        }
    }
    return TRUE;
}

static host_t *get_route(private_kernel_vpp_net_t *this, host_t *dest,
                         int prefix, bool nexthop, char **iface, host_t *src)
{
    fib_path_t path;
    char *out, *tmp;
    int out_len, i, num;
    vl_api_fib_path_t *fp;
    host_t *addr = NULL;
    enumerator_t *enumerator;
    iface_t *entry;
    int family;

    path.sw_if_index = ~0;
    path.preference = ~0;
    path.next_hop = chunk_empty;

    if (dest->get_family(dest) == AF_INET)
    {
        vl_api_ip_fib_dump_t *mp;
        vl_api_ip_fib_details_t *rmp;

        family = AF_INET;
        if (prefix == -1)
            prefix = 32;

        mp = vl_msg_api_alloc(sizeof(*mp));
        mp->_vl_msg_id = ntohs(VL_API_IP_FIB_DUMP);
        if (vac->send_dump(vac, (char *)mp, sizeof(*mp), &out, &out_len))
            return NULL;
        vl_msg_api_free(mp);
        tmp = out;
        while (tmp < (out + out_len))
        {
            rmp = (void *)tmp;
            num = ntohl(rmp->count);
            if (addr_in_subnet(dest->get_address(dest), prefix, chunk_create(rmp->address, 4), rmp->address_length))
            {
                fp = rmp->path;
                for (i = 0; i < num; i++)
                {
                    if (fp->is_drop)
                    {
                        fp++;
                        continue;
                    }
                    if ((fp->preference < path.preference) || (path.sw_if_index == ~0))
                    {
                        path.sw_if_index = ntohl(fp->sw_if_index);
                        path.preference = fp->preference;
                        chunk_clear(&path.next_hop);
                        path.next_hop = chunk_create(fp->next_hop, 4);
                    }
                    fp++;
                }
            }
            tmp += sizeof(*rmp) + (sizeof(*fp) * num);
        }
    }
    else
    {
        vl_api_ip6_fib_dump_t *mp;
        vl_api_ip6_fib_details_t *rmp;

        family = AF_INET6;
        if (prefix == -1)
            prefix = 128;

        mp = vl_msg_api_alloc(sizeof(*mp));
        mp->_vl_msg_id = ntohs(VL_API_IP6_FIB_DUMP);
        if (vac->send_dump(vac, (char *)mp, sizeof(*mp), &out, &out_len))
            return NULL;
        vl_msg_api_free(mp);
        tmp = out;
        while (tmp < (out + out_len))
        {
            rmp = (void *)tmp;
            num = ntohl(rmp->count);
            if (addr_in_subnet(dest->get_address(dest), prefix, chunk_create(rmp->address, 16), rmp->address_length))
            {
                fp = rmp->path;
                for (i = 0; i < num; i++)
                {
                    if (fp->is_drop)
                    {
                        fp++;
                        continue;
                    }
                    if ((fp->preference < path.preference) || (path.sw_if_index == ~0))
                    {
                        path.sw_if_index = ntohl(fp->sw_if_index);
                        path.preference = fp->preference;
                        chunk_clear(&path.next_hop);
                        path.next_hop = chunk_create(fp->next_hop, 16);
                    }
                    fp++;
                }
            }
            tmp += sizeof(*rmp) + (sizeof(*fp) * num);
        }
    }

    if (path.next_hop.len)
    {
        if (nexthop)
        {
            if (iface)
            {
                *iface = NULL;
                this->mutex->lock(this->mutex);
                enumerator = this->ifaces->create_enumerator(this->ifaces);
                while (enumerator->enumerate(enumerator, &entry))
                {
                    if (entry->index == path.sw_if_index)
                    {
                        *iface = strdup(entry->if_name);
                        break;
                    }
                }
                enumerator->destroy(enumerator);
                this->mutex->unlock(this->mutex);
            }
            addr = host_create_from_chunk(family, path.next_hop, 0);
        }
        else
        {
            if (src)
            {
                addr = src->clone(src);
            }
        }
    }

    free(out);
    return addr;
}

METHOD(enumerator_t, addr_enumerate, bool, addr_enumerator_t *this, va_list args)
{
    iface_t *entry;
    host_t **host;

    VA_ARGS_VGET(args, host);

    while (TRUE)
    {
        while (!this->addrs)
        {
            if (!this->ifaces->enumerate(this->ifaces, &entry))
            {
                return FALSE;
            }
            if (!entry->up && !(this->which & ADDR_TYPE_DOWN))
            {
                continue;
            }
            this->addrs = entry->addrs->create_enumerator(entry->addrs);
        }
        if (this->addrs->enumerate(this->addrs, host))
        {
            return TRUE;
        }
        this->addrs->destroy(this->addrs);
        this->addrs = NULL;
    }
}

METHOD(enumerator_t, addr_destroy, void, addr_enumerator_t *this)
{
    DESTROY_IF(this->addrs);
    this->ifaces->destroy(this->ifaces);
    this->mutex->unlock(this->mutex);
    free(this);
}

METHOD(kernel_net_t, get_interface_name, bool,
    private_kernel_vpp_net_t *this, host_t* ip, char **name)
{
    iface_t *entry;

    this->mutex->lock(this->mutex);
    entry = address2entry(this, ip);
    if (entry && name)
    {
        *name = strdup(entry->if_name);
    }
    this->mutex->unlock(this->mutex);

    return entry != NULL;
}

METHOD(kernel_net_t, create_address_enumerator, enumerator_t*,
    private_kernel_vpp_net_t *this, kernel_address_type_t which)
{
    addr_enumerator_t *enumerator;

    if (!(which & ADDR_TYPE_REGULAR))
    {
        /* we currently have no virtual, but regular IPs only */
        return enumerator_create_empty();
    }

    this->mutex->lock(this->mutex);

    INIT(enumerator,
        .public = {
            .enumerate = enumerator_enumerate_default,
            .venumerate = _addr_enumerate,
            .destroy = _addr_destroy,
        },
        .which = which,
        .ifaces = this->ifaces->create_enumerator(this->ifaces),
        .mutex = this->mutex,
    );
    return &enumerator->public;
}

METHOD(kernel_net_t, get_source_addr, host_t*,
    private_kernel_vpp_net_t *this, host_t *dest, host_t *src)
{
    return get_route(this, dest, -1, FALSE, NULL, src);
}

METHOD(kernel_net_t, get_nexthop, host_t*,
    private_kernel_vpp_net_t *this, host_t *dest, int prefix, host_t *src,
    char **iface)
{
    return get_route(this, dest, prefix, TRUE, iface, src);
}

METHOD(kernel_net_t, add_ip, status_t,
    private_kernel_vpp_net_t *this, host_t *virtual_ip, int prefix,
    char *iface_name)
{
    return NOT_SUPPORTED;
}

METHOD(kernel_net_t, del_ip, status_t,
    private_kernel_vpp_net_t *this, host_t *virtual_ip, int prefix,
    bool wait)
{
    return NOT_SUPPORTED;
}

METHOD(kernel_net_t, add_route, status_t,
    private_kernel_vpp_net_t *this, chunk_t dst_net, u_int8_t prefixlen,
    host_t *gateway, host_t *src_ip, char *if_name)
{
    return manage_route(this, TRUE, dst_net, prefixlen, gateway, if_name);
}

METHOD(kernel_net_t, del_route, status_t,
    private_kernel_vpp_net_t *this, chunk_t dst_net, u_int8_t prefixlen,
    host_t *gateway, host_t *src_ip, char *if_name)
{
    return manage_route(this, FALSE, dst_net, prefixlen, gateway, if_name);
}

static void iface_destroy(iface_t *this)
{
    this->addrs->destroy_offset(this->addrs, offsetof(host_t, destroy));
    free(this);
}

METHOD(kernel_net_t, destroy, void,
    private_kernel_vpp_net_t *this)
{
    this->net_update->cancel(this->net_update);
    this->mutex->destroy(this->mutex);
    this->ifaces->destroy_function(this->ifaces, (void*)iface_destroy);
    free(this);
}

static void update_addrs(private_kernel_vpp_net_t *this, iface_t *entry)
{
    char *out;
    int out_len, i, num;
    vl_api_ip_address_dump_t *mp;
    vl_api_ip_address_details_t *rmp;
    linked_list_t *addrs;
    host_t *host;

    mp = vl_msg_api_alloc(sizeof(*mp));
    mp->_vl_msg_id = ntohs(VL_API_IP_ADDRESS_DUMP);
    mp->sw_if_index = ntohl(entry->index);
    mp->is_ipv6 = 0;
    if (vac->send_dump(vac, (char *)mp, sizeof(*mp), &out, &out_len))
        return;
    num = out_len / sizeof(*rmp);
    addrs = linked_list_create();
    for (i = 0; i < num; i++)
    {
        rmp = (void *)out;
        out += sizeof(*rmp);
        host = host_create_from_chunk(AF_INET, chunk_create(rmp->ip, 4), 0);
        addrs->insert_last(addrs, host);
    }
    vl_msg_api_free(mp);
    free(out);
    mp = vl_msg_api_alloc(sizeof(*mp));
    mp->_vl_msg_id = ntohs(VL_API_IP_ADDRESS_DUMP);
    mp->sw_if_index = ntohl(entry->index);
    mp->is_ipv6 = 1;
    if (vac->send_dump(vac, (char *)mp, sizeof(*mp), &out, &out_len))
        return;
    num = out_len / sizeof(*rmp);
    for (i = 0; i < num; i++)
    {
        rmp = (void *)out;
        out += sizeof(*rmp);
        host = host_create_from_chunk(AF_INET6, chunk_create(rmp->ip, 16), 0);
        addrs->insert_last(addrs, host);
    }
    vl_msg_api_free(mp);
    free(out);

    entry->addrs->destroy(entry->addrs);
    entry->addrs = linked_list_create_from_enumerator(addrs->create_enumerator(addrs));
    addrs->destroy(addrs);
}

static void event_cb(char *data, int data_len, void *ctx)
{
    private_kernel_vpp_net_t *this = ctx;
    vl_api_sw_interface_event_t *event;
    iface_t *entry;
    enumerator_t *enumerator;

    event = (void*)data;
    DBG3(DBG_NET, "interface event %d", ntohl(event->sw_if_index));
    this->mutex->lock(this->mutex);
    enumerator = this->ifaces->create_enumerator(this->ifaces);
    while (enumerator->enumerate(enumerator, &entry))
    {
        if (entry->index == ntohl(event->sw_if_index))
        {
            if (event->deleted)
            {
                this->ifaces->remove_at(this->ifaces, enumerator);
                DBG2(DBG_NET, "interface deleted %u %s",
                     entry->index, entry->if_name);
                iface_destroy(entry);
            }
            else if (entry->up != event->admin_up_down)
            {
                entry->up = event->admin_up_down ? TRUE : FALSE;
                DBG2(DBG_NET, "interface state changed %u %s %s",
                     entry->index, entry->if_name, entry->up ? "UP" : "DOWN");
            }
            break;
        }
    }
    enumerator->destroy(enumerator);
    this->mutex->unlock(this->mutex);
    free(data);
}

static void *net_update_thread_fn(private_kernel_vpp_net_t *this)
{
    status_t rv;
    while (1)
    {
        char *out;
        int out_len;
        vl_api_sw_interface_dump_t *mp;
        vl_api_sw_interface_details_t *rmp;
        int i, num;
        enumerator_t *enumerator;
        iface_t *entry;

        mp = vl_msg_api_alloc (sizeof (*mp));
        mp->_vl_msg_id = ntohs(VL_API_SW_INTERFACE_DUMP);
        mp->name_filter_valid = 0;
        rv = vac->send_dump(vac, (char *)mp, sizeof(*mp), &out, &out_len);
        if (!rv)
        {
            this->mutex->lock(this->mutex);
            enumerator = this->ifaces->create_enumerator(this->ifaces);
            num = out_len / sizeof(*rmp);
            for (i = 0; i < num; i++)
            {
                 bool exists = FALSE;
                 rmp = (void *)out;
                 out += sizeof(*rmp);
                 while (enumerator->enumerate(enumerator, &entry))
                 {
                     if (entry->index == ntohl(rmp->sw_if_index))
                     {
                         exists = TRUE;
                         break;
                     }
                 }
                 if (!exists)
                 {
                     INIT(entry,
                             .index = ntohl(rmp->sw_if_index),
                             .up = rmp->admin_up_down ? TRUE : FALSE,
                             .addrs = linked_list_create(),
                     );
                     strncpy(entry->if_name, rmp->interface_name, 64);
                     DBG2(DBG_KNL, "IF %d %s %s", entry->index, entry->if_name, entry->up ? "UP" : "DOWN");
                     this->ifaces->insert_last(this->ifaces, entry);
                 }
                 update_addrs(this, entry);
            }
            enumerator->destroy(enumerator);
            this->mutex->unlock(this->mutex);
            free(out);
        }
        vl_msg_api_free(mp);

        if (!this->events_on)
        {
            vl_api_want_interface_events_t *emp;
            api_main_t *am = &api_main;

            emp = vl_msg_api_alloc (sizeof (*emp));
            emp->_vl_msg_id = ntohs(VL_API_WANT_INTERFACE_EVENTS);
            emp->enable_disable = 1;
            emp->pid = am->our_pid;
            rv = vac->register_event(vac, (char *)emp, sizeof(*emp), event_cb,
                                     VL_API_SW_INTERFACE_EVENT, this);
            if (!rv)
                this->events_on = TRUE;

        }

        sleep(5);
    }
    return NULL;
}

kernel_vpp_net_t *kernel_vpp_net_create()
{
    private_kernel_vpp_net_t *this;

    INIT(this,
        .public = {
            .interface = {
                .get_interface = _get_interface_name,
                .create_address_enumerator = _create_address_enumerator,
                .get_source_addr = _get_source_addr,
                .get_nexthop = _get_nexthop,
                .add_ip = _add_ip,
                .del_ip = _del_ip,
                .add_route = _add_route,
                .del_route = _del_route,
                .destroy = _destroy,
            },
        },
        .mutex = mutex_create(MUTEX_TYPE_DEFAULT),
        .ifaces = linked_list_create(),
        .events_on = FALSE,
    );

    this->net_update = thread_create((thread_main_t)net_update_thread_fn, this);

    return &this->public;
}
