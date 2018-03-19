#include <library.h>
#include <utils/debug.h>
#include <threading/thread.h>
#include <threading/condvar.h>
#include <threading/mutex.h>
#include <collections/array.h>
#include <collections/hashtable.h>
#include <vlibapi/api.h>
#include <vlibmemory/api.h>
#include <vpp/api/vpe_msg_enum.h>

#include "kernel_vpp_shared.h"

#define vl_typedefs
#define vl_endianfun
#include <vpp/api/vpe_all_api_h.h>
#undef vl_typedefs
#undef vl_endianfun

typedef struct private_vac_t private_vac_t;
typedef struct vl_api_header_t vl_api_header_t;
typedef struct vl_api_rheader_t vl_api_rheader_t;
typedef struct want_event_reply_t want_event_reply_t;

vac_t *vac;

struct private_vac_t {
    vac_t public;
    uint16_t read_timeout;
    bool connected_to_vlib;
    bool rx_is_running;
    thread_t *rx;
    mutex_t *queue_lock;
    condvar_t *suspend_cv;
    condvar_t *resume_cv;
    condvar_t *terminate_cv;

    mutex_t *entries_lock;
    hashtable_t *entries;
    mutex_t *events_lock;
    hashtable_t *events;
    refcount_t seq;
};

struct vl_api_header_t {
    uint16_t _vl_msg_id;
    uint32_t client_index;
    uint32_t context;
} __attribute__((packed));

struct vl_api_rheader_t {
    uint16_t _vl_msg_id;
    uint32_t context;
} __attribute__((packed));

struct want_event_reply_t {
    uint16_t _vl_msg_id;
    uint32_t context;
    int32_t retval;
} __attribute__((packed));

typedef struct {
    condvar_t *condvar;
    array_t *rmsgs;
    bool complete;
    bool is_dump;
} entry_t;

typedef struct {
    uint32_t data_len;
    uint8_t data[0];
} rmsgbuf_t;

typedef struct {
    event_cb_t cb;
    void *ctx;
} event_t;

static void vac_free (void * msg)
{
    vl_msg_api_free (msg);
}

static void vac_api_handler (private_vac_t *this, void *msg)
{
    vl_api_rheader_t *rmp;
    entry_t *entry;
    rmsgbuf_t *rmsg;
    uintptr_t seq, event_id;
    u16 id = ntohs(*((u16 *)msg));
    msgbuf_t *msgbuf = (msgbuf_t *)(((u8 *)msg) - offsetof(msgbuf_t, data));
    int l = ntohl(msgbuf->data_len);
    event_t *event;

    if (l == 0)
    {
        DBG2(DBG_KNL, "vac msg ID %d has wrong len %d", id, l);
        vac_free(msg);
        return;
    }

    rmp = (void *)msg;
    seq = (uintptr_t)rmp->context;
    if (id == VL_API_IP_ADDRESS_DETAILS)
    {
        vl_api_ip_address_details_t *ip;
        ip = (void*)msg;
        seq = (uintptr_t)ip->context;
    }
    DBG3(DBG_KNL, "vac read msg ID %d len %d seq %u", id, l, seq);
    this->entries_lock->lock(this->entries_lock);
    entry = this->entries->get(this->entries, (void*)seq);
    if (entry)
    {
        if (entry->is_dump)
        {
            if (id == VL_API_CONTROL_PING_REPLY)
            {
                entry->complete = TRUE;
                entry->condvar->signal(entry->condvar);
                DBG3(DBG_KNL, "vac received control ping");
                vac_free(msg);
                this->entries_lock->unlock(this->entries_lock);
                return;
            }
        }
        else
        {
            entry->complete = TRUE;
            entry->condvar->signal(entry->condvar);
        }
        rmsg = malloc(l + sizeof(msgbuf_t));
        rmsg->data_len = l;
        memcpy(rmsg->data, msg, l);
        array_insert(entry->rmsgs, ARRAY_TAIL, rmsg);
    }
    else
    {
        this->events_lock->lock(this->events_lock);
        event_id = (uintptr_t)id;
        event = this->events->get(this->events, (void*)event_id);
        if (event)
            event->cb(msg, l, event->ctx);
        else
            DBG1(DBG_KNL, "received unknown vac msg seq %u, ignored", seq);
        this->events_lock->unlock(this->events_lock);
    }

    this->entries_lock->unlock(this->entries_lock);
    vac_free(msg);
}

static void *vac_rx_thread_fn(private_vac_t *this)
{
    svm_queue_t *q;
    api_main_t *am = &api_main;
    vl_api_memclnt_keepalive_t *mp;
    vl_api_memclnt_keepalive_reply_t *rmp;
    vl_shmem_hdr_t *shmem_hdr;
    uword msg;

    q = am->vl_input_queue;

    while (TRUE)
    {
        while (!svm_queue_sub(q, (u8 *)&msg, SVM_Q_WAIT, 0))
        {
            u16 id = ntohs(*((u16 *)msg));
            switch (id) {
            case VL_API_RX_THREAD_EXIT:
                vl_msg_api_free((void *) msg);
                this->queue_lock->lock(this->queue_lock);
                this->terminate_cv->signal(this->terminate_cv);
                this->queue_lock->unlock(this->queue_lock);
                DBG3(DBG_KNL, "vac received rx thread exit");
                thread_exit(NULL);
                return NULL;
                break;

            case VL_API_MEMCLNT_RX_THREAD_SUSPEND:
                vl_msg_api_free((void * )msg);
                this->queue_lock->lock(this->queue_lock);
                this->suspend_cv->signal(this->suspend_cv);
                this->resume_cv->wait(this->resume_cv, this->queue_lock);
                this->queue_lock->unlock(this->queue_lock);
                DBG3(DBG_KNL, "vac received rx thread suspend");
                break;

            case VL_API_MEMCLNT_READ_TIMEOUT:
                DBG3(DBG_KNL, "vac received read timeout");
                vl_msg_api_free((void *) msg);
                break;

            case VL_API_MEMCLNT_KEEPALIVE:
                mp = (void *)msg;
                rmp = vl_msg_api_alloc (sizeof (*rmp));
                memset (rmp, 0, sizeof (*rmp));
                rmp->_vl_msg_id = ntohs(VL_API_MEMCLNT_KEEPALIVE_REPLY);
                rmp->context = mp->context;
                shmem_hdr = am->shmem_hdr;
                vl_msg_api_send_shmem(shmem_hdr->vl_input_queue, (u8 *)&rmp);
                vl_msg_api_free((void *) msg);
                DBG3(DBG_KNL, "vac received keepalive");
                break;

            default:
                vac_api_handler(this, (void *)msg);
            }
        }
    }

    return NULL;
}

METHOD(vac_t, destroy, void, private_vac_t *this)
{
    if (this->connected_to_vlib)
    {
        if (this->rx)
        {
            api_main_t *am = &api_main;
            vl_api_rx_thread_exit_t *ep;
            bool timed_out;
            ep = vl_msg_api_alloc (sizeof (*ep));
            ep->_vl_msg_id = ntohs(VL_API_RX_THREAD_EXIT);
            vl_msg_api_send_shmem(am->vl_input_queue, (u8 *)&ep);
            this->queue_lock->lock(this->queue_lock);
            timed_out = this->terminate_cv->timed_wait(this->terminate_cv,
                                                       this->queue_lock,
                                                       5000);
            this->queue_lock->unlock(this->queue_lock);
            if (timed_out)
                this->rx->cancel(this->rx);
            else
                this->rx->join(this->rx);
        }
        vl_client_disconnect();
        vl_client_api_unmap();
    }

    this->queue_lock->destroy(this->queue_lock);
    this->suspend_cv->destroy(this->suspend_cv);
    this->resume_cv->destroy(this->resume_cv);
    this->terminate_cv->destroy(this->terminate_cv);
    this->entries->destroy(this->entries);
    this->entries_lock->destroy(this->entries_lock);
    this->events->destroy(this->events);
    this->events_lock->destroy(this->events_lock);

    vac = NULL;
    free(this);
}

static status_t vac_write(private_vac_t *this, char *p, int l, uint32_t ctx)
{
    api_main_t *am = &api_main;
    vl_api_header_t *mp = vl_msg_api_alloc(l);
    svm_queue_t *q;

    if (!this->connected_to_vlib)
        return FAILED;

    if (!mp)
        return FAILED;

    memcpy(mp, p, l);
    mp->client_index = am->my_client_index;
    mp->context = ctx;
    q = am->shmem_hdr->vl_input_queue;
    if (svm_queue_add(q, (u8 *)&mp, 0))
    {
        DBG1(DBG_KNL, "vac vpe_api_write failed");
        vac_free(mp);
        return FAILED;
    }
    DBG3(DBG_KNL, "vac write msg ID %d len %d", ntohs(mp->_vl_msg_id), l);

    return SUCCESS;
}

static void destroy_entry(entry_t *entry)
{
    entry->condvar->destroy(entry->condvar);
    array_destroy_function(entry->rmsgs, (void*)free, NULL);
    free(entry);
}

static status_t send_vac(private_vac_t *this, char *in, int in_len, char **out,
                         int *out_len, bool is_dump)
{
    entry_t *entry;
    uint32_t ctx = ref_get(&this->seq);
    uintptr_t seq = (uintptr_t)ctx;
    rmsgbuf_t *rmsg;
    char *ptr;
    int i;

    this->entries_lock->lock(this->entries_lock);
    INIT(entry,
            .condvar = condvar_create(CONDVAR_TYPE_DEFAULT),
            .rmsgs = array_create(0, 0),
            .is_dump = is_dump,
    );
    this->entries->put(this->entries, (void*)seq, entry);

    if (vac_write(this, in, in_len, ctx))
    {
        destroy_entry(entry);
        this->entries_lock->unlock(this->entries_lock);
        return FAILED;
    }

    if (is_dump)
    {
        vl_api_control_ping_t *mp;
        status_t rv;
        mp = vl_msg_api_alloc (sizeof (*mp));
        mp->_vl_msg_id = ntohs(VL_API_CONTROL_PING);
        rv = vac_write(this, (char *)mp, sizeof(*mp), ctx);
        vl_msg_api_free(mp);
        if (rv)
        {
            destroy_entry(entry);
            this->entries_lock->unlock(this->entries_lock);
            return FAILED;
        }
    }

    while (!entry->complete)
    {
        if (this->read_timeout)
        {
            if (entry->condvar->timed_wait(entry->condvar, this->entries_lock,
                                           this->read_timeout * 1000))
            {
                break;
            }
        }
        else
        {
            entry->condvar->wait(entry->condvar, this->entries_lock);
        }
    }

    this->entries->remove(this->entries, (void*)seq);
    this->entries_lock->unlock(this->entries_lock);

    if (!entry->complete)
    {
        destroy_entry(entry);
        DBG1(DBG_KNL, "vac timeout");
        return OUT_OF_RES;
    }

    for (i = 0, *out_len = 0; i < array_count(entry->rmsgs); i++)
    {
        array_get(entry->rmsgs, i, &rmsg);
        *out_len += rmsg->data_len;
    }
    ptr = malloc(*out_len);
    *out = ptr;
    while (array_remove(entry->rmsgs, ARRAY_HEAD, &rmsg))
    {
        memcpy(ptr, rmsg->data, rmsg->data_len);
        ptr += rmsg->data_len;
        free(rmsg);
    }

    destroy_entry(entry);

    return SUCCESS;
}

METHOD(vac_t, vac_send, status_t, private_vac_t *this, char *in, int in_len, char **out, int *out_len)
{
    return send_vac(this, in, in_len, out, out_len, FALSE);
}

METHOD(vac_t, vac_send_dump, status_t, private_vac_t *this, char *in, int in_len, char **out, int *out_len)
{
    return send_vac(this, in, in_len, out, out_len, TRUE);
}

METHOD(vac_t, register_event, status_t, private_vac_t *this, char *in,
       int in_len, event_cb_t cb, uint16_t event_id, void *ctx)
{
    char *out;
    int out_len;
    want_event_reply_t *rmp;
    uintptr_t id = (uintptr_t)event_id;
    event_t *event;

    if (vac->send(vac, in, in_len, &out, &out_len))
        return FAILED;
    rmp = (void *)out;
    if (rmp->retval)
        return FAILED;
    free(out);
    this->events_lock->lock(this->events_lock);
    INIT(event,
            .cb = cb,
            .ctx = ctx,
    );
    this->events->put(this->events, (void*)id, event);
    this->events_lock->unlock(this->events_lock);

    return SUCCESS;
}

vac_t *vac_create(char *name)
{
    private_vac_t *this;

    INIT(this,
            .public = {
                    .destroy = _destroy,
                    .send = _vac_send,
                    .send_dump = _vac_send_dump,
                    .register_event = _register_event,
            },
            .rx_is_running = FALSE,
            .read_timeout = lib->settings->get_int(lib->settings,
                            "%s.plugins.kernel-vpp.read_timeout", 0, lib->ns),
            .queue_lock = mutex_create(MUTEX_TYPE_DEFAULT),
            .suspend_cv = condvar_create(CONDVAR_TYPE_DEFAULT),
            .resume_cv = condvar_create(CONDVAR_TYPE_DEFAULT),
            .terminate_cv = condvar_create(CONDVAR_TYPE_DEFAULT),
            .entries_lock = mutex_create(MUTEX_TYPE_RECURSIVE),
            .entries = hashtable_create(hashtable_hash_ptr, hashtable_equals_ptr, 4),
            .events_lock = mutex_create(MUTEX_TYPE_DEFAULT),
            .events = hashtable_create(hashtable_hash_ptr, hashtable_equals_ptr, 4),
            .seq = 0,
    );

    if (vl_client_api_map("/vpe-api"))
    {
        DBG1(DBG_KNL, "vac unable to map");
        destroy(this);
        return NULL;
    }

    if (vl_client_connect(name, 0, 32) < 0)
    {
        DBG1(DBG_KNL, "vac unable to connect");
        vl_client_api_unmap();
        destroy(this);
        return NULL;
    }

    this->connected_to_vlib = TRUE;

    this->rx = thread_create((thread_main_t)vac_rx_thread_fn, this);
    if (!this->rx)
    {
        vl_client_api_unmap();
        destroy(this);
        return NULL;
    }
    this->rx_is_running = TRUE;

    vac = &this->public;
    return &this->public;
}
