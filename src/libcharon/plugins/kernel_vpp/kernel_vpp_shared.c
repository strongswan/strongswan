/*
 * Copyright (C) 2020 LabN Consulting, L.L.C.
 * Copyright (C) 2018 PANTHEON.tech.
 *
 * Copyright (C) 2014 Martin Willi
 * Copyright (C) 2014 revosec AG
 *
 * Copyright (C) 2008-2019 Tobias Brunner
 * HSR Hochschule fuer Technik Rapperswil
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
/*
 * Copyright (C) 2016 secunet Security Networks AG
 * Copyright (C) 2016 Thomas Egerer
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 */

#include <collections/array.h>
#include <collections/hashtable.h>
#include <library.h>
#include <threading/condvar.h>
#include <threading/mutex.h>
#include <threading/thread.h>
#include <utils/debug.h>

#include "kernel_vpp_shared.h"

typedef struct private_vac_t private_vac_t;
typedef struct vl_api_header_t vl_api_header_t;
typedef struct vl_api_rheader_t vl_api_rheader_t;
typedef struct want_event_reply_t want_event_reply_t;

const char *vpp_api_msg_names[] = {
#define vl_msg_id(x, y) [x] = #x,
#include <vpp/api/vpe_all_api_h.h>
#undef vl_msg_id
};
int vpp_api_nmsg_names = sizeof(vpp_api_msg_names) / sizeof(*vpp_api_msg_names);

vac_t *vac;

/**
 * Private variables and functions of vac_t class.
 */
struct private_vac_t {
	/**
	 * public part of the vac_t object.
	 */
	vac_t public;

	/**
	 * Timeout for VPP API replies, in ms
	 */
	uint16_t read_timeout;

	/**
	 * True if connected to VPP vlib
	 */
	bool connected_to_vlib;

	/**
	 * True if receive thread is running
	 */
	bool rx_is_running;

	/**
	 * Receive thread
	 */
	thread_t *rx;

	/**
	 * Mutex to lock receive queue
	 */
	mutex_t *queue_lock;

	/**
	 * Condition variable rx thread susspend
	 */
	condvar_t *suspend_cv;

	/**
	 * Condition variable rx thread resume
	 */
	condvar_t *resume_cv;

	/**
	 * Condition variable rx thread terminate
	 */
	condvar_t *terminate_cv;

	/**
	 * Mutex to lock send VPP API message entries
	 */
	mutex_t *entries_lock;

	/**
	 * VPP API message entries currently active, uintptr_t seq => entry_t
	 */
	hashtable_t *entries;

	/**
	 * Mutex to lock VPP API event entries
	 */
	mutex_t *events_lock;

	/**
	 * VPP API event entries currently active, uintptr_t id = event_t
	 */
	hashtable_t *events;

	/**
	 * Current sequence number for VPP API messages
	 */
	refcount_t seq;
};

/**
 * VPP API message header
 */
struct vl_api_header_t {
	/** message ID */
	uint16_t _vl_msg_id;

	/** opaque cookie to identify the client */
	uint32_t client_index;

	/** client context, to match reply with request */
	uint32_t context;
} __attribute__((packed));

/**
 * VPP API response message header
 */
struct vl_api_rheader_t {
	/** message ID */
	uint16_t _vl_msg_id;

	/** opaque cookie to identify the client */
	uint32_t context;
} __attribute__((packed));

/**
 * VPP API register event response message header
 */
struct want_event_reply_t {
	/** message ID */
	uint16_t _vl_msg_id;

	/** opaque cookie to identify the client */
	uint32_t context;

	/** retrun code for the request */
	int32_t retval;
} __attribute__((packed));

/**
 * VPP API request entry the answer for a waiting thread is collected in
 */
typedef struct {
	/** Condition variable thread is waiting */
	condvar_t *condvar;
	/** Array of reply msgs in a multi-message response, as struct rmsgbuf_t */
	array_t *rmsgs;
	/** All response messages received? */
	bool complete;
	/** Is VPP API dump? */
	bool is_dump;
} entry_t;

/**
 * Reply message buffer
 */
typedef struct {
	/** Data length */
	uint32_t data_len;
	/** Reply data */
	uint8_t data[0];
} rmsgbuf_t;

/**
 * VPP API event entry
 */
typedef struct {
	/** Event callback */
	event_cb_t cb;
	/** User data passed to callback */
	void *ctx;
} event_t;

/**
 * Free VPP API message
 */
static void
vac_free(void *msg)
{
	vl_msg_api_free(msg);
}

/**
 * Process a single VPP API message
 */
static void
vac_api_handler(private_vac_t *this, void *msg)
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
		if (id < vpp_api_nmsg_names)
		{
			KDBG2("vac msg %s has wrong len %d", vpp_api_msg_names[id], l);
		}
		else
		{
			KDBG2("vac msg UNKNOWN (%d) has wrong len %d", id, l);
		}

		vac_free(msg);
		return;
	}

	rmp = (void *)msg;
	seq = (uintptr_t)rmp->context;
	if (id == VL_API_IP_ADDRESS_DETAILS)
	{
		vl_api_ip_address_details_t *ip;
		ip = (void *)msg;
		seq = (uintptr_t)ip->context;
	}

	if (id < vpp_api_nmsg_names)
	{
		KDBG3("vac read msg %s len %d seq %u", vpp_api_msg_names[id], l, seq);
	}
	else
	{
		KDBG3("vac read msg UNKNOWN (%d) len %d seq %u", id, l, seq);
	}

	this->entries_lock->lock(this->entries_lock);
	entry = this->entries->get(this->entries, (void *)seq);
	if (entry)
	{
		if (entry->is_dump)
		{
			if (id == VL_API_CONTROL_PING_REPLY)
			{
				entry->complete = TRUE;
				entry->condvar->signal(entry->condvar);
				KDBG3("vac received control ping");
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
		event = this->events->get(this->events, (void *)event_id);
		if (event)
			event->cb(msg, l, event->ctx);
		else
			KDBG1("received unknown vac msg seq %u, ignored", seq);
		this->events_lock->unlock(this->events_lock);
	}

	this->entries_lock->unlock(this->entries_lock);
	vac_free(msg);
}

/**
 * VPP API receive thread
 */
static void *
vac_rx_thread_fn(private_vac_t *this)
{
	svm_queue_t *q;
	vl_api_memclnt_keepalive_t *mp;
	vl_api_memclnt_keepalive_reply_t *rmp;
	vl_shmem_hdr_t *shmem_hdr;
	uword msg;

#ifdef HAVE_VLIBAPI_GET_MAIN
	api_main_t *am = vlibapi_get_main();
#else
	api_main_t *am = &api_main;
#endif

	q = am->vl_input_queue;

	while (TRUE)
	{
		while (!svm_queue_sub(q, (u8 *)&msg, SVM_Q_WAIT, 0))
		{
			u16 id = ntohs(*((u16 *)msg));
			switch (id)
			{
			case VL_API_RX_THREAD_EXIT:
				vl_msg_api_free((void *)msg);
				this->queue_lock->lock(this->queue_lock);
				this->terminate_cv->signal(this->terminate_cv);
				this->queue_lock->unlock(this->queue_lock);
				KDBG3("vac received rx thread exit");
				thread_exit(NULL);
				return NULL;
				break;

			case VL_API_MEMCLNT_RX_THREAD_SUSPEND:
				vl_msg_api_free((void *)msg);
				this->queue_lock->lock(this->queue_lock);
				this->suspend_cv->signal(this->suspend_cv);
				this->resume_cv->wait(this->resume_cv, this->queue_lock);
				this->queue_lock->unlock(this->queue_lock);
				KDBG3("vac received rx thread suspend");
				break;

			case VL_API_MEMCLNT_READ_TIMEOUT:
				KDBG3("vac received read timeout");
				vl_msg_api_free((void *)msg);
				break;

			case VL_API_MEMCLNT_KEEPALIVE:
				mp = (void *)msg;
				rmp = vl_msg_api_alloc_zero(sizeof(*rmp));
				rmp->_vl_msg_id = ntohs(VL_API_MEMCLNT_KEEPALIVE_REPLY);
				rmp->context = mp->context;
				shmem_hdr = am->shmem_hdr;
				vl_msg_api_send_shmem(shmem_hdr->vl_input_queue, (u8 *)&rmp);
				vl_msg_api_free((void *)msg);
				KDBG3("vac received keepalive");
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
#ifdef HAVE_VLIBAPI_GET_MAIN
			api_main_t *am = vlibapi_get_main();
#else
			api_main_t *am = &api_main;
#endif
			vl_api_rx_thread_exit_t *ep;
			bool timed_out;
			ep = vl_msg_api_alloc_zero(sizeof(*ep));
			ep->_vl_msg_id = ntohs(VL_API_RX_THREAD_EXIT);
			vl_msg_api_send_shmem(am->vl_input_queue, (u8 *)&ep);
			this->queue_lock->lock(this->queue_lock);
			timed_out = this->terminate_cv->timed_wait(this->terminate_cv,
													   this->queue_lock, 5000);
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

/**
 * Write a VPP API message to shared memory
 */
static status_t
vac_write(private_vac_t *this, char *p, int l, uint32_t ctx)
{
#ifdef HAVE_VLIBAPI_GET_MAIN
	api_main_t *am = vlibapi_get_main();
#else
	api_main_t *am = &api_main;
#endif
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
		KDBG1("vac vpe_api_write failed");
		vac_free(mp);
		return FAILED;
	}

	int msg_id = ntohs(mp->_vl_msg_id);
	KDBG3("vac write msg %s len %d", vpp_api_msg_names[msg_id], l);

	return SUCCESS;
}

/**
 * Clean up a thread waiting entry
 */
static void
destroy_entry(entry_t *entry)
{
	entry->condvar->destroy(entry->condvar);
	array_destroy_function(entry->rmsgs, (void *)free, NULL);
	free(entry);
}

/**
 * Send VPP API message and wait for a reply
 */
static status_t
send_vac(private_vac_t *this, char *in, int in_len, char **out, int *out_len,
		 bool is_dump)
{
	entry_t *entry;
	uint32_t ctx = ref_get(&this->seq);
	uintptr_t seq = (uintptr_t)ctx;
	rmsgbuf_t *rmsg;
	char *ptr;
	int i;

	this->entries_lock->lock(this->entries_lock);
	/* clang-format off */
	INIT(entry,
         .condvar = condvar_create(CONDVAR_TYPE_DEFAULT),
		 .rmsgs = array_create(0, 0),
         .is_dump = is_dump);
	this->entries->put(this->entries, (void *)seq, entry);
	/* clang-format on */

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
		mp = vl_msg_api_alloc_zero(sizeof(*mp));
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

	this->entries->remove(this->entries, (void *)seq);
	this->entries_lock->unlock(this->entries_lock);

	if (!entry->complete)
	{
		destroy_entry(entry);
		KDBG1("vac timeout");
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

METHOD(vac_t, vac_send, status_t, private_vac_t *this, char *in, int in_len,
	   char **out, int *out_len)
{
	return send_vac(this, in, in_len, out, out_len, FALSE);
}

METHOD(vac_t, vac_send_dump, status_t, private_vac_t *this, char *in,
	   int in_len, char **out, int *out_len)
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
	INIT(event, .cb = cb, .ctx = ctx);
	this->events->put(this->events, (void *)id, event);
	this->events_lock->unlock(this->events_lock);

	return SUCCESS;
}

vac_t *
vac_create(char *name)
{
	private_vac_t *this;

	INIT(this,
		 .public =
			 {
				 .destroy = _destroy,
				 .send = _vac_send,
				 .send_dump = _vac_send_dump,
				 .register_event = _register_event,
			 },
		 .rx_is_running = FALSE,
		 .read_timeout = lib->settings->get_int(
			 lib->settings, "%s.plugins.kernel-vpp.read_timeout", 0, lib->ns),
		 .queue_lock = mutex_create(MUTEX_TYPE_DEFAULT),
		 .suspend_cv = condvar_create(CONDVAR_TYPE_DEFAULT),
		 .resume_cv = condvar_create(CONDVAR_TYPE_DEFAULT),
		 .terminate_cv = condvar_create(CONDVAR_TYPE_DEFAULT),
		 .entries_lock = mutex_create(MUTEX_TYPE_RECURSIVE),
		 .entries =
			 hashtable_create(hashtable_hash_ptr, hashtable_equals_ptr, 4),
		 .events_lock = mutex_create(MUTEX_TYPE_DEFAULT),
		 .events =
			 hashtable_create(hashtable_hash_ptr, hashtable_equals_ptr, 4),
		 .seq = 0, );

	clib_mem_init_thread_safe(0, 256 << 20);

	if (vl_client_api_map("/vpe-api"))
	{
		KDBG1("vac unable to map");
		destroy(this);
		return NULL;
	}

	if (vl_client_connect(name, 0, 32) < 0)
	{
		KDBG1("vac unable to connect");
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

/*
 * fd.io coding-style-patch-verification: CLANG
 *
 * Local Variables:
 * c-file-style: "bsd"
 * c-basic-offset: 4
 * tab-width: 4
 * indent-tabs-mode: t
 * End:
 */
