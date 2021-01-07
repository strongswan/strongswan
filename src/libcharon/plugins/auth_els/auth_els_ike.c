/*
 * Copyright (C) 2019-2020 Marvell 
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

#include "auth_els_plugin.h"
#include "auth_els_ike.h"

#include <scsi/scsi.h>
#include <scsi/scsi_bsg_fc.h>

#include <sa/ikev2/keymat_v2.h>
#include <sa/ikev1/keymat_v1.h>
#include <sa/ikev2/tasks/child_create.h>
#include <encoding/payloads/nonce_payload.h>
#include <encoding/payloads/cert_payload.h>
#include <encoding/payloads/auth_payload.h>
#include <encoding/payloads/id_payload.h>
#include <encoding/payloads/sa_payload.h>
#include <encoding/payloads/ts_payload.h>
#include <encoding/payloads/ke_payload.h>
#include <encoding/payloads/notify_payload.h>
#include <threading/rwlock.h>
#include <threading/condvar.h>
#include <threading/mutex.h>
#include <processing/jobs/rekey_ike_sa_job.h>
#include <processing/jobs/rekey_child_sa_job.h>
#include <processing/jobs/delete_ike_sa_job.h>

#include "auth_els_socket.h"
#include "auth_els_utils.h"

/**
 * Private data of an auth_els_ike_t object.
 */
typedef struct private_auth_els_ike_t private_auth_els_ike_t;
struct private_auth_els_ike_t {

	/**
	 * Public auth_els_ike_t interface.
	 */
	auth_els_ike_t public;

	hashtable_t *fchosts;
	auth_els_plugin_t *plugin;

	unsigned int rekey_time;
	unsigned int reauth_time;
	unsigned int reauth_rekey_jitter;
};



METHOD(listener_t, ike_keys, bool,
	private_auth_els_ike_t *this, ike_sa_t *ike_sa, diffie_hellman_t *dh,
	chunk_t dh_other, chunk_t nonce_i, chunk_t nonce_r, ike_sa_t *rekey,
	shared_key_t *shared, auth_method_t method)
{    
	DBG_ENTER;

	return TRUE;
}

METHOD(listener_t, ike_updown, bool,
	private_auth_els_ike_t *this, ike_sa_t *ike_sa, bool up)
{
	DBG_STD ("enter: up=%s", (up? "yes" : "no"));

	return TRUE;
}

METHOD(listener_t, ike_rekey, bool,
	private_auth_els_ike_t *this, ike_sa_t *old, ike_sa_t *new)
{
	return TRUE;
}


METHOD(listener_t, child_keys, bool,
		private_auth_els_ike_t *this, ike_sa_t *ike_sa, child_sa_t *child_sa,
	bool initiator, diffie_hellman_t *dh, chunk_t nonce_i, chunk_t nonce_r)
{
	DBG_STD ("ike_sa: %p, child_sa: %p", ike_sa, child_sa);
	
	chunk_t secret;

	if (dh && dh->get_shared_secret(dh, &secret))
	{
		DBG_STD ("DH secret:");
		chunk_clear(&secret);
	}
	
	return TRUE;
}

METHOD(listener_t, child_state_change, bool,
		private_auth_els_ike_t *this, ike_sa_t *ike_sa,
	child_sa_t *child_sa, child_sa_state_t state)
{
	
	DBG_STD ("ike_sa: %p, child_sa: %p, new state: %N", ike_sa, child_sa, child_sa_state_names, state);

	return TRUE;
}

METHOD(listener_t, child_updown, bool,
		private_auth_els_ike_t *this, ike_sa_t *ike_sa,
		child_sa_t *child_sa,  bool up)
{
	DBG_ENTER;
	
	return TRUE;
}

METHOD(listener_t, child_rekey, bool,
		private_auth_els_ike_t *this, ike_sa_t *ike_sa,
		child_sa_t *old, child_sa_t *new)
{
	DBG_STD ("ike_sa: %p, child_sa old: %p, new: %p", ike_sa, old, new);

	return TRUE;
}

METHOD(listener_t, narrow, bool,
		private_auth_els_ike_t *this, ike_sa_t *ike_sa,
		child_sa_t *child_sa, narrow_hook_t type,
		linked_list_t *local, linked_list_t *remote)
{
	DBG_ENTER;

	return TRUE;
}

METHOD(listener_t, ike_reestablish_pre, bool,
		private_auth_els_ike_t *this, ike_sa_t *old, ike_sa_t *new)
{
	DBG_ENTER;
	return TRUE;
}

METHOD(listener_t, ike_reestablish_post, bool,
		private_auth_els_ike_t *this, ike_sa_t *old, ike_sa_t *new,
		 bool initiated)
{
	DBG_ENTER;
	return TRUE;
}

METHOD(listener_t, ike_state_change, bool,
	private_auth_els_ike_t *this, ike_sa_t *ike_sa, ike_sa_state_t new)
{
	DBG_STD ("ike_sa: %p, new_state=%N", ike_sa, ike_sa_state_names, new);

	return TRUE;
}

METHOD(listener_t, message_hook, bool,
	private_auth_els_ike_t *this, ike_sa_t *ike_sa, message_t *message,
	bool incoming, bool plain)
{
	DBG_STD ("plain=%s - incoming=%s - request=%s message=%N, message_id initiate: %x, respond: %x",
			(plain?"true":"false"),
			(incoming?"true":"false"),
			(message->get_request(message)?"true":"false"),
			exchange_type_names, message->get_exchange_type(message), 
			ike_sa->get_message_id(ike_sa, true), ike_sa->get_message_id(ike_sa, false));
	
	return true;
}

METHOD(listener_t, authorize, bool,
	private_auth_els_ike_t *this, ike_sa_t *ike_sa,
	bool final, bool *success)
{
	DBG2(DBG_CFG, "auth_els - entering authorize event");

	if (final)
	{
		DBG_STD ("final event");
	}

	*success = TRUE;

	return TRUE; /* stay registered */
}


METHOD(listener_t, alert_hook, bool,
		private_auth_els_ike_t *this, ike_sa_t *ike_sa, alert_t alert, va_list args)
{
	DBG_STD ("enter: alert=%d, ike_sa: %p", alert, ike_sa);

	switch(alert)
	{
	case ALERT_SHUTDOWN_SIGNAL:
		DBG_STD ("AUTH_ELS Plugin shutdown: send app_stop to all hosts now.");
		break;
		
	case ALERT_KEEP_ON_CHILD_SA_FAILURE:
	case ALERT_RETRANSMIT_SEND_TIMEOUT:
	case ALERT_HALF_OPEN_TIMEOUT:		
	case ALERT_PEER_INIT_UNREACHABLE:
	case ALERT_LOCAL_AUTH_FAILED:
	case ALERT_PEER_AUTH_FAILED:
	case ALERT_PEER_ADDR_FAILED:
	case ALERT_PARSE_ERROR_HEADER:
	case ALERT_PARSE_ERROR_BODY:
	case ALERT_PROPOSAL_MISMATCH_IKE:
	case ALERT_PROPOSAL_MISMATCH_CHILD:
	case ALERT_TS_MISMATCH:
	case ALERT_INSTALL_CHILD_SA_FAILED:
	case ALERT_INSTALL_CHILD_POLICY_FAILED:
	case ALERT_AUTHORIZATION_FAILED:
	case ALERT_RETRANSMIT_RECEIVE:
	
	case ALERT_INVALID_IKE_SPI:
	case ALERT_TS_NARROWED:
	case ALERT_RETRANSMIT_SEND:
	case ALERT_IKE_SA_EXPIRED:
	default:
		break;
	};

	return TRUE;
}

METHOD(auth_els_ike_t, destroy, void,
	private_auth_els_ike_t *this)
{
	DBG2(DBG_CFG, "auth_els_ike: destroy");

	free(this);
}

/**
 * See header
 */
auth_els_ike_t *auth_els_ike_create(auth_els_plugin_t *plugin_ref)
{
	DBG2(DBG_CFG, "In auth_els_ike_create");

	private_auth_els_ike_t *this;

	INIT(this,
		.public = {
			.listener = {
				.ike_keys = _ike_keys,
				.ike_updown = _ike_updown,
				.ike_rekey = _ike_rekey,
				.ike_state_change = _ike_state_change,
				.message = _message_hook,
				.authorize = _authorize,
				.alert = _alert_hook,
				.ike_reestablish_pre = _ike_reestablish_pre,
				.ike_reestablish_post = _ike_reestablish_post,
				.child_keys = _child_keys,
				.child_state_change = _child_state_change,
				.child_updown = _child_updown,
				.child_rekey = _child_rekey,
				.narrow = _narrow,
			},
			.destroy = _destroy,
		},
		.plugin = plugin_ref,
	);

	return &(this->public);
}
