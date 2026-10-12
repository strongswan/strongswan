/*
 * Copyright (C) 2007-2012 Martin Willi
 *
 * Copyright (C) secunet Security Networks AG
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

#define _GNU_SOURCE
#include "eap_gtc.h"

#include <daemon.h>
#include <library.h>
#include <sa/ike_sa.h>

#ifdef __linux__
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <signal.h>
#include <stdio.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>
#endif /* __linux__ */

#define GTC_REQUEST_MSG "password"

typedef struct private_eap_gtc_t private_eap_gtc_t;

/**
 * Private data of an eap_gtc_t object.
 */
struct private_eap_gtc_t {

	/**
	 * Public authenticator_t interface.
	 */
	eap_gtc_t public;

	/**
	 * ID of the server
	 */
	identification_t *server;

	/**
	 * ID of the peer
	 */
	identification_t *peer;

	/**
	 * EAP message identifier
	 */
	uint8_t identifier;

	/**
	 * This method has entered the selected Fortinet credential path.
	 */
	bool forti_selected;

	/**
	 * Empty GTC responses continue an explicitly approved push wait.
	 */
	bool forti_push_wait;
};

typedef struct eap_gtc_header_t eap_gtc_header_t;

/**
 * packed eap GTC header struct
 */
struct eap_gtc_header_t {
	/** EAP code (REQUEST/RESPONSE) */
	uint8_t code;
	/** unique message identifier */
	uint8_t identifier;
	/** length of whole message */
	uint16_t length;
	/** EAP type */
	uint8_t type;
	/** type data */
	uint8_t data[];
} __attribute__((__packed__));

METHOD(eap_method_t, initiate_peer, status_t,
	private_eap_gtc_t *this, eap_payload_t **out)
{
	/* peer never initiates */
	return FAILED;
}

METHOD(eap_method_t, initiate_server, status_t,
	private_eap_gtc_t *this, eap_payload_t **out)
{
	eap_gtc_header_t *req;
	size_t len;

	len = strlen(GTC_REQUEST_MSG);
	req = alloca(sizeof(eap_gtc_header_t) + len);
	req->length = htons(sizeof(eap_gtc_header_t) + len);
	req->code = EAP_REQUEST;
	req->identifier = this->identifier;
	req->type = EAP_GTC;
	memcpy(req->data, GTC_REQUEST_MSG, len);

	*out = eap_payload_create_data(chunk_create((void*)req,
								   sizeof(eap_gtc_header_t) + len));
	return NEED_MORE;
}

#ifdef __linux__

/**
 * Get monotonic time in milliseconds for the bounded helper exchange.
 */
static int64_t monotonic_milliseconds(void)
{
	struct timespec now;

	if (clock_gettime(CLOCK_MONOTONIC, &now))
	{
		return -1;
	}
	return (int64_t)now.tv_sec * 1000 + now.tv_nsec / 1000000;
}

/**
 * Run an absolute helper without a shell, bound its wait and erase its output.
 */
static bool fortigate_otp_read(ike_sa_t *sa, chunk_t *out)
{
	char *helper, *connection, id[16], buf[32] = {0};
	int fds[2], status = 0;
	pid_t pid, waited;
	int64_t deadline, now;
	size_t used = 0, i;
	bool ok = FALSE, eof = FALSE;
	bool push_capable = sa->has_condition(sa, COND_FORTIGATE_MFA_PUSH);

	helper = lib->settings->get_str(lib->settings,
			"%s.plugins.eap-gtc.otp_helper", NULL, lib->ns);
	if (!helper || helper[0] != '/' || pipe2(fds, O_CLOEXEC))
	{
		DBG1(DBG_IKE, "FortiGate MFA requires an absolute-path OTP helper");
		return FALSE;
	}
	now = monotonic_milliseconds();
	if (now < 0)
	{
		close(fds[0]);
		close(fds[1]);
		return FALSE;
	}
	deadline = now + 125000;
	snprintf(id, sizeof(id), "%u", sa->get_unique_id(sa));
	connection = sa->get_name(sa);
	pid = fork();
	if (!pid)
	{
		int nullfd = open("/dev/null", O_RDWR);
		if (nullfd < 0 || dup2(fds[1], STDOUT_FILENO) < 0 ||
			dup2(nullfd, STDIN_FILENO) < 0 || dup2(nullfd, STDERR_FILENO) < 0)
		{
			_exit(127);
		}
		/* Do not leak daemon/VICI/UDP descriptors into the token agent. */
		closefrom(3);
		if (push_capable)
		{
			execl(helper, helper, "--ike-id", id, "--connection", connection,
				  "--push-capable", (char*)NULL);
		}
		else
		{
			execl(helper, helper, "--ike-id", id, "--connection",
				  connection, (char*)NULL);
		}
		_exit(127);
	}
	close(fds[1]);
	if (pid < 0)
	{
		close(fds[0]);
		return FALSE;
	}
	DBG1(DBG_IKE, "FortiGate MFA: waiting for the runtime token agent");
	while (used < sizeof(buf))
	{
		struct pollfd fd = { .fd = fds[0], .events = POLLIN };
		ssize_t got;
		int ready;

		now = monotonic_milliseconds();
		if (now < 0 || now >= deadline)
		{
			break;
		}
		ready = poll(&fd, 1, deadline - now);
		if (ready < 0 && errno == EINTR)
		{
			continue;
		}
		if (ready <= 0 || (fd.revents & (POLLERR | POLLNVAL)))
		{
			break;
		}
		got = read(fds[0], buf + used, sizeof(buf) - used);
		if (got < 0 && errno == EINTR)
		{
			continue;
		}
		if (!got)
		{
			eof = TRUE;
			break;
		}
		if (got < 0)
		{
			break;
		}
		used += got;
	}
	close(fds[0]);
	if (!eof)
	{
		kill(pid, SIGKILL);
	}
	/* EOF alone does not guarantee exit; keep the same bounded deadline. */
	do
	{
		waited = waitpid(pid, &status, WNOHANG);
		if (!waited || (waited < 0 && errno == EINTR))
		{
			now = monotonic_milliseconds();
			if (now < 0 || now >= deadline)
			{
				kill(pid, SIGKILL);
				while (waitpid(pid, &status, 0) < 0 && errno == EINTR)
				{
				}
				eof = FALSE;
				break;
			}
			poll(NULL, 0, 10);
		}
	} while (!waited || (waited < 0 && errno == EINTR));
	if (eof && waited == pid && WIFEXITED(status) && !WEXITSTATUS(status))
	{
		/* Typed local decision, not text to put in the EAP payload. No output,
		 * cancellation or a failed helper must never be mistaken for push. */
		if (push_capable && used == 5 && memeq(buf, "PUSH\n", 5))
		{
			*out = chunk_empty;
			ok = TRUE;
		}
		else
		{
			if (used && buf[used - 1] == '\n')
			{
				used--;
			}
			if (used && buf[used - 1] == '\r')
			{
				used--;
			}
			ok = used >= 4 && used <= 8;
			for (i = 0; ok && i < used; i++)
			{
				ok = buf[i] >= '0' && buf[i] <= '9';
			}
			if (ok)
			{
				*out = chunk_clone(chunk_create(buf, used));
			}
		}
	}
	memwipe(buf, sizeof(buf));
	if (!ok)
	{
		DBG1(DBG_IKE, "FortiGate MFA token request cancelled, invalid, "
			 "or timed out");
	}
	return ok;
}

#else /* !__linux__ */

/**
 * The runtime helper currently requires Linux process and pipe facilities.
 */
static bool fortigate_otp_read(ike_sa_t *sa, chunk_t *out)
{
	(void)sa;
	(void)out;
	DBG1(DBG_IKE, "Fortinet MFA runtime helpers are only supported on Linux");
	return FALSE;
}

#endif /* __linux__ */

METHOD(eap_method_t, process_peer, status_t,
	private_eap_gtc_t *this, eap_payload_t *in, eap_payload_t **out)
{
	eap_gtc_header_t *res;
	shared_key_t *shared = NULL;
	chunk_t key = chunk_empty;
	ike_sa_t *sa = charon->bus->get_sa(charon->bus);
	bool token = ike_sa_is_fortigate_mfa(sa);
	size_t len;

	if (token)
	{
		this->forti_selected = TRUE;
	}
	if (this->forti_selected && !token)
	{
		/* Keep this one-way even after a failed push request. Removing the
		 * opt-in must never route this method to an ordinary EAP password. */
		this->forti_push_wait = FALSE;
		return FAILED;
	}
	if (token)
	{
		chunk_t request = in->get_data(in);

		if (request.len < 5 || request.ptr[0] != EAP_REQUEST ||
			request.ptr[4] != EAP_GTC ||
			untoh16(request.ptr + 2) != request.len)
		{
			this->forti_push_wait = FALSE;
			return FAILED;
		}
		if (this->forti_push_wait)
		{
			if (!sa->has_condition(sa, COND_FORTIGATE_MFA_PUSH))
			{
				this->forti_push_wait = FALSE;
				return FAILED;
			}
			/* FortiClient answers each subsequent GTC request with no data
			 * while the gateway waits for the mobile push approval. */
			key = chunk_empty;
		}
		else
		{
			if (!fortigate_otp_read(sa, &key))
			{
				return FAILED;
			}
			this->forti_push_wait = key.len == 0;
			if (this->forti_push_wait)
			{
				DBG1(DBG_IKE, "FortiGate MFA: requesting "
					 "FortiToken Mobile push");
			}
		}
	}
	else
	{
		shared = lib->credmgr->get_shared(lib->credmgr, SHARED_EAP,
										  this->peer, this->server);
		if (shared == NULL)
		{
			DBG1(DBG_IKE, "no EAP key found for '%Y' - '%Y'",
				 this->peer, this->server);
			return FAILED;
		}
		key = shared->get_key(shared);
	}
	len = key.len;

	/* TODO: According to the draft we should "SASLprep" password, RFC4013. */

	this->identifier = in->get_identifier(in);
	res = alloca(sizeof(eap_gtc_header_t) + len);
	res->length = htons(sizeof(eap_gtc_header_t) + len);
	res->code = EAP_RESPONSE;
	res->identifier = this->identifier;
	res->type = EAP_GTC;
	if (len)
	{
		memcpy(res->data, key.ptr, len);
	}

	if (token)
	{
		chunk_clear(&key);
	}
	else
	{
		shared->destroy(shared);
	}

	*out = eap_payload_create_data(chunk_create((void*)res,
								   sizeof(eap_gtc_header_t) + len));
	if (token)
	{
		memwipe(res, sizeof(eap_gtc_header_t) + len);
	}
	return NEED_MORE;
}

METHOD(eap_method_t, process_server, status_t,
	private_eap_gtc_t *this, eap_payload_t *in, eap_payload_t **out)
{
	status_t status = FAILED;
	chunk_t user, pass;
	xauth_method_t *xauth;
	cp_payload_t *ci, *co;
	char *backend;

	user = this->peer->get_encoding(this->peer);
	pass = chunk_skip(in->get_data(in), 5);
	if (this->identifier != in->get_identifier(in) || !pass.len)
	{
		DBG1(DBG_IKE, "received invalid EAP-GTC message");
		return FAILED;
	}

	/* get XAuth backend to use for credential verification. Default to PAM
	 * to support legacy EAP-GTC configurations */
	backend = lib->settings->get_str(lib->settings,
								"%s.plugins.eap-gtc.backend", "pam", lib->ns);
	xauth = charon->xauth->create_instance(charon->xauth, backend, XAUTH_SERVER,
										   this->server, this->peer);
	if (!xauth)
	{
		DBG1(DBG_IKE, "creating EAP-GTC XAuth backend '%s' failed", backend);
		return FAILED;
	}
	if (xauth->initiate(xauth, &co) == NEED_MORE)
	{
		/* assume that "out" contains username/password attributes */
		co->destroy(co);
		ci = cp_payload_create_type(PLV1_CONFIGURATION, CFG_REPLY);
		ci->add_attribute(ci, configuration_attribute_create_chunk(
					PLV1_CONFIGURATION_ATTRIBUTE, XAUTH_USER_NAME, user));
		ci->add_attribute(ci, configuration_attribute_create_chunk(
					PLV1_CONFIGURATION_ATTRIBUTE, XAUTH_USER_PASSWORD, pass));
		switch (xauth->process(xauth, ci, &co))
		{
			case SUCCESS:
				status = SUCCESS;
				break;
			case NEED_MORE:
				/* TODO: multiple exchanges currently not supported */
				co->destroy(co);
				break;
			case FAILED:
			default:
				break;
		}
		ci->destroy(ci);
	}
	xauth->destroy(xauth);
	return status;
}

METHOD(eap_method_t, get_type, eap_type_t,
	private_eap_gtc_t *this, pen_t *vendor)
{
	*vendor = 0;
	return EAP_GTC;
}

METHOD(eap_method_t, get_msk, status_t,
	private_eap_gtc_t *this, chunk_t *msk)
{
	return NOT_SUPPORTED;
}

METHOD(eap_method_t, get_identifier, uint8_t,
	private_eap_gtc_t *this)
{
	return this->identifier;
}

METHOD(eap_method_t, set_identifier, void,
	private_eap_gtc_t *this, uint8_t identifier)
{
	this->identifier = identifier;
}

METHOD(eap_method_t, is_mutual, bool,
	private_eap_gtc_t *this)
{
	return FALSE;
}

METHOD(eap_method_t, destroy, void,
	private_eap_gtc_t *this)
{
	this->peer->destroy(this->peer);
	this->server->destroy(this->server);
	free(this);
}

/**
 * Generic constructor
 */
static private_eap_gtc_t *eap_gtc_create_generic(identification_t *server,
												 identification_t *peer)
{
	private_eap_gtc_t *this;

	INIT(this,
		.public = {
			.eap_method_interface = {
				.get_type = _get_type,
				.is_mutual = _is_mutual,
				.get_msk = _get_msk,
				.get_identifier = _get_identifier,
				.set_identifier = _set_identifier,
				.destroy = _destroy,
			},
		},
		.peer = peer->clone(peer),
		.server = server->clone(server),
	);

	return this;
}

/*
 * see header
 */
eap_gtc_t *eap_gtc_create_server(identification_t *server, identification_t *peer)
{
	private_eap_gtc_t *this = eap_gtc_create_generic(server, peer);

	this->public.eap_method_interface.initiate = _initiate_server;
	this->public.eap_method_interface.process = _process_server;

	/* generate a non-zero identifier */
	do {
		this->identifier = random();
	} while (!this->identifier);

	return &this->public;
}

/*
 * see header
 */
eap_gtc_t *eap_gtc_create_peer(identification_t *server, identification_t *peer)
{
	private_eap_gtc_t *this = eap_gtc_create_generic(server, peer);

	this->public.eap_method_interface.initiate = _initiate_peer;
	this->public.eap_method_interface.process = _process_peer;

	return &this->public;
}
