/*
 * Copyright (C) 2008 Tobias Brunner
 * Copyright (C) 2005-2006 Martin Willi
 * Copyright (C) 2005 Jan Hutter
 * Hochschule fuer Technik Rapperswil
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

#include <stdlib.h>
#include <unistd.h>

#include "receiver.h"

#include <daemon.h>
#include <network/socket.h>
#include <network/packet.h>
#include <processing/jobs/job.h>
#include <processing/jobs/process_message_job.h>
#include <processing/jobs/callback_job.h>
#include <crypto/hashers/hasher.h>

/** lifetime of a cookie, in seconds */
#define COOKIE_LIFETIME 10
/** how many times to reuse the secret */
#define COOKIE_REUSE 10000
/** default value for private_receiver_t.cookie_threshold */
#define COOKIE_THRESHOLD_DEFAULT 10
/** default value for private_receiver_t.block_threshold */
#define BLOCK_THRESHOLD_DEFAULT 5
/** length of the secret to use for cookie calculation */
#define SECRET_LENGTH 16

typedef struct private_receiver_t private_receiver_t;

/**
 * Private data of a receiver_t object.
 */
struct private_receiver_t {
	/**
	 * Public part of a receiver_t object.
	 */
	receiver_t public;

	/**
	 * Threads job receiving packets
	 */
	callback_job_t *job;

	/**
	 * current secret to use for cookie calculation
	 */
	char secret[SECRET_LENGTH];

	/**
	 * previous secret used to verify older cookies
	 */
	char secret_old[SECRET_LENGTH];

	/**
	 * how many times we have used "secret" so far
	 */
	u_int32_t secret_used;

	/**
	 * time we did the cookie switch
	 */
	u_int32_t secret_switch;

	/**
	 * time offset to use, hides our system time
	 */
	u_int32_t secret_offset;

	/**
	 * the RNG to use for secret generation
	 */
	rng_t *rng;

	/**
	 * hasher to use for cookie calculation
	 */
	hasher_t *hasher;

	/**
	 * require cookies after this many half open IKE_SAs
	 */
	u_int32_t cookie_threshold;

	/**
	 * how many half open IKE_SAs per peer before blocking
	 */
	u_int32_t block_threshold;
};

/**
 * send a notify back to the sender
 */
static void send_notify(message_t *request, notify_type_t type, chunk_t data)
{
	if (request->get_request(request) &&
		request->get_exchange_type(request) == IKE_SA_INIT)
	{
		message_t *response;
		host_t *src, *dst;
		packet_t *packet;
		ike_sa_id_t *ike_sa_id;

		response = message_create();
		dst = request->get_source(request);
		src = request->get_destination(request);
		response->set_source(response, src->clone(src));
		response->set_destination(response, dst->clone(dst));
		response->set_exchange_type(response, request->get_exchange_type(request));
		response->set_request(response, FALSE);
		response->set_message_id(response, 0);
		ike_sa_id = request->get_ike_sa_id(request);
		ike_sa_id->switch_initiator(ike_sa_id);
		response->set_ike_sa_id(response, ike_sa_id);
		response->add_notify(response, FALSE, type, data);
		if (response->generate(response, NULL, NULL, &packet) == SUCCESS)
		{
			charon->sender->send(charon->sender, packet);
			response->destroy(response);
		}
	}
}

/**
 * build a cookie
 */
static chunk_t cookie_build(private_receiver_t *this, message_t *message,
							u_int32_t t, chunk_t secret)
{
	u_int64_t spi = message->get_initiator_spi(message);
	host_t *ip = message->get_source(message);
	chunk_t input, hash;

	/* COOKIE = t | sha1( IPi | SPIi | t | secret ) */
	input = chunk_cata("cccc", ip->get_address(ip), chunk_from_thing(spi),
					  chunk_from_thing(t), secret);
	hash = chunk_alloca(this->hasher->get_hash_size(this->hasher));
	this->hasher->get_hash(this->hasher, input, hash.ptr);
	return chunk_cat("cc", chunk_from_thing(t), hash);
}

/**
 * verify a received cookie
 */
static bool cookie_verify(private_receiver_t *this, message_t *message,
						  chunk_t cookie)
{
	u_int32_t t, now;
	chunk_t reference;
	chunk_t secret;

	now = time_monotonic(NULL);
	t = *(u_int32_t*)cookie.ptr;

	if (cookie.len != sizeof(u_int32_t) +
			this->hasher->get_hash_size(this->hasher) ||
		t < now - this->secret_offset - COOKIE_LIFETIME)
	{
		DBG2(DBG_NET, "received cookie lifetime expired, rejecting");
		return FALSE;
	}

	/* check if cookie is derived from old_secret */
	if (t + this->secret_offset > this->secret_switch)
	{
		secret = chunk_from_thing(this->secret);
	}
	else
	{
		secret = chunk_from_thing(this->secret_old);
	}

	/* compare own calculation against received */
	reference = cookie_build(this, message, t, secret);
	if (chunk_equals(reference, cookie))
	{
		chunk_free(&reference);
		return TRUE;
	}
	chunk_free(&reference);
	return FALSE;
}

/**
 * check if cookies are required, and if so, a valid cookie is included
 */
static bool cookie_required(private_receiver_t *this, message_t *message)
{
	bool failed = FALSE;

	if (charon->ike_sa_manager->get_half_open_count(charon->ike_sa_manager,
												NULL) >= this->cookie_threshold)
	{
		/* check for a cookie. We don't use our parser here and do it
		 * quick and dirty for performance reasons.
		 * we assume the cookie is the first payload (which is a MUST), and
		 * the cookie's SPI length is zero. */
		packet_t *packet = message->get_packet(message);
		chunk_t data = packet->get_data(packet);
		if (data.len <
			 IKE_HEADER_LENGTH + NOTIFY_PAYLOAD_HEADER_LENGTH +
			 sizeof(u_int32_t) + this->hasher->get_hash_size(this->hasher) ||
			*(data.ptr + 16) != NOTIFY ||
			*(u_int16_t*)(data.ptr + IKE_HEADER_LENGTH + 6) != htons(COOKIE))
		{
			/* no cookie found */
			failed = TRUE;
		}
		else
		{
			data.ptr += IKE_HEADER_LENGTH + NOTIFY_PAYLOAD_HEADER_LENGTH;
			data.len = sizeof(u_int32_t) + this->hasher->get_hash_size(this->hasher);
			if (!cookie_verify(this, message, data))
			{
				DBG2(DBG_NET, "found cookie, but content invalid");
				failed = TRUE;
			}
		}
		packet->destroy(packet);
	}
	return failed;
}

/**
 * check if peer has to many half open IKE_SAs
 */
static bool peer_to_aggressive(private_receiver_t *this, message_t *message)
{
	if (charon->ike_sa_manager->get_half_open_count(charon->ike_sa_manager,
						message->get_source(message)) >= this->block_threshold)
	{
		return TRUE;
	}
	return FALSE;
}

/**
 * Job callback to receive packets
 */
static job_requeue_t receive_packets(private_receiver_t *this)
{
	packet_t *packet;
	message_t *message;
	job_t *job;

	/* read in a packet */
	if (charon->socket->receive(charon->socket, &packet) != SUCCESS)
	{
		DBG2(DBG_NET, "receiving from socket failed!");
		return JOB_REQUEUE_FAIR;
	}

	/* parse message header */
	message = message_create_from_packet(packet);
	if (message->parse_header(message) != SUCCESS)
	{
		DBG1(DBG_NET, "received invalid IKE header from %H - ignored",
			 packet->get_source(packet));
		message->destroy(message);
		return JOB_REQUEUE_DIRECT;
	}

	/* check IKE major version */
	if (message->get_major_version(message) != IKE_MAJOR_VERSION)
	{
		DBG1(DBG_NET, "received unsupported IKE version %d.%d from %H, "
			 "sending INVALID_MAJOR_VERSION", message->get_major_version(message),
			 message->get_minor_version(message), packet->get_source(packet));
		send_notify(message, INVALID_MAJOR_VERSION, chunk_empty);
		message->destroy(message);
		return JOB_REQUEUE_DIRECT;
	}

	if (message->get_request(message) &&
		message->get_exchange_type(message) == IKE_SA_INIT)
	{
		/* check for cookies */
		if (this->cookie_threshold && cookie_required(this, message))
		{
			u_int32_t now = time_monotonic(NULL);
			chunk_t cookie = cookie_build(this, message, now - this->secret_offset,
										  chunk_from_thing(this->secret));

			DBG2(DBG_NET, "received packet from: %#H to %#H",
				 message->get_source(message),
				 message->get_destination(message));
			DBG2(DBG_NET, "sending COOKIE notify to %H",
				 message->get_source(message));
			send_notify(message, COOKIE, cookie);
			chunk_free(&cookie);
			if (++this->secret_used > COOKIE_REUSE)
			{
				/* create new cookie */
				DBG1(DBG_NET, "generating new cookie secret after %d uses",
					 this->secret_used);
				memcpy(this->secret_old, this->secret, SECRET_LENGTH);
				this->rng->get_bytes(this->rng,	SECRET_LENGTH, this->secret);
				this->secret_switch = now;
				this->secret_used = 0;
			}
			message->destroy(message);
			return JOB_REQUEUE_DIRECT;
		}

		/* check if peer has not too many IKE_SAs half open */
		if (this->block_threshold && peer_to_aggressive(this, message))
		{
			DBG1(DBG_NET, "ignoring IKE_SA setup from %H, "
				 "peer too aggressive", message->get_source(message));
			message->destroy(message);
			return JOB_REQUEUE_DIRECT;
		}
	}
	job = (job_t*)process_message_job_create(message);
	charon->processor->queue_job(charon->processor, job);
	return JOB_REQUEUE_DIRECT;
}

METHOD(receiver_t, destroy, void,
	private_receiver_t *this)
{
	this->job->cancel(this->job);
	this->rng->destroy(this->rng);
	this->hasher->destroy(this->hasher);
	free(this);
}

/*
 * Described in header.
 */
receiver_t *receiver_create()
{
	private_receiver_t *this;
	u_int32_t now = time_monotonic(NULL);

	INIT(this,
		.public.destroy = _destroy,
		.secret_switch = now,
		.secret_offset = random() % now,
	);

	if (lib->settings->get_bool(lib->settings, "charon.dos_protection", TRUE))
	{
		this->cookie_threshold = lib->settings->get_int(lib->settings,
						"charon.cookie_threshold", COOKIE_THRESHOLD_DEFAULT);
		this->block_threshold = lib->settings->get_int(lib->settings,
						"charon.block_threshold", BLOCK_THRESHOLD_DEFAULT);
	}
	this->hasher = lib->crypto->create_hasher(lib->crypto, HASH_PREFERRED);
	if (this->hasher == NULL)
	{
		DBG1(DBG_NET, "creating cookie hasher failed, no hashers supported");
		free(this);
		return NULL;
	}
	this->rng = lib->crypto->create_rng(lib->crypto, RNG_STRONG);
	if (this->rng == NULL)
	{
		DBG1(DBG_NET, "creating cookie RNG failed, no RNG supported");
		this->hasher->destroy(this->hasher);
		free(this);
		return NULL;
	}
	this->rng->get_bytes(this->rng, SECRET_LENGTH, this->secret);
	memcpy(this->secret_old, this->secret, SECRET_LENGTH);

	this->job = callback_job_create((callback_job_cb_t)receive_packets,
									this, NULL, NULL);
	charon->processor->queue_job(charon->processor, (job_t*)this->job);

	return &this->public;
}

