#include "isakmp_dpd.h"

#include <encoding/payloads/notify_payload.h>
#include <sa/ikev1/tasks/informational.h>

#include <daemon.h>

#ifdef SLIPSTREAM
/* Should be the last include */
#include <ikev2_mem.h>
#endif /* SLIPSTREAM */

typedef struct private_isakmp_dpd_t private_isakmp_dpd_t;

/**
 * Private members of a isakmp_dpd_t task.
 */
struct private_isakmp_dpd_t {

	/**
	 * Public methods and task_t interface.
	 */
	isakmp_dpd_t public;

	/**
	 * Sequence number.
	 */
	u_int32_t seqnr;

	/**
	 * Notify payload, only provided for requests.
	 */
	notify_payload_t *notify;

	/**
	 * IKE SA we are serving.
	 */
	ike_sa_t *ike_sa;
};

/**
 * Get DPD sequence number from notify payload.
 */
static bool get_seqnr(notify_payload_t *notify, u_int32_t *seqnr)
{
	chunk_t chunk = notify->get_notification_data(notify);

	if( chunk.ptr && chunk.len == 4)
	{
		u_int32_t seqnr_read = *((u_int32_t*)chunk.ptr);

		*seqnr = ntohl(seqnr_read);

		return TRUE;
	}

	DBG1(DBG_IKE, "no DPD seqnr received");

	return FALSE;
}

/**
 * Add notify payload to message.
 */
static void add_notify(private_isakmp_dpd_t *this, message_t *message, notify_type_t type)
{
	notify_payload_t *notify;

	ike_sa_id_t *ike_sa_id;
	u_int64_t spi_i, spi_r;
	u_int32_t seqnr;
	chunk_t spi;

	notify = notify_payload_create_from_protocol_and_type(NOTIFY_V1,
		PROTO_IKE, type);

	seqnr = htonl(this->seqnr);
	ike_sa_id = this->ike_sa->get_id(this->ike_sa);
	spi_i = ike_sa_id->get_initiator_spi(ike_sa_id);
	spi_r = ike_sa_id->get_responder_spi(ike_sa_id);
	spi = chunk_cata("cc", chunk_from_thing(spi_i), chunk_from_thing(spi_r));

	notify->set_spi_data(notify, spi);
	notify->set_notification_data(notify, chunk_from_thing(seqnr));

	message->add_payload(message, (payload_t*)notify);
}

METHOD(isakmp_dpd_t, get_dpd_seqnr, u_int32_t,
	private_isakmp_dpd_t *this)
{
	return this->seqnr;
}

METHOD(task_t, build_i, status_t,
	private_isakmp_dpd_t *this, message_t *message)
{
	add_notify(this, message, DPD_R_U_THERE);

	return NEED_MORE;
}

METHOD(task_t, build_r, status_t,
			 private_isakmp_dpd_t *this, message_t *message)
{
	add_notify(this, message, DPD_R_U_THERE_ACK);

	return SUCCESS;
}

METHOD(task_t, process_i, status_t,
	private_isakmp_dpd_t *this, message_t *message)
{
	enumerator_t *enumerator;
	notify_payload_t *notify;
	notify_type_t type;
	payload_t *payload;
	task_t *info_task = NULL;

	enumerator = message->create_payload_enumerator(message);
	while (enumerator->enumerate(enumerator, &payload))
	{
		switch (payload->get_type(payload))
		{
			case NOTIFY_V1:
				notify = (notify_payload_t*)payload;
				type = notify->get_notify_type(notify);

				if (type == DPD_R_U_THERE_ACK)
				{
					u_int32_t seqnr;

					if (!get_seqnr(notify, &seqnr))
					{
						return FAILED;
					}

					if (this->seqnr != seqnr)
					{
						DBG1(DBG_IKE, "received DPD Ack with unexpected seqnr (%u) expect (%u)",seqnr,this->seqnr);
						return SUCCESS;
					}

					DBG4(DBG_IKE, "received DPD Ack with seqnr (%u)",seqnr);

					return SUCCESS;

				}
				else if (type == DPD_R_U_THERE)
				{
					u_int32_t expected = this->seqnr + 1;

					if (!get_seqnr(notify, &this->seqnr))
					{
						return FAILED;
					}

					if (expected != 1 && this->seqnr != expected)
					{
						DBG1(DBG_IKE, "received DPD request with unexpected seqnr (%u) expect (%u)",
							this->seqnr,expected);
						return SUCCESS;
					}

					DBG4(DBG_IKE, "received DPD request with seqnr %u",this->seqnr);

					this->public.task.build = _build_r;
					return NEED_MORE;
				}
				else
				{
					info_task = (task_t*)informational_create(this->ike_sa, NULL, 0);
				}
				continue;

			default:
				continue;
		}
		break;
	}
	enumerator->destroy(enumerator);

	if (info_task)
	{
		status_t status = info_task->process(info_task, message);
		/* Assuming that the informational task will not need to send other replies than dpd */
		info_task->destroy(info_task);
		return status;
	}

	return SUCCESS;
}

METHOD(task_t, process_r, status_t,
			 private_isakmp_dpd_t *this, message_t *message)
{
	u_int32_t expected = this->seqnr + 1;

	if (this->notify)
	{
		if (!get_seqnr(this->notify, &this->seqnr))
		{
			return FAILED;
		}

		if (expected != 1 && this->seqnr != expected)
		{
			DBG1(DBG_IKE, "received DPD request with unexpected seqnr (%u) expect (%u)",
				this->seqnr,expected);
			return SUCCESS;
		}

		DBG4(DBG_IKE, "DPD request received with seqnr %u",this->seqnr);
	}
	else
	{
		DBG1(DBG_IKE, "no notify provided");
		return FAILED;
	}
	return NEED_MORE;
}


METHOD(task_t, get_type, task_type_t,
	private_isakmp_dpd_t *this)
{
	return TASK_ISAKMP_DPD;
}


METHOD(task_t, migrate, void,
	private_isakmp_dpd_t *this, ike_sa_t *ike_sa)
{
	this->ike_sa = ike_sa;
	this->seqnr = 0;

}

METHOD(task_t, destroy, void,
	private_isakmp_dpd_t *this)
{
	free(this);
}

/*
 * Described in header.
 */
isakmp_dpd_t *isakmp_dpd_create(ike_sa_t *ike_sa, notify_payload_t *notify, u_int32_t seqnr)
{
	private_isakmp_dpd_t *this;

	INIT(this,
		.public = {
			.task = {
				.get_type = _get_type,
				.migrate = _migrate,
				.destroy = _destroy,
			},
			.get_dpd_seqnr = _get_dpd_seqnr,
		},
		.notify = notify,
		.ike_sa = ike_sa,
		.seqnr = seqnr,
	);

	if (!notify)
	{
		this->public.task.build = _build_i;
		this->public.task.process = _process_i;
	}
	else
	{
		this->public.task.build = _build_r;
		this->public.task.process = _process_r;
	}

	return &this->public;
}
