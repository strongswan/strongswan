/**
 * @file transaction.c
 * 
 * @brief Generic contstructor for the different transaction types.
 * 
 */

/*
 * Copyright (C) 2006 Martin Willi
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

#include "transaction.h"

#include <sa/child_sa.h>
#include <sa/transactions/ike_sa_init.h>
#include <sa/transactions/ike_auth.h>
#include <sa/transactions/delete_ike_sa.h>
#include <sa/transactions/create_child_sa.h>
#include <sa/transactions/delete_child_sa.h>
#include <sa/transactions/dead_peer_detection.h>
#include <sa/transactions/rekey_ike_sa.h>
#include <encoding/payloads/ts_payload.h>
#include <encoding/payloads/sa_payload.h>
#include <encoding/payloads/nonce_payload.h>
#include <encoding/payloads/notify_payload.h>
#include <encoding/payloads/delete_payload.h>
#include <utils/logger_manager.h>


/*
 * see header file
 */
transaction_t *transaction_create(ike_sa_t *ike_sa, message_t *request)
{
	iterator_t *iterator;
	payload_t *current;
	transaction_t *transaction = NULL;
	
	if (!request->get_request(request))
	{
		return NULL;
	}
	
	switch (request->get_exchange_type(request))
	{
		case IKE_SA_INIT:
		{
			if (ike_sa->get_state(ike_sa) == IKE_CREATED)
			{
				transaction = (transaction_t*)ike_sa_init_create(ike_sa);
			}
			break;
		}
		case IKE_AUTH:
		{
			/* IKE_AUTH is always created in IKE_SA_INIT, it never should
			 * appear alone */
			break;
		}
		case CREATE_CHILD_SA:
		{
			if (ike_sa->get_state(ike_sa) < IKE_ESTABLISHED)
			{
				break;
			}
			/* check protocol of SA payload */
			iterator = request->get_payload_iterator(request);
			while (iterator->iterate(iterator, (void**)&current))
			{
				if (current->get_type(current) == SECURITY_ASSOCIATION)
				{
					iterator_t *prop_iter;
					proposal_substructure_t *prop_struct;
					sa_payload_t *sa_payload = (sa_payload_t*)current;
					
					prop_iter = sa_payload->create_proposal_substructure_iterator(sa_payload, TRUE);
					if (prop_iter->iterate(prop_iter, (void**)&prop_struct))
					{
						switch (prop_struct->get_protocol_id(prop_struct))
						{
							case PROTO_IKE:
								transaction = (transaction_t*)
										rekey_ike_sa_create(ike_sa);
								break;
							case PROTO_AH:
							case PROTO_ESP:
								transaction = (transaction_t*)
										create_child_sa_create(ike_sa);
								break;
							default:
								break;
						}
					}
					prop_iter->destroy(prop_iter);
				}
				if (transaction)
				{
					break;
				}
			}
			iterator->destroy(iterator);
			break;
		}
		case INFORMATIONAL:
		{
			if (ike_sa->get_state(ike_sa) < IKE_ESTABLISHED)
			{
				break;
			}
			u_int payload_count = 0;
			iterator = request->get_payload_iterator(request);
			while (iterator->iterate(iterator, (void**)&current))
			{
				payload_count++;
				switch (current->get_type(current))
				{
					case DELETE:
					{
						delete_payload_t *delete_payload = (delete_payload_t*)current;
						switch (delete_payload->get_protocol_id(delete_payload))
						{
							case PROTO_IKE:
								transaction = (transaction_t*)
										delete_ike_sa_create(ike_sa);
								break;
							case PROTO_AH:
							case PROTO_ESP:
								transaction = (transaction_t*)
										delete_child_sa_create(ike_sa);
								break;
							default:
								break;
						}
						break;
					}
					default:
						break;
				}
				if (transaction)
				{
					break;
				}
			}
			iterator->destroy(iterator);
			/* empty informationals are used for dead peer detection in
			 * IKEv2. We use a special transaction for it. */
			if (payload_count == 0)
			{
				transaction = (transaction_t*)
						dead_peer_detection_create(ike_sa);
			}
			break;
		}
		default:
			break;
	}
	return transaction;	
}
