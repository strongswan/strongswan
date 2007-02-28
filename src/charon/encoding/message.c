/**
 * @file message.c
 *
 * @brief Implementation of message_t.
 *
 */

/*
 * Copyright (C) 2006 Tobias Brunner, Daniel Roethlisberger
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
#include <string.h>
#include <printf.h>

#include "message.h"

#include <library.h>
#include <daemon.h>
#include <sa/ike_sa_id.h>
#include <encoding/generator.h>
#include <encoding/parser.h>
#include <utils/linked_list.h>
#include <encoding/payloads/encodings.h>
#include <encoding/payloads/payload.h>
#include <encoding/payloads/encryption_payload.h>
#include <encoding/payloads/unknown_payload.h>

/**
 * Max number of notify payloads per IKEv2 Message
 */
#define MAX_NOTIFY_PAYLOADS 20


typedef struct payload_rule_t payload_rule_t;

/**
 * A payload rule defines the rules for a payload
 * in a specific message rule. It defines if and how 
 * many times a payload must/can occur in a message
 * and if it must be encrypted.
 */
struct payload_rule_t {
	/**
	 * Payload type.
	 */
	 payload_type_t payload_type;
	 
	 /**
	  * Minimal occurence of this payload.
	  */
	 size_t min_occurence;

	 /**
	  * Max occurence of this payload.
	  */
	 size_t max_occurence;
	 
	 /**
	  * TRUE if payload must be encrypted
	  */
	 bool encrypted;
	 
	 /**
	  * If this payload occurs, the message rule is
	  * fullfilled in any case. This applies e.g. to 
	  * notify_payloads.
	  */
	 bool sufficient;
};

typedef struct message_rule_t message_rule_t;

/**
 * A message rule defines the kind of a message,
 * if it has encrypted contents and a list
 * of payload rules.
 * 
 */
struct message_rule_t {
	/**
	 * Type of message.
	 */
	exchange_type_t exchange_type;
	
	/**
	 * Is message a request or response.
	 */
	bool is_request;

	/**
	 * Message contains encrypted content.
	 */
	bool encrypted_content;
	
	/**
	 * Number of payload rules which will follow
	 */
	size_t payload_rule_count;
	 
	/**
	 * Pointer to first payload rule
	 */
	payload_rule_t *payload_rules;
};

/**
 * Message rule for IKE_SA_INIT from initiator.
 */
static payload_rule_t ike_sa_init_i_payload_rules[] = {
	{NOTIFY,0,MAX_NOTIFY_PAYLOADS,FALSE,FALSE},
	{SECURITY_ASSOCIATION,1,1,FALSE,FALSE},
	{KEY_EXCHANGE,1,1,FALSE,FALSE},
	{NONCE,1,1,FALSE,FALSE},
};

/**
 * Message rule for IKE_SA_INIT from responder.
 */
static payload_rule_t ike_sa_init_r_payload_rules[] = {
	{NOTIFY,0,MAX_NOTIFY_PAYLOADS,FALSE,TRUE},
	{SECURITY_ASSOCIATION,1,1,FALSE,FALSE},
	{KEY_EXCHANGE,1,1,FALSE,FALSE},
	{NONCE,1,1,FALSE,FALSE},
};

/**
 * Message rule for IKE_AUTH from initiator.
 */
static payload_rule_t ike_auth_i_payload_rules[] = {
	{NOTIFY,0,MAX_NOTIFY_PAYLOADS,TRUE,FALSE},
	{EXTENSIBLE_AUTHENTICATION,0,1,TRUE,TRUE},
	{AUTHENTICATION,0,1,TRUE,TRUE},
	{ID_INITIATOR,1,1,TRUE,FALSE},
	{CERTIFICATE,0,1,TRUE,FALSE},
	{CERTIFICATE_REQUEST,0,1,TRUE,FALSE},
	{ID_RESPONDER,0,1,TRUE,FALSE},
	{SECURITY_ASSOCIATION,1,1,TRUE,FALSE},
	{TRAFFIC_SELECTOR_INITIATOR,1,1,TRUE,FALSE},
	{TRAFFIC_SELECTOR_RESPONDER,1,1,TRUE,FALSE},
	{CONFIGURATION,0,1,TRUE,FALSE},
};

/**
 * Message rule for IKE_AUTH from responder.
 */
static payload_rule_t ike_auth_r_payload_rules[] = {
	{NOTIFY,0,MAX_NOTIFY_PAYLOADS,TRUE,TRUE},
	{EXTENSIBLE_AUTHENTICATION,0,1,TRUE,TRUE},
	{CERTIFICATE,0,1,TRUE,FALSE},
	{ID_RESPONDER,0,1,TRUE,FALSE},
	{AUTHENTICATION,0,1,TRUE,FALSE},
	{SECURITY_ASSOCIATION,0,1,TRUE,FALSE},
	{TRAFFIC_SELECTOR_INITIATOR,0,1,TRUE,FALSE},
	{TRAFFIC_SELECTOR_RESPONDER,0,1,TRUE,FALSE},
	{CONFIGURATION,0,1,TRUE,FALSE},
};


/**
 * Message rule for INFORMATIONAL from initiator.
 */
static payload_rule_t informational_i_payload_rules[] = {
	{NOTIFY,0,MAX_NOTIFY_PAYLOADS,TRUE,FALSE},
	{CONFIGURATION,0,1,TRUE,FALSE},
	{DELETE,0,1,TRUE,FALSE},
	
};

/**
 * Message rule for INFORMATIONAL from responder.
 */
static payload_rule_t informational_r_payload_rules[] = {
	{NOTIFY,0,MAX_NOTIFY_PAYLOADS,TRUE,FALSE},
	{CONFIGURATION,0,1,TRUE,FALSE},
	{DELETE,0,1,TRUE,FALSE},
};

/**
 * Message rule for CREATE_CHILD_SA from initiator.
 */
static payload_rule_t create_child_sa_i_payload_rules[] = {
	{NOTIFY,0,MAX_NOTIFY_PAYLOADS,TRUE,FALSE},
	{SECURITY_ASSOCIATION,1,1,TRUE,FALSE},
	{NONCE,1,1,TRUE,FALSE},
	{KEY_EXCHANGE,0,1,TRUE,FALSE},
	{TRAFFIC_SELECTOR_INITIATOR,0,1,TRUE,FALSE},
	{TRAFFIC_SELECTOR_RESPONDER,0,1,TRUE,FALSE},
	{CONFIGURATION,0,1,TRUE,FALSE},
};

/**
 * Message rule for CREATE_CHILD_SA from responder.
 */
static payload_rule_t create_child_sa_r_payload_rules[] = {
	{NOTIFY,0,MAX_NOTIFY_PAYLOADS,TRUE,TRUE},
	{SECURITY_ASSOCIATION,1,1,TRUE,FALSE},
	{NONCE,1,1,TRUE,FALSE},
	{KEY_EXCHANGE,0,1,TRUE,FALSE},
	{TRAFFIC_SELECTOR_INITIATOR,0,1,TRUE,FALSE},
	{TRAFFIC_SELECTOR_RESPONDER,0,1,TRUE,FALSE},
	{CONFIGURATION,0,1,TRUE,FALSE},
};


/**
 * Message rules, defines allowed payloads.
 */
static message_rule_t message_rules[] = {
	{IKE_SA_INIT,TRUE,FALSE,(sizeof(ike_sa_init_i_payload_rules)/sizeof(payload_rule_t)),ike_sa_init_i_payload_rules},
	{IKE_SA_INIT,FALSE,FALSE,(sizeof(ike_sa_init_r_payload_rules)/sizeof(payload_rule_t)),ike_sa_init_r_payload_rules},
	{IKE_AUTH,TRUE,TRUE,(sizeof(ike_auth_i_payload_rules)/sizeof(payload_rule_t)),ike_auth_i_payload_rules},
	{IKE_AUTH,FALSE,TRUE,(sizeof(ike_auth_r_payload_rules)/sizeof(payload_rule_t)),ike_auth_r_payload_rules},
	{INFORMATIONAL,TRUE,TRUE,(sizeof(informational_i_payload_rules)/sizeof(payload_rule_t)),informational_i_payload_rules},
	{INFORMATIONAL,FALSE,TRUE,(sizeof(informational_r_payload_rules)/sizeof(payload_rule_t)),informational_r_payload_rules},
	{CREATE_CHILD_SA,TRUE,TRUE,(sizeof(create_child_sa_i_payload_rules)/sizeof(payload_rule_t)),create_child_sa_i_payload_rules},
	{CREATE_CHILD_SA,FALSE,TRUE,(sizeof(create_child_sa_r_payload_rules)/sizeof(payload_rule_t)),create_child_sa_r_payload_rules},
};


typedef struct private_message_t private_message_t;

/**
 * Private data of an message_t object.
 */
struct private_message_t {

	/**
	 * Public part of a message_t object.
	 */
	message_t public;

	/**
	 * Minor version of message.
	 */
	u_int8_t major_version;
	
	/**
	 * Major version of message.
	 */
	u_int8_t minor_version;
	
	/**
	 * First Payload in message.
	 */
	payload_type_t first_payload;

	/**
	 * Assigned exchange type.
	 */
	exchange_type_t exchange_type;

	/**
	 * TRUE if message is a request, FALSE if a reply.
	 */
	bool is_request;
	
	/**
	 * Message ID of this message.
	 */
	u_int32_t message_id;
	
	/**
	 * ID of assigned IKE_SA.
	 */
	ike_sa_id_t *ike_sa_id;
	
	/**
	 * Assigned UDP packet, stores incoming packet or last generated one.
	 */
	packet_t *packet;
	 
	/**
	 * Linked List where payload data are stored in.
	 */
	linked_list_t *payloads;
	
	 /**
	  * Assigned parser to parse Header and Body of this message.
	  */
	parser_t *parser;
	
	/**
	 * The message rule for this message instance
	 */
	message_rule_t *message_rule;
};

/**
 * Implementation of private_message_t.set_message_rule.
 */
static  status_t set_message_rule(private_message_t *this)
{
	int i;
		
	for (i = 0; i < (sizeof(message_rules) / sizeof(message_rule_t)); i++)
	{
		if ((this->exchange_type == message_rules[i].exchange_type) &&
			(this->is_request == message_rules[i].is_request))
		{
			/* found rule for given exchange_type*/
			this->message_rule = &(message_rules[i]);
			return SUCCESS;
		}
	}
	this->message_rule = NULL;
	return NOT_FOUND;
}

/**
 * Implementation of private_message_t.get_payload_rule.
 */
static status_t get_payload_rule(private_message_t *this, payload_type_t payload_type, payload_rule_t **payload_rule)
{
	int i;
	
	for (i = 0; i < this->message_rule->payload_rule_count;i++)
	{
		if (this->message_rule->payload_rules[i].payload_type == payload_type)
		{
			*payload_rule = &(this->message_rule->payload_rules[i]);
			return SUCCESS;
		}
	}
	
	*payload_rule = NULL;
	return NOT_FOUND;
}

/**
 * Implementation of message_t.set_ike_sa_id.
 */
static void set_ike_sa_id (private_message_t *this,ike_sa_id_t *ike_sa_id)
{
	DESTROY_IF(this->ike_sa_id);
	this->ike_sa_id = ike_sa_id->clone(ike_sa_id);
}

/**
 * Implementation of message_t.get_ike_sa_id.
 */
static ike_sa_id_t* get_ike_sa_id (private_message_t *this)
{
	return this->ike_sa_id;
}

/**
 * Implementation of message_t.set_message_id.
 */
static void set_message_id (private_message_t *this,u_int32_t message_id)
{
	this->message_id = message_id;
}

/**
 * Implementation of message_t.get_message_id.
 */
static u_int32_t get_message_id (private_message_t *this)
{
	return this->message_id;
}

/**
 * Implementation of message_t.get_initiator_spi.
 */
static u_int64_t get_initiator_spi (private_message_t *this)
{
	return (this->ike_sa_id->get_initiator_spi(this->ike_sa_id));
}

/**
 * Implementation of message_t.get_responder_spi.
 */
static u_int64_t get_responder_spi (private_message_t *this)
{
	return (this->ike_sa_id->get_responder_spi(this->ike_sa_id));
}

/**
 * Implementation of message_t.set_major_version.
 */
static void set_major_version (private_message_t *this,u_int8_t major_version)
{
	this->major_version = major_version;
}


/**
 * Implementation of message_t.set_major_version.
 */
static u_int8_t get_major_version (private_message_t *this)
{
	return this->major_version;
}

/**
 * Implementation of message_t.set_minor_version.
 */
static void set_minor_version (private_message_t *this,u_int8_t minor_version)
{
	this->minor_version = minor_version;
}

/**
 * Implementation of message_t.get_minor_version.
 */
static u_int8_t get_minor_version (private_message_t *this)
{
	return this->minor_version;
}

/**
 * Implementation of message_t.set_exchange_type.
 */
static void set_exchange_type (private_message_t *this,exchange_type_t exchange_type)
{
	this->exchange_type = exchange_type;
}

/**
 * Implementation of message_t.get_exchange_type.
 */
static exchange_type_t get_exchange_type (private_message_t *this)
{
	return this->exchange_type;
}

/**
 * Implementation of message_t.set_request.
 */
static void set_request (private_message_t *this,bool request)
{
	this->is_request = request;
}

/**
 * Implementation of message_t.get_request.
 */
static exchange_type_t get_request (private_message_t *this)
{
	return this->is_request;
}

/**
 * Is this message in an encoded form?
 */
static bool is_encoded(private_message_t *this)
{
	chunk_t data = this->packet->get_data(this->packet);
	
	if (data.ptr == NULL)
	{
		return FALSE;
	}
	return TRUE;
}

/**
 * Implementation of message_t.add_payload.
 */
static void add_payload(private_message_t *this, payload_t *payload)
{
	payload_t *last_payload;
	if (this->payloads->get_count(this->payloads) > 0)
	{
		this->payloads->get_last(this->payloads,(void **) &last_payload);
		last_payload->set_next_type(last_payload, payload->get_type(payload));
	}
	else
	{
		this->first_payload = payload->get_type(payload);
	}
	payload->set_next_type(payload, NO_PAYLOAD);
	this->payloads->insert_last(this->payloads, (void*)payload);

	DBG2(DBG_ENC ,"added payload of type %N to message",
		 payload_type_names, payload->get_type(payload));
}

/**
 * Implementation of message_t.add_notify.
 */
static void add_notify(private_message_t *this, bool flush, notify_type_t type, 
					   chunk_t data)
{
	notify_payload_t *notify;
	payload_t *payload;
	
	if (flush)
	{
		while (this->payloads->remove_last(this->payloads, 
												(void**)&payload) == SUCCESS)
		{
			payload->destroy(payload);
		}
	}
	notify = notify_payload_create();
	notify->set_notify_type(notify, type);
	notify->set_notification_data(notify, data);
	add_payload(this, (payload_t*)notify);
}

/**
 * Implementation of message_t.set_source.
 */
static void set_source(private_message_t *this, host_t *host)
{
	this->packet->set_source(this->packet, host);
}

/**
 * Implementation of message_t.set_destination.
 */
static void set_destination(private_message_t *this, host_t *host)
{
	this->packet->set_destination(this->packet, host);
}

/**
 * Implementation of message_t.get_source.
 */
static host_t* get_source(private_message_t *this)
{
	return this->packet->get_source(this->packet);
}

/**
 * Implementation of message_t.get_destination.
 */
static host_t * get_destination(private_message_t *this)
{
	return this->packet->get_destination(this->packet);
}

/**
 * Implementation of message_t.get_payload_iterator.
 */
static iterator_t *get_payload_iterator(private_message_t *this)
{
	return this->payloads->create_iterator(this->payloads, TRUE);
}

/**
 * Implementation of message_t.get_payload.
 */
static payload_t *get_payload(private_message_t *this, payload_type_t type)
{
	payload_t *current, *found = NULL;
	iterator_t *iterator;
	
	iterator = this->payloads->create_iterator(this->payloads, TRUE);
	while (iterator->iterate(iterator, (void**)&current))
	{
		if (current->get_type(current) == type)
		{
			found = current;
			break;
		}
	}
	iterator->destroy(iterator);
	return found;
}

/**
 * output handler in printf()
 */
static int print(FILE *stream, const struct printf_info *info,
				 const void *const *args)
{
	private_message_t *this = *((private_message_t**)(args[0]));
	iterator_t *iterator;
	payload_t *payload;
	bool first = TRUE;
	size_t total_written = 0;
	size_t written;
	
	if (this == NULL)
	{
		return fprintf(stream, "(null)");
	}
	
	written = fprintf(stream, "%N %s [", 
					  exchange_type_names, this->exchange_type,
					  this->is_request ? "request" : "response");
	if (written < 0)
	{
		return written;
	}
	total_written += written;
	
	iterator = this->payloads->create_iterator(this->payloads, TRUE);
	while (iterator->iterate(iterator, (void**)&payload))
	{
		if (!first)
		{
			written = fprintf(stream, " ");
			if (written < 0)
			{
				return written;
			}
			total_written += written;
		}
		else
		{
			first = FALSE;
		}
		written = fprintf(stream, "%N", payload_type_short_names,
						  payload->get_type(payload));
		if (written < 0)
		{
			return written;
		}
		total_written += written;
	}
	iterator->destroy(iterator);
	written = fprintf(stream, "]");
	if (written < 0)
	{
		return written;
	}
	total_written += written;
	return total_written;
}

/**
 * register printf() handlers
 */
static void __attribute__ ((constructor))print_register()
{
	register_printf_function(PRINTF_MESSAGE, print, arginfo_ptr);
}

/**
 * Implementation of private_message_t.encrypt_payloads.
 */
static status_t encrypt_payloads (private_message_t *this,crypter_t *crypter, signer_t* signer)
{
	encryption_payload_t *encryption_payload = NULL;
	status_t status;
	linked_list_t *all_payloads;
	
	if (!this->message_rule->encrypted_content)
	{
		DBG2(DBG_ENC, "message doesn't have to be encrypted");
		/* message contains no content to encrypt */
		return SUCCESS;
	}
	
	DBG2(DBG_ENC, "copy all payloads to a temporary list");
	all_payloads = linked_list_create();
	
	/* first copy all payloads in a temporary list */
	while (this->payloads->get_count(this->payloads) > 0)
	{
		void *current_payload;
		this->payloads->remove_first(this->payloads,&current_payload);
		all_payloads->insert_last(all_payloads,current_payload);
	}
	
	encryption_payload = encryption_payload_create();

	DBG2(DBG_ENC, "check each payloads if they have to get encrypted");
	while (all_payloads->get_count(all_payloads) > 0)
	{
		payload_rule_t *payload_rule;
		payload_t *current_payload;
		bool to_encrypt = FALSE;
		
		all_payloads->remove_first(all_payloads,(void **)&current_payload);
		
		status = get_payload_rule(this,
					current_payload->get_type(current_payload),&payload_rule);
		/* for payload types which are not found in supported payload list, 
		 * it is presumed that they don't have to be encrypted */
		if ((status == SUCCESS) && (payload_rule->encrypted))
		{
			DBG2(DBG_ENC, "payload %N gets encrypted",
				 payload_type_names, current_payload->get_type(current_payload));
			to_encrypt = TRUE;
		}
		
		if (to_encrypt)
		{
			DBG2(DBG_ENC, "insert payload %N to encryption payload",
				 payload_type_names, current_payload->get_type(current_payload));
			encryption_payload->add_payload(encryption_payload,current_payload);
		}
		else
		{
			DBG2(DBG_ENC, "insert payload %N unencrypted",
				 payload_type_names ,current_payload->get_type(current_payload));
			add_payload(this, (payload_t*)encryption_payload);
		}
	}

	status = SUCCESS;
	DBG2(DBG_ENC, "encrypting encryption payload");
	encryption_payload->set_transforms(encryption_payload, crypter,signer);
	status = encryption_payload->encrypt(encryption_payload);
	DBG2(DBG_ENC, "add encrypted payload to payload list");
	add_payload(this, (payload_t*)encryption_payload);
	
	all_payloads->destroy(all_payloads);
	
	return status;
}

/**
 * Implementation of message_t.generate.
 */
static status_t generate(private_message_t *this, crypter_t *crypter, signer_t* signer, packet_t **packet)
{
	generator_t *generator;
	ike_header_t *ike_header;
	payload_t *payload, *next_payload;
	iterator_t *iterator;
	status_t status;
	chunk_t packet_data;
	
	if (is_encoded(this))
	{
		/* already generated, return a new packet clone */
		*packet = this->packet->clone(this->packet);
		return SUCCESS;
	}
	
	DBG1(DBG_ENC, "generating %M", this);
	
	if (this->exchange_type == EXCHANGE_TYPE_UNDEFINED)
	{
		DBG1(DBG_ENC, "exchange type is not defined");
		return INVALID_STATE;
	}
	
	if (this->packet->get_source(this->packet) == NULL ||
		this->packet->get_destination(this->packet) == NULL) 
	{
		DBG1(DBG_ENC, "%s not defined",
			 !this->packet->get_source(this->packet) ? "source" : "destination");
		return INVALID_STATE;
	}
	
	/* set the rules for this messge */
	status = set_message_rule(this);
	if (status != SUCCESS)
	{
		DBG1(DBG_ENC, "no message rules specified for this message type");
		return NOT_SUPPORTED;
	}
	
	/* going to encrypt all content which have to be encrypted */
	status = encrypt_payloads(this, crypter, signer);
	if (status != SUCCESS)
	{
		DBG1(DBG_ENC, "payload encryption failed");
		return status;
	}
	
	/* build ike header */
	ike_header = ike_header_create();
	
	ike_header->set_exchange_type(ike_header, this->exchange_type);
	ike_header->set_message_id(ike_header, this->message_id);
	ike_header->set_response_flag(ike_header, !this->is_request);
	ike_header->set_initiator_flag(ike_header, this->ike_sa_id->is_initiator(this->ike_sa_id));
	ike_header->set_initiator_spi(ike_header, this->ike_sa_id->get_initiator_spi(this->ike_sa_id));
	ike_header->set_responder_spi(ike_header, this->ike_sa_id->get_responder_spi(this->ike_sa_id));

	generator = generator_create();
	
	payload = (payload_t*)ike_header;

	
	/* generate every payload expect last one, this is doen later*/
	iterator = this->payloads->create_iterator(this->payloads, TRUE);
	while(iterator->iterate(iterator, (void**)&next_payload))
	{
		payload->set_next_type(payload, next_payload->get_type(next_payload));
		generator->generate_payload(generator, payload);
		payload = next_payload;
	}
	iterator->destroy(iterator);
	
	/* last payload has no next payload*/
	payload->set_next_type(payload, NO_PAYLOAD);

	generator->generate_payload(generator, payload);

	ike_header->destroy(ike_header);
		
	/* build packet */
	generator->write_to_chunk(generator, &packet_data);
	generator->destroy(generator);
	
	/* if last payload is of type encrypted, integrity checksum if necessary */
	if (payload->get_type(payload) == ENCRYPTED)
	{
		DBG2(DBG_ENC, "build signature on whole message");
		encryption_payload_t *encryption_payload = (encryption_payload_t*)payload;
		status = encryption_payload->build_signature(encryption_payload, packet_data);
		if (status != SUCCESS)
		{
			return status;
		}
	}
	
	this->packet->set_data(this->packet, packet_data);
	
	/* clone packet for caller */
	*packet = this->packet->clone(this->packet);
	
	DBG2(DBG_ENC, "message generated successfully");
	return SUCCESS;
}

/**
 * Implementation of message_t.get_packet.
 */
static packet_t *get_packet (private_message_t *this)
{
	if (this->packet == NULL)
	{
		return NULL;
	}
	return this->packet->clone(this->packet);
}

/**
 * Implementation of message_t.get_packet_data.
 */
static chunk_t get_packet_data (private_message_t *this)
{
	if (this->packet == NULL)
	{
		return chunk_empty;
	}
	return chunk_clone(this->packet->get_data(this->packet));
}

/**
 * Implementation of message_t.parse_header.
 */
static status_t parse_header(private_message_t *this)
{
	ike_header_t *ike_header;
	status_t status;
	
	DBG2(DBG_ENC, "parsing header of message");
	
	this->parser->reset_context(this->parser);
	status = this->parser->parse_payload(this->parser,HEADER,(payload_t **) &ike_header);
	if (status != SUCCESS)
	{
		DBG1(DBG_ENC, "header could not be parsed");
		return status;
		
	}
	
	/* verify payload */
	status = ike_header->payload_interface.verify(&(ike_header->payload_interface));
	if (status != SUCCESS)
	{
		DBG1(DBG_ENC, "header verification failed");
		ike_header->destroy(ike_header);
		return status;
	}
	
	if (this->ike_sa_id != NULL)
	{
		this->ike_sa_id->destroy(this->ike_sa_id);
	}
	
	this->ike_sa_id = ike_sa_id_create(ike_header->get_initiator_spi(ike_header),
									   ike_header->get_responder_spi(ike_header),
									   ike_header->get_initiator_flag(ike_header));

	this->exchange_type = ike_header->get_exchange_type(ike_header);
	this->message_id = ike_header->get_message_id(ike_header);
	this->is_request = (!(ike_header->get_response_flag(ike_header)));
	this->major_version = ike_header->get_maj_version(ike_header);
	this->minor_version = ike_header->get_min_version(ike_header);
	this->first_payload = ike_header->payload_interface.get_next_type(&(ike_header->payload_interface));
	
	DBG2(DBG_ENC, "parsed a %N %s", exchange_type_names, this->exchange_type,
		 this->is_request ? "request" : "response");
	
	ike_header->destroy(ike_header);
	
	/* get the rules for this messge */
	status = set_message_rule(this);
	if (status != SUCCESS)
	{
		DBG1(DBG_ENC, "no message rules specified for a %N %s",
			 exchange_type_names, this->exchange_type,
			 this->is_request ? "request" : "response");
	}
	
	return status;
}

/**
 * Implementation of private_message_t.decrypt_and_verify_payloads.
 */
static status_t decrypt_payloads(private_message_t *this,crypter_t *crypter, signer_t* signer)
{
	bool current_payload_was_encrypted = FALSE;
	payload_t *previous_payload = NULL;
	int payload_number = 1;
	iterator_t *iterator;
	payload_t *current_payload;
	status_t status;

	iterator = this->payloads->create_iterator(this->payloads,TRUE);

	/* process each payload and decrypt a encryption payload */
	while(iterator->iterate(iterator, (void**)&current_payload))
	{
		payload_rule_t *payload_rule;
		payload_type_t current_payload_type;
		
		/* needed to check */
		current_payload_type = current_payload->get_type(current_payload);
		
		DBG2(DBG_ENC, "process payload of type %N",
			 payload_type_names, current_payload_type);
		
		if (current_payload_type == ENCRYPTED)
		{
			encryption_payload_t *encryption_payload;
			payload_t *current_encrypted_payload;
			
			encryption_payload = (encryption_payload_t*)current_payload;
			
			DBG2(DBG_ENC, "found an encryption payload");

			if (payload_number != this->payloads->get_count(this->payloads))
			{
				/* encrypted payload is not last one */
				DBG1(DBG_ENC, "encrypted payload is not last payload");
				iterator->destroy(iterator);
				return VERIFY_ERROR;
			}
			/* decrypt */
			encryption_payload->set_transforms(encryption_payload, crypter, signer);
			DBG2(DBG_ENC, "verify signature of encryption payload");
			status = encryption_payload->verify_signature(encryption_payload,
										this->packet->get_data(this->packet));
			if (status != SUCCESS)
			{
				DBG1(DBG_ENC, "encryption payload signature invalid");
				iterator->destroy(iterator);
				return FAILED;
			}
			DBG2(DBG_ENC, "decrypting content of encryption payload");
			status = encryption_payload->decrypt(encryption_payload);
			if (status != SUCCESS)
			{
				DBG1(DBG_ENC, "encrypted payload could not be decrypted and parsed");
				iterator->destroy(iterator);
				return PARSE_ERROR;
			}
			
			/* needed later to find out if a payload was encrypted */
			current_payload_was_encrypted = TRUE;
			
			/* check if there are payloads contained in the encryption payload */
			if (encryption_payload->get_payload_count(encryption_payload) == 0)
			{
				DBG2(DBG_ENC, "encrypted payload is empty");
				/* remove the encryption payload, is not needed anymore */
				iterator->remove(iterator);
				/* encrypted payload contains no other payload */
				current_payload_type = NO_PAYLOAD;
			}
			else
			{
				/* encryption_payload is replaced with first payload contained in encryption_payload */
				encryption_payload->remove_first_payload(encryption_payload, &current_encrypted_payload);
				iterator->replace(iterator,NULL,(void *) current_encrypted_payload);
				current_payload_type = current_encrypted_payload->get_type(current_encrypted_payload);
			}
			
			/* is the current paylad the first in the message? */
			if (previous_payload == NULL)
			{
				/* yes, set the first payload type of the message to the current type */
				this->first_payload = current_payload_type;
			}
			else
			{
				/* no, set the next_type of the previous payload to the current type */
				previous_payload->set_next_type(previous_payload, current_payload_type);
			}
			
			/* all encrypted payloads are added to the payload list */
			while (encryption_payload->get_payload_count(encryption_payload) > 0)
			{
				encryption_payload->remove_first_payload(encryption_payload, &current_encrypted_payload);
				DBG2(DBG_ENC, "insert unencrypted payload of type %N at end of list",
					 payload_type_names, current_encrypted_payload->get_type(current_encrypted_payload));
				this->payloads->insert_last(this->payloads,current_encrypted_payload);
			}
			
			/* encryption payload is processed, payloads are moved. Destroy it. */
			encryption_payload->destroy(encryption_payload);	
		}

		/* we allow unknown payloads of any type and don't bother if it was encrypted. Not our problem. */
		if (current_payload_type != UNKNOWN_PAYLOAD && current_payload_type != NO_PAYLOAD)
		{
			/* get the ruleset for found payload */
			status = get_payload_rule(this, current_payload_type, &payload_rule);
			if (status != SUCCESS)
			{
				/* payload is not allowed */
				DBG1(DBG_ENC, "payload type %N not allowed",
								  payload_type_names, current_payload_type);
				iterator->destroy(iterator);
				return VERIFY_ERROR;
			}
			
			/* check if the payload was encrypted, and if it should been have encrypted */
			if (payload_rule->encrypted != current_payload_was_encrypted)
			{
				/* payload was not encrypted, but should have been. or vice-versa */
				DBG1(DBG_ENC, "payload type %N should be %s!",
					 payload_type_names, current_payload_type,
					 (payload_rule->encrypted) ? "encrypted" : "not encrypted");
				iterator->destroy(iterator);
				return VERIFY_ERROR;
			}
		}
		/* advance to the next payload */
		payload_number++;
		/* is stored to set next payload in case of found encryption payload */
		previous_payload = current_payload;
	}
	iterator->destroy(iterator);
	return SUCCESS;
}

/**
 * Implementation of private_message_t.verify.
 */
static status_t verify(private_message_t *this)
{
	int i;
	iterator_t *iterator;
	payload_t *current_payload;
	size_t total_found_payloads = 0;
	
	DBG2(DBG_ENC, "verifying message structure");
	
	iterator = this->payloads->create_iterator(this->payloads,TRUE);
	/* check for payloads with wrong count*/
	for (i = 0; i < this->message_rule->payload_rule_count;i++)
	{
		size_t found_payloads = 0;
	
		/* check all payloads for specific rule */
		iterator->reset(iterator);
		
		while(iterator->iterate(iterator,(void **)&current_payload))
		{
			payload_type_t current_payload_type;
			
			current_payload_type = current_payload->get_type(current_payload);
			if (current_payload_type == UNKNOWN_PAYLOAD)
			{
				/* unknown payloads are ignored, IF they are not critical */
				unknown_payload_t *unknown_payload = (unknown_payload_t*)current_payload;
				if (unknown_payload->is_critical(unknown_payload))
				{
					DBG1(DBG_ENC, "%N is not supported, but its critical!",
						 payload_type_names, current_payload_type);
					iterator->destroy(iterator);
					return NOT_SUPPORTED;	
				}
			}
			else if (current_payload_type == this->message_rule->payload_rules[i].payload_type)
			{
				found_payloads++;
				total_found_payloads++;
				DBG2(DBG_ENC, "found payload of type %N",
					 payload_type_names, this->message_rule->payload_rules[i].payload_type);
				
				/* as soon as ohe payload occures more then specified, the verification fails */
				if (found_payloads > this->message_rule->payload_rules[i].max_occurence)
				{
					DBG1(DBG_ENC, "payload of type %N more than %d times (%d) occured in current message",
						 payload_type_names, current_payload_type,
						 this->message_rule->payload_rules[i].max_occurence, found_payloads);
					iterator->destroy(iterator);
					return VERIFY_ERROR;
				}
			}
		}
		
		if (found_payloads < this->message_rule->payload_rules[i].min_occurence)
		{
			DBG1(DBG_ENC, "payload of type %N not occured %d times (%d)",
				 payload_type_names, this->message_rule->payload_rules[i].payload_type,
				 this->message_rule->payload_rules[i].min_occurence, found_payloads);
			iterator->destroy(iterator);
			return VERIFY_ERROR;
		}
		if ((this->message_rule->payload_rules[i].sufficient) && (this->payloads->get_count(this->payloads) == total_found_payloads))
		{
			iterator->destroy(iterator);
			return SUCCESS;	
		}
	}
	iterator->destroy(iterator);
	return SUCCESS;
}

/**
 * Implementation of message_t.parse_body.
 */
static status_t parse_body(private_message_t *this, crypter_t *crypter, signer_t *signer)
{
	status_t status = SUCCESS;
	payload_type_t current_payload_type;
		
	current_payload_type = this->first_payload;	
		
	DBG2(DBG_ENC, "parsing body of message, first payload is %N",
		 payload_type_names, current_payload_type);

	/* parse payload for payload, while there are more available */
	while ((current_payload_type != NO_PAYLOAD))
	{
		payload_t *current_payload;
		
		DBG2(DBG_ENC, "starting parsing a %N payload", 
			 payload_type_names, current_payload_type);
		
		/* parse current payload */
		status = this->parser->parse_payload(this->parser,current_payload_type,(payload_t **) &current_payload);
		
		if (status != SUCCESS)
		{
			DBG1(DBG_ENC, "payload type %N could not be parsed",
				 payload_type_names, current_payload_type);
			return PARSE_ERROR;
		}

		DBG2(DBG_ENC, "verifying payload of type %N",
			 payload_type_names, current_payload_type);
		
		/* verify it, stop parsig if its invalid */
		status = current_payload->verify(current_payload);
		if (status != SUCCESS)
		{
			DBG1(DBG_ENC, "%N payload verification failed",
				 payload_type_names, current_payload_type);
			current_payload->destroy(current_payload);
			return VERIFY_ERROR;
		}
		
		DBG2(DBG_ENC, "%N payload verified. Adding to payload list",
			 payload_type_names, current_payload_type);
		this->payloads->insert_last(this->payloads,current_payload);
		
		/* an encryption payload is the last one, so STOP here. decryption is done later */
		if (current_payload_type == ENCRYPTED)
		{
			DBG2(DBG_ENC, "%N payload found. Stop parsing",
				 payload_type_names, current_payload_type);
			break;
		}
		
		/* get next payload type */
		current_payload_type = current_payload->get_next_type(current_payload);
	}

	if (current_payload_type == ENCRYPTED)
	{
		status = decrypt_payloads(this,crypter,signer);
		if (status != SUCCESS)
		{
			DBG1(DBG_ENC, "could not decrypt payloads");
			return status;
		}
	}
	
	status = verify(this);
	if (status != SUCCESS)
	{
		return status;
	}
	
	DBG1(DBG_ENC, "parsed %M", this);
	
	return SUCCESS;
}

/**
 * Implementation of message_t.destroy.
 */
static void destroy (private_message_t *this)
{
	DESTROY_IF(this->ike_sa_id);
	this->payloads->destroy_offset(this->payloads, offsetof(payload_t, destroy));
	this->packet->destroy(this->packet);
	this->parser->destroy(this->parser);
	free(this);
}

/*
 * Described in Header-File
 */
message_t *message_create_from_packet(packet_t *packet)
{
	private_message_t *this = malloc_thing(private_message_t);

	/* public functions */
	this->public.set_major_version = (void(*)(message_t*, u_int8_t))set_major_version;
	this->public.get_major_version = (u_int8_t(*)(message_t*))get_major_version;
	this->public.set_minor_version = (void(*)(message_t*, u_int8_t))set_minor_version;
	this->public.get_minor_version = (u_int8_t(*)(message_t*))get_minor_version;
	this->public.set_message_id = (void(*)(message_t*, u_int32_t))set_message_id;
	this->public.get_message_id = (u_int32_t(*)(message_t*))get_message_id;
	this->public.get_initiator_spi = (u_int64_t(*)(message_t*))get_initiator_spi;
	this->public.get_responder_spi = (u_int64_t(*)(message_t*))get_responder_spi;
	this->public.set_ike_sa_id = (void(*)(message_t*, ike_sa_id_t *))set_ike_sa_id;
	this->public.get_ike_sa_id = (ike_sa_id_t*(*)(message_t*))get_ike_sa_id;
	this->public.set_exchange_type = (void(*)(message_t*, exchange_type_t))set_exchange_type;
	this->public.get_exchange_type = (exchange_type_t(*)(message_t*))get_exchange_type;
	this->public.set_request = (void(*)(message_t*, bool))set_request;
	this->public.get_request = (bool(*)(message_t*))get_request;
	this->public.add_payload = (void(*)(message_t*,payload_t*))add_payload;
	this->public.add_notify = (void(*)(message_t*,bool,notify_type_t,chunk_t))add_notify;
	this->public.generate = (status_t (*) (message_t *,crypter_t*,signer_t*,packet_t**)) generate;
	this->public.set_source = (void (*) (message_t*,host_t*)) set_source;
	this->public.get_source = (host_t * (*) (message_t*)) get_source;
	this->public.set_destination = (void (*) (message_t*,host_t*)) set_destination;
	this->public.get_destination = (host_t * (*) (message_t*)) get_destination;
	this->public.get_payload_iterator = (iterator_t * (*) (message_t *)) get_payload_iterator;
	this->public.get_payload = (payload_t * (*) (message_t *, payload_type_t)) get_payload;
	this->public.parse_header = (status_t (*) (message_t *)) parse_header;
	this->public.parse_body = (status_t (*) (message_t *,crypter_t*,signer_t*)) parse_body;
	this->public.get_packet = (packet_t * (*) (message_t*)) get_packet;
	this->public.get_packet_data = (chunk_t (*) (message_t *this)) get_packet_data;
	this->public.destroy = (void(*)(message_t*))destroy;
		
	/* private values */
	this->exchange_type = EXCHANGE_TYPE_UNDEFINED;
	this->is_request = TRUE;
	this->ike_sa_id = NULL;
	this->first_payload = NO_PAYLOAD;
	this->message_id = 0;
	
	/* private values */
	if (packet == NULL)
	{
		packet = packet_create();	
	}
	this->message_rule = NULL;
	this->packet = packet;
	this->payloads = linked_list_create();
	
	/* parser is created from data of packet */
	this->parser = parser_create(this->packet->get_data(this->packet));
	
	return (&this->public);
}

/*
 * Described in Header.
 */
message_t *message_create()
{
	return message_create_from_packet(NULL);
}
