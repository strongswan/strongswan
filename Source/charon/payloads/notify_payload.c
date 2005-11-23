/**
 * @file notify_payload.c
 * 
 * @brief Declaration of the class notify_payload_t. 
 * 
 * An object of this type represents an IKEv2 Notify-Payload.
 * 
 * See section 3.10 of Draft for details of this payload type.
 * 
 */

/*
 * Copyright (C) 2005 Jan Hutter, Martin Willi
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
 
/* offsetof macro */
#include <stddef.h>

#include "notify_payload.h"

#include <payloads/encodings.h>
#include <utils/allocator.h>

/**
 * Private data of an notify_payload_t Object
 * 
 */
typedef struct private_notify_payload_s private_notify_payload_t;

struct private_notify_payload_s {
	/**
	 * public notify_payload_t interface
	 */
	notify_payload_t public;
	
	/**
	 * next payload type
	 */
	u_int8_t  next_payload;

	/**
	 * Critical flag
	 */
	bool critical;
		
	/**
	 * Length of this payload
	 */
	u_int16_t payload_length;
		
	/**
	 * protocol id
	 */
	u_int8_t protocol_id;
	
	/**
	 * spi size
	 */
	u_int8_t spi_size;
	
	/**
	 * notify message type
	 */
	u_int16_t notify_message_type;
	
	/**
	 * Security parameter index (spi)
	 */
	chunk_t spi;

	/**
	 * Notification data
	 */
	chunk_t notification_data;
	
	/**
	 * @brief Computes the length of this payload.
	 *
	 * @param this 	calling private_ke_payload_t object
	 * @return 		
	 * 				SUCCESS in any case
	 */
	status_t (*compute_length) (private_notify_payload_t *this);
};

/**
 * Encoding rules to parse or generate a IKEv2-Notify Payload
 * 
 * The defined offsets are the positions in a object of type 
 * private_notify_payload_t.
 * 
 */
encoding_rule_t notify_payload_encodings[] = {
 	/* 1 Byte next payload type, stored in the field next_payload */
	{ U_INT_8,			offsetof(private_notify_payload_t, next_payload) 		},
	/* the critical bit */
	{ FLAG,				offsetof(private_notify_payload_t, critical) 			},	
 	/* 7 Bit reserved bits, nowhere stored */
	{ RESERVED_BIT,	0 														}, 
	{ RESERVED_BIT,	0 														}, 
	{ RESERVED_BIT,	0 														}, 
	{ RESERVED_BIT,	0 														}, 
	{ RESERVED_BIT,	0 														}, 
	{ RESERVED_BIT,	0 														}, 
	{ RESERVED_BIT,	0 														}, 
	/* Length of the whole payload*/
	{ PAYLOAD_LENGTH,	offsetof(private_notify_payload_t, payload_length) 		},	
	/* Protocol ID as 8 bit field*/
	{ U_INT_8,			offsetof(private_notify_payload_t, protocol_id) 			},
	/* SPI Size as 8 bit field*/
	{ SPI_SIZE,			offsetof(private_notify_payload_t, spi_size) 			},
	/* Notify message type as 16 bit field*/
	{ U_INT_16,			offsetof(private_notify_payload_t, notify_message_type)	},
	/* SPI as variable length field*/
	{ SPI,				offsetof(private_notify_payload_t, spi)		 			},
	/* Key Exchange Data is from variable size */
	{ NOTIFICATION_DATA,	offsetof(private_notify_payload_t, notification_data) 	}
};

/*
                           1                   2                   3
       0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
      ! Next Payload  !C!  RESERVED   !         Payload Length        !
      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
      !  Protocol ID  !   SPI Size    !      Notify Message Type      !
      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
      !                                                               !
      ~                Security Parameter Index (SPI)                 ~
      !                                                               !
      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
      !                                                               !
      ~                       Notification Data                       ~
      !                                                               !
      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
*/

/**
 * Implements payload_t's verify function.
 * See #payload_s.verify for description.
 */
static status_t verify(private_notify_payload_t *this)
{
	if (this->critical)
	{
		/* critical bit is set! */
		return FAILED;
	}
	if (this->protocol_id > 3)
	{
		/* reserved for future use */
		return FAILED;
	}
	
	/* notify message types and data is not getting checked in here */
	
	return SUCCESS;
}

/**
 * Implements payload_t's get_encoding_rules function.
 * See #payload_s.get_encoding_rules for description.
 */
static status_t get_encoding_rules(private_notify_payload_t *this, encoding_rule_t **rules, size_t *rule_count)
{
	*rules = notify_payload_encodings;
	*rule_count = sizeof(notify_payload_encodings) / sizeof(encoding_rule_t);
	return SUCCESS;
}

/**
 * Implements payload_t's get_type function.
 * See #payload_s.get_type for description.
 */
static payload_type_t get_type(private_notify_payload_t *this)
{
	return KEY_EXCHANGE;
}

/**
 * Implements payload_t's get_next_type function.
 * See #payload_s.get_next_type for description.
 */
static payload_type_t get_next_type(private_notify_payload_t *this)
{
	return (this->next_payload);
}

/**
 * Implements payload_t's set_next_type function.
 * See #payload_s.set_next_type for description.
 */
static status_t set_next_type(private_notify_payload_t *this,payload_type_t type)
{
	this->next_payload = type;
	return SUCCESS;
}

/**
 * Implements payload_t's get_length function.
 * See #payload_s.get_length for description.
 */
static size_t get_length(private_notify_payload_t *this)
{
	this->compute_length(this);
	return this->payload_length;
}

/**
 * Implements private_ke_payload_t's compute_length function.
 * See #private_ke_payload_s.compute_length for description.
 */
static status_t compute_length (private_notify_payload_t *this)
{
	size_t length = NOTIFY_PAYLOAD_HEADER_LENGTH;
	if (this->notification_data.ptr != NULL)
	{
		length += this->notification_data.len;
	}
	if (this->spi.ptr != NULL)
	{
		length += this->spi.len;
	}
	
	this->payload_length = length;
		
	return SUCCESS;
}


/**
 * Implements notify_payload_t's get_protocol_id function.
 * See #notify_payload_s.get_protocol_id for description.
 */
u_int8_t get_protocol_id(private_notify_payload_t *this)
{
	return this->protocol_id;
}

/**
 * Implements notify_payload_t's set_protocol_id function.
 * See #notify_payload_s.set_protocol_id for description.
 */
status_t set_protocol_id(private_notify_payload_t *this, u_int8_t protocol_id)
{
	this->protocol_id = protocol_id;
	return SUCCESS;
}

/**
 * Implements notify_payload_t's get_notification_data function.
 * See #notify_payload_s.get_notification_data for description.
 */
u_int16_t get_notify_message_type(private_notify_payload_t *this)
{
	return this->notify_message_type;
}

/**
 * Implements notify_payload_t's get_notification_data function.
 * See #notify_payload_s.get_notification_data for description.
 */
status_t set_notify_message_type(private_notify_payload_t *this, u_int16_t notify_message_type)
{
	this->notify_message_type = notify_message_type;
	return SUCCESS;
}

/**
 * Implements notify_payload_t's get_spi function.
 * See #notify_payload_s.get_spi for description.
 */
chunk_t get_spi(private_notify_payload_t *this)
{
	return (this->spi);
}

/**
 * Implements notify_payload_t's set_spi function.
 * See #notify_payload_s.set_spi for description.
 */
status_t set_spi(private_notify_payload_t *this, chunk_t spi)
{
	/* destroy existing data first */
	if (this->spi.ptr != NULL)
	{
		/* free existing value */
		allocator_free(this->spi.ptr);
		this->spi.ptr = NULL;
		this->spi.len = 0;
		
	}
	
	this->spi.ptr = allocator_clone_bytes(spi.ptr,spi.len);
	if (this->spi.ptr == NULL)
	{
		return OUT_OF_RES;
	}
	this->spi.len = spi.len;
	this->spi_size = spi.len;
	this->compute_length(this);
	
	return SUCCESS;
}


/**
 * Implements notify_payload_t's get_notification_data function.
 * See #notify_payload_s.get_notification_data for description.
 */
chunk_t get_notification_data(private_notify_payload_t *this)
{
	return (this->notification_data);
}

/**
 * Implements notify_payload_t's get_notification_data function.
 * See #notify_payload_s.get_notification_data for description.
 */
status_t set_notification_data(private_notify_payload_t *this, chunk_t notification_data)
{
	/* destroy existing data first */
	if (this->notification_data.ptr != NULL)
	{
		/* free existing value */
		allocator_free(this->notification_data.ptr);
		this->notification_data.ptr = NULL;
		this->notification_data.len = 0;
		
	}
	
	this->notification_data.ptr = allocator_clone_bytes(notification_data.ptr,notification_data.len);
	if (this->notification_data.ptr == NULL)
	{
		return OUT_OF_RES;
	}
	this->notification_data.len = notification_data.len;
	this->compute_length(this);
	
	return SUCCESS;
}

/**
 * Implements payload_t's and notify_payload_t's destroy function.
 * See #payload_s.destroy or notify_payload_s.destroy for description.
 */
static status_t destroy(private_notify_payload_t *this)
{
	if (this->notification_data.ptr != NULL)
	{
		allocator_free(this->notification_data.ptr);
	}
	if (this->spi.ptr != NULL)
	{
		allocator_free(this->spi.ptr);
	}

	allocator_free(this);
	return SUCCESS;
}

/*
 * Described in header
 */
notify_payload_t *notify_payload_create()
{
	private_notify_payload_t *this = allocator_alloc_thing(private_notify_payload_t);
	if (this == NULL)
	{
		return NULL;	
	}	
	/* interface functions */
	this->public.payload_interface.verify = (status_t (*) (payload_t *))verify;
	this->public.payload_interface.get_encoding_rules = (status_t (*) (payload_t *, encoding_rule_t **, size_t *) ) get_encoding_rules;
	this->public.payload_interface.get_length = (size_t (*) (payload_t *)) get_length;
	this->public.payload_interface.get_next_type = (payload_type_t (*) (payload_t *)) get_next_type;
	this->public.payload_interface.set_next_type = (status_t (*) (payload_t *,payload_type_t)) set_next_type;
	this->public.payload_interface.get_type = (payload_type_t (*) (payload_t *)) get_type;
	this->public.payload_interface.destroy = (status_t (*) (payload_t *))destroy;

	/* public functions */
	this->public.get_protocol_id = (u_int8_t (*) (notify_payload_t *)) get_protocol_id;
	this->public.set_protocol_id  = (status_t (*) (notify_payload_t *,u_int8_t)) set_protocol_id;
	this->public.get_notify_message_type = (u_int16_t (*) (notify_payload_t *)) get_notify_message_type;
	this->public.set_notify_message_type = (status_t (*) (notify_payload_t *,u_int16_t)) set_notify_message_type;
	this->public.get_spi = (chunk_t (*) (notify_payload_t *)) get_spi;
	this->public.set_spi = (status_t (*) (notify_payload_t *,chunk_t)) set_spi;
	this->public.get_notification_data = (chunk_t (*) (notify_payload_t *)) get_notification_data;
	this->public.set_notification_data = (status_t (*) (notify_payload_t *,chunk_t)) set_notification_data;
	this->public.destroy = (status_t (*) (notify_payload_t *)) destroy;
	
	/* private functions */
	this->compute_length = compute_length;
	
	/* set default values of the fields */
	this->critical = NOTIFY_PAYLOAD_CRITICAL_FLAG;
	this->next_payload = NO_PAYLOAD;
	this->payload_length = NOTIFY_PAYLOAD_HEADER_LENGTH;
	this->protocol_id = 0;
	this->notify_message_type = 0;
	this->spi.ptr = NULL;
	this->spi.len = 0;
	this->notification_data.ptr = NULL;
	this->notification_data.len = 0;

	return (&(this->public));
}

