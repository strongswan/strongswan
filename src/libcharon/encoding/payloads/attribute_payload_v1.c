
#include <stddef.h>

#include "attribute_payload_v1.h"

#include <encoding/payloads/encodings.h>
#include <utils/linked_list.h>

ENUM(config_type_v1_names, ISAKMP_CFG_REQUEST, ISAKMP_CFG_ACK,
	"ISAKMP_CFG_REQUEST",
	"ISAKMP_CFG_REPLY",
	"ISAKMP_CFG_SET",
	"ISAKMP_CFG_ACK",
);

typedef struct private_attribute_payload_v1_t private_attribute_payload_v1_t;

/**
 * Private data of an attribute_payload_v1_t object.
 */
struct private_attribute_payload_v1_t {

	/**
	 * Public cp_payload_t interface.
	 */
	attribute_payload_v1_t public;

	/**
	 * Next payload type.
	 */
	u_int8_t  next_payload;

	/**
	 * Length of this payload.
	 */
	u_int16_t payload_length;

	/**
	 * List of attributes, as configuration_attribute_t
	 */
	linked_list_t *attributes;

	/**
	 * Reserved bytes
	 */
	u_int8_t reserved_byte[2];

	/**
	 * Identifier
	 */
	u_int16_t identifier;

	/**
	 * Config Type.
	 */
	u_int8_t type;
};

/**
 * Encoding rules to parse or generate a IKEv2-CP Payload
 *
 * The defined offsets are the positions in a object of type
 * private_attribute_payload_v1_t.
 */
encoding_rule_t attribute_payload_v1_encodings[] = {
	/* 1 Byte next payload type, stored in the field next_payload */
	{ U_INT_8,					offsetof(private_attribute_payload_v1_t, next_payload)	},
	/* reserved byte */
	{ RESERVED_BYTE,				offsetof(private_attribute_payload_v1_t, reserved_byte[0])	},
	/* Length of the whole Attribute payload*/
	{ PAYLOAD_LENGTH,			offsetof(private_attribute_payload_v1_t, payload_length)	},
	/* Config type */
	{ U_INT_8,					offsetof(private_attribute_payload_v1_t, type)			},
	/* 3 reserved bytes */
	{ RESERVED_BYTE,			offsetof(private_attribute_payload_v1_t, reserved_byte[1])},

	/* Identifier */
	{ U_INT_16,				offsetof(private_attribute_payload_v1_t, identifier)},

	/* List of configuration attributes */
	{ PAYLOAD_LIST + CONFIGURATION_ATTRIBUTE,	offsetof(private_attribute_payload_v1_t, attributes)		}
};

/*
                           1                   2                   3
       0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
      ! Next Payload  !   RESERVED    !         Payload Length        !
      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
      !   CFG Type    !   RESERVED    !           Identifier          !
      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
      !                                                               !
      ~                   Configuration Attributes                    ~
      !                                                               !
      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
*/

METHOD(payload_t, verify, status_t,
	private_attribute_payload_v1_t *this)
{
	status_t status = SUCCESS;
	enumerator_t *enumerator;
	payload_t *attribute;

	enumerator = this->attributes->create_enumerator(this->attributes);
	while (enumerator->enumerate(enumerator, &attribute))
	{
		status = attribute->verify(attribute);
		if (status != SUCCESS)
		{
			break;
		}
	}
	enumerator->destroy(enumerator);
	return status;
}

METHOD(payload_t, get_encoding_rules, void,
	private_attribute_payload_v1_t *this, encoding_rule_t **rules, size_t *rule_count)
{
	*rules = attribute_payload_v1_encodings;
	*rule_count = countof(attribute_payload_v1_encodings);
}

METHOD(payload_t, get_type, payload_type_t,
	private_attribute_payload_v1_t *this)
{
	return ATTRIBUTE_V1;
}

METHOD(payload_t, get_next_type, payload_type_t,
	private_attribute_payload_v1_t *this)
{
	return this->next_payload;
}

METHOD(payload_t, set_next_type, void,
	private_attribute_payload_v1_t *this,payload_type_t type)
{
	this->next_payload = type;
}

/**
 * recompute the length of the payload.
 */
static void compute_length(private_attribute_payload_v1_t *this)
{
	enumerator_t *enumerator;
	payload_t *attribute;

	this->payload_length = ATTRIBUTE_PAYLOAD_V1_HEADER_LENGTH;

	enumerator = this->attributes->create_enumerator(this->attributes);
	while (enumerator->enumerate(enumerator, &attribute))
	{
		this->payload_length += attribute->get_length(attribute);
	}
	enumerator->destroy(enumerator);
}

METHOD(payload_t, get_length, size_t,
	private_attribute_payload_v1_t *this)
{
	return this->payload_length;
}

METHOD(attribute_payload_v1_t, create_attribute_enumerator, enumerator_t*,
	private_attribute_payload_v1_t *this)
{
	return this->attributes->create_enumerator(this->attributes);
}

METHOD(attribute_payload_v1_t, add_attribute, void,
	private_attribute_payload_v1_t *this, data_attribute_v1_t *attribute)
{
	this->attributes->insert_last(this->attributes, attribute);
	compute_length(this);
}

METHOD(attribute_payload_v1_t, get_config_type, config_type_v1_t,
	private_attribute_payload_v1_t *this)
{
	return this->type;
}

METHOD2(payload_t, attribute_payload_v1_t, destroy, void,
	private_attribute_payload_v1_t *this)
{
	this->attributes->destroy_offset(this->attributes,
								offsetof(data_attribute_v1_t, destroy));
	free(this);
}

/*
 * Described in header.
 */
attribute_payload_v1_t *attribute_payload_v1_create_type(config_type_v1_t type)
{
	private_attribute_payload_v1_t *this;

	INIT(this,
		.public = {
			.payload_interface = {
				.verify = _verify,
				.get_encoding_rules = _get_encoding_rules,
				.get_length = _get_length,
				.get_next_type = _get_next_type,
				.set_next_type = _set_next_type,
				.get_type = _get_type,
				.destroy = _destroy,
			},
			.create_attribute_enumerator = _create_attribute_enumerator,
			.add_attribute = _add_attribute,
			.get_type = _get_config_type,
			.destroy = _destroy,
		},
		.next_payload = NO_PAYLOAD,
		.payload_length = ATTRIBUTE_PAYLOAD_V1_HEADER_LENGTH,
		.attributes = linked_list_create(),
		.type = type,
	);
	return &this->public;
}

/*
 * Described in header.
 */
attribute_payload_v1_t *attribute_payload_v1_create()
{
	return attribute_payload_v1_create_type(ISAKMP_CFG_REQUEST);
}
