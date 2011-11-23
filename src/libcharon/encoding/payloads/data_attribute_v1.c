
#include <stddef.h>

#include "data_attribute_v1.h"

#include <encoding/payloads/encodings.h>
#include <library.h>
#include <daemon.h>

typedef struct private_data_attribute_v1_t private_data_attribute_v1_t;

/**
 * Private data of an data_attribute_v1_t object.
 */
struct private_data_attribute_v1_t {

	/**
	 * Public data_attribute_v1_t interface.
	 */
	data_attribute_v1_t public;

	/**
	 * Reserved bit
	 */
	bool af_flag;

	/**
	 * Type of the attribute.
	 */
	u_int16_t type;

	/**
	 * Length of the attribute.
	 */
	u_int16_t length_or_value;

	/**
	 * Attribute value as chunk.
	 */
	chunk_t value;
};

/**
 * Encoding rules to parse or generate a configuration attribute.
 *
 * The defined offsets are the positions in a object of type
 * private_data_attribute_v1_t.
 */
encoding_rule_t data_attribute_v1_encodings[] = {
	/* AF Flag */
	{ FLAG,						offsetof(private_data_attribute_v1_t, af_flag)},
	/* type of the attribute as 15 bit unsigned integer */
	{ ATTRIBUTE_TYPE,					offsetof(private_data_attribute_v1_t, type)	},
	/* Length of attribute value */
	{ ATTRIBUTE_LENGTH_OR_VALUE,	offsetof(private_data_attribute_v1_t, length_or_value)	},
	/* Value of attribute if attribute format flag is zero */
	{ ATTRIBUTE_VALUE,	offsetof(private_data_attribute_v1_t, value)	}
};

/*
                           1                   2                   3
       0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
      !R|         Attribute Type      !            Length             |
      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
      |                                                               |
      ~                             Value                             ~
      |                                                               |
      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
*/

METHOD(payload_t, verify, status_t,
	private_data_attribute_v1_t *this)
{
	bool failed = FALSE;

	if (this->length_or_value != this->value.len)
	{
		DBG1(DBG_ENC, "invalid attribute length");
		return FAILED;
	}

	switch (this->type)
	{
		 case INTERNAL_IP4_ADDRESS:
		 case INTERNAL_IP4_NETMASK:
		 case INTERNAL_IP4_DNS:
		 case INTERNAL_IP4_NBNS:
		 case INTERNAL_ADDRESS_EXPIRY:
		 case INTERNAL_IP4_DHCP:
			if (this->length_or_value != 0 && this->length_or_value != 4)
			{
				failed = TRUE;
			}
			break;
		 case INTERNAL_IP4_SUBNET:
			if (this->length_or_value != 0 && this->length_or_value != 8)
			{
				failed = TRUE;
			}
			break;
		 case INTERNAL_IP6_ADDRESS:
		 case INTERNAL_IP6_SUBNET:
			if (this->length_or_value != 0 && this->length_or_value != 17)
			{
				failed = TRUE;
			}
			break;
		 case INTERNAL_IP6_DNS:
		 case INTERNAL_IP6_NBNS:
		 case INTERNAL_IP6_DHCP:
			if (this->length_or_value != 0 && this->length_or_value != 16)
			{
				failed = TRUE;
			}
			break;
		 case SUPPORTED_ATTRIBUTES:
			if (this->length_or_value % 2)
			{
				failed = TRUE;
			}
			break;
		 case APPLICATION_VERSION:
			/* any length acceptable */
			break;
		 default:
			DBG1(DBG_ENC, "unknown attribute type %N",
				 configuration_attribute_type_names, this->type);
			break;
	}

	if (failed)
	{
		DBG1(DBG_ENC, "invalid attribute length %d for %N",
			 this->length_or_value, configuration_attribute_type_names, this->type);
		return FAILED;
	}
	return SUCCESS;
}

METHOD(payload_t, get_encoding_rules, void,
	private_data_attribute_v1_t *this, encoding_rule_t **rules,
	size_t *rule_count)
{
	*rules = data_attribute_v1_encodings;
	*rule_count = countof(data_attribute_v1_encodings);
}

METHOD(payload_t, get_header_length, int,
	private_data_attribute_v1_t *this)
{
	return 4;
}

METHOD(payload_t, get_type, payload_type_t,
	private_data_attribute_v1_t *this)
{
	return DATA_ATTRIBUTE_V1;
}

METHOD(payload_t, get_next_type, payload_type_t,
	private_data_attribute_v1_t *this)
{
	return NO_PAYLOAD;
}

METHOD(payload_t, set_next_type, void,
	private_data_attribute_v1_t *this, payload_type_t type)
{
}

METHOD(payload_t, get_length, size_t,
	private_data_attribute_v1_t *this)
{
	return get_header_length(this) + this->value.len;
}

METHOD(data_attribute_v1_t, get_dattr_type, configuration_attribute_type_t,
	private_data_attribute_v1_t *this)
{
	return this->type;
}

METHOD(data_attribute_v1_t, get_value, u_int16_t,
	private_data_attribute_v1_t *this)
{
	return this->length_or_value;
}

METHOD(data_attribute_v1_t, get_value_chunk, chunk_t,
	private_data_attribute_v1_t *this)
{
	return this->value;
}

METHOD2(payload_t, data_attribute_v1_t, destroy, void,
	private_data_attribute_v1_t *this)
{
	free(this->value.ptr);
	free(this);
}

/*
 * Described in header.
 */
data_attribute_v1_t *data_attribute_v1_create()
{
	private_data_attribute_v1_t *this;

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
			.get_value_chunk = _get_value_chunk,
			.get_type = _get_dattr_type,
			.destroy = _destroy,
		},
	);
	return &this->public;
}

/*
 * Described in header.
 */
data_attribute_v1_t *data_attribute_v1_create_value(
							configuration_attribute_type_t type, chunk_t value)
{
	private_data_attribute_v1_t *this;

	this = (private_data_attribute_v1_t*)data_attribute_v1_create();
	this->type = ((u_int16_t)type) & 0x7FFF;
	this->value = chunk_clone(value);
	this->length_or_value = value.len;
	this->af_flag = FALSE;

	return &this->public;
}

/*
 * Described in header.
 */
data_attribute_v1_t *data_attribute_v1_create_basic(
							configuration_attribute_type_t type, u_int16_t value)
{
	private_data_attribute_v1_t *this;

	this = (private_data_attribute_v1_t*)data_attribute_v1_create();
	this->type = ((u_int16_t)type) & 0x7FFF;
	this->length_or_value = value;
	this->af_flag = TRUE;

	return &this->public;
}
