
/**
 * @defgroup attribute_payload_v1 attribute_payload_v1
 * @{ @ingroup payloads
 */

#ifndef ATTRIBUTE_PAYLOAD_V1_H_
#define ATTRIBUTE_PAYLOAD_V1_H_

typedef enum config_type_v1_t config_type_v1_t;
typedef struct attribute_payload_v1_t attribute_payload_v1_t;

#include <library.h>
#include <encoding/payloads/payload.h>
#include <encoding/payloads/data_attribute_v1.h>
#include <utils/enumerator.h>

/**
 * ATTRIBUTE_PAYLOAD_V1 length in bytes without any proposal substructure.
 */
#define ATTRIBUTE_PAYLOAD_V1_HEADER_LENGTH 8

/**
 * Config Type of an Attribute Payload.
 */
enum config_type_v1_t {
	ISAKMP_CFG_REQUEST = 1,
	ISAKMP_CFG_REPLY = 2,
	ISAKMP_CFG_SET = 3,
	ISAKMP_CFG_ACK = 4,
};

/**
 * enum name for config_type_v1_t.
 */
extern enum_name_t *config_type_v1_names;

/**
 * Class representing an ISAKMP Config Mode Attribute Payload.
 *
 * The Attribute Payload format is described in draft-ietf-ipsec-isakmp-mode-cfg-o5.txt section 3.2.
 */
struct attribute_payload_v1_t {

	/**
	 * The payload_t interface.
	 */
	payload_t payload_interface;

	/**
	 * Creates an enumerator of stored data_attribute_v1_t objects.
	 *
	 * @return			enumerator over configration_attribute_t
	 */
	enumerator_t *(*create_attribute_enumerator) (attribute_payload_v1_t *this);

	/**
	 * Adds a configuration attribute to the attribute payload.
	 *
	 * @param attribute	attribute to add
	 */
	void (*add_attribute)(attribute_payload_v1_t *this,
						  data_attribute_v1_t *attribute);

	/**
	 * Get the attribute payload type.
	 *
	 * @return			type of attribute payload
	 */
	config_type_v1_t (*get_type) (attribute_payload_v1_t *this);

	/**
	 * Destroys an attribute_payload_v1_t object.
	 */
	void (*destroy) (attribute_payload_v1_t *this);
};

/**
 * Creates an empty attribute payload
 *
 * @return		empty attribute payload
 */
attribute_payload_v1_t *attribute_payload_v1_create();

/**
 * Creates an attribute_payload_v1_t with type and value
 *
 * @param config_type	type of attribute payload to create
 * @return				created attribute payload
 */
attribute_payload_v1_t *attribute_payload_v1_create_type(config_type_v1_t config_type);

#endif /** ATTRIBUTE_PAYLOAD_V1_H_ @}*/
