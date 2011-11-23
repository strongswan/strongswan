
/**
 * @defgroup data_attribute_v1 data_attribute_v1
 * @{ @ingroup payloads
 */

#ifndef DATA_ATTRIBUTE_V1_H_
#define DATA_ATTRIBUTE_V1_H_

typedef struct data_attribute_v1_t data_attribute_v1_t;

#include <library.h>
#include <attributes/attributes.h>
#include <encoding/payloads/payload.h>

/**
 * Configuration attribute header length in bytes.
 */
#define DATA_ATTRIBUTE_V1_HEADER_LENGTH 4

/**
 * Class representing an IKEv1-Data Attribute.
 *
 * The DATA_ATTRIBUTE_V1 format is described in RFC section 3.15.1.
 */
struct data_attribute_v1_t {

	/**
	 * Implements payload_t interface.
	 */
	payload_t payload_interface;

	/**
	 * Get the type of the attribute.
	 *
	 * @return 		type of the data attribute
	 */
	configuration_attribute_type_t (*get_type)(data_attribute_v1_t *this);

	/**
	 * Returns the value of the attribute.
	 *
	 * @return 		the basic internal value
	 */
	u_int16_t (*get_value) (data_attribute_v1_t *this);

	/**
	 * Returns the value of the attribute.
	 *
	 * @return 		chunk_t pointing to the internal value
	 */
	chunk_t (*get_value_chunk) (data_attribute_v1_t *this);

	/**
	 * Destroys an configuration_attribute_t object.
	 */
	void (*destroy) (data_attribute_v1_t *this);
};

/**
 * Creates an empty data attribute.
 *
 * @return		created data attribute
 */
data_attribute_v1_t *data_attribute_v1_create();

/**
 * Creates a data attribute with type and value.
 *
 * @param type	type of data attribute
 * @param value	value, gets cloned
 * @return		created data attribute
 */
data_attribute_v1_t *data_attribute_v1_create_value(
							configuration_attribute_type_t type, chunk_t value);


/**
 * Creates a data attribute with type and value.
 *
 * @param type	type of data attribute
 * @param value	value
 * @return		created data attribute
 */
data_attribute_v1_t *data_attribute_v1_create_basic(
							configuration_attribute_type_t type, u_int16_t value);

#endif /** DATA_ATTRIBUTE_V1_H_ @}*/
