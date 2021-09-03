/*
 * Copyright (C) 2020 Stafan Gula
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

#include "eap_anyconnect.h"

#include <daemon.h>
#include <library.h>
#include <crypto/hashers/hasher.h>
#include <inttypes.h>
#include <collections/array.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>
#include <asn1/asn1.h>
#include <asn1/oid.h>
#include <sa/ikev2/keymat_v2.h>
#include <sa/ikev2/authenticators/pubkey_authenticator.h>
#include <encoding/payloads/auth_payload.h>
#include <libxml/xmlwriter.h>

enum eap_anyconnect_types_t {
	EAP_ANYCONNECT_XML = 0,
	EAP_ANYCONNECT_SIGN = 1,
	EAP_ANYCONNECT_PKCS7 = 3,
};

enum eap_anyconnect_xml_types_t {
	EAP_ANYCONNECT_XML_NONE = 0,
	EAP_ANYCONNECT_XML_INIT = 1,
	EAP_ANYCONNECT_XML_AUTH_REPLY = 2,
	EAP_ANYCONNECT_XML_ACK = 3,
};

enum eap_anyconnect_settings_t {
	EAP_ANYCONNECT_SETTINGS_VERSION = 0,
	EAP_ANYCONNECT_SETTINGS_COMPUTER_NAME = 1,
	EAP_ANYCONNECT_SETTINGS_DEVICE_TYPE = 2,
	EAP_ANYCONNECT_SETTINGS_PLATFORM_VERSION = 3,
	EAP_ANYCONNECT_SETTINGS_UNIQUE_ID = 4,
	EAP_ANYCONNECT_SETTINGS_UNIQUE_ID_GLOBAL = 5,
	EAP_ANYCONNECT_SETTINGS_DEVICE_ID = 6,
	EAP_ANYCONNECT_SETTINGS_MAC_ADDRESS = 7,
	EAP_ANYCONNECT_SETTINGS_GROUP_ACCESS = 8,
	EAP_ANYCONNECT_SETTINGS_OPAQUE_TUNNEL_GROUP = 9,
	EAP_ANYCONNECT_SETTINGS_OPAQUE_CONFIG_HASH = 10,
	EAP_ANYCONNECT_SETTINGS_TOKEN_FILE = 11,
	EAP_ANYCONNECT_SETTINGS_TOKEN_SERVER_HASH = 12,
	EAP_ANYCONNECT_SETTINGS_TOKEN_CLIENT_HASH = 13,
	EAP_ANYCONNECT_SETTINGS_CSD_WRAPPER = 14,
};

#define EAP_ANYCONNECT_SETTINGS_FIRST EAP_ANYCONNECT_SETTINGS_VERSION
#define EAP_ANYCONNECT_SETTINGS_LAST EAP_ANYCONNECT_SETTINGS_CSD_WRAPPER

typedef enum eap_anyconnect_types_t eap_anyconnect_types_t;
typedef enum eap_anyconnect_xml_types_t eap_anyconnect_xml_types_t;
typedef enum eap_anyconnect_settings_t eap_anyconnect_settings_t;
typedef struct eap_anyconnect_tlv_t eap_anyconnect_tlv_t;
typedef struct eap_anyconnect_data_t eap_anyconnect_data_t;
typedef struct private_eap_anyconnect_t private_eap_anyconnect_t;
typedef struct eap_anyconnect_header_t eap_anyconnect_header_t;
typedef struct eap_anyconnect_xml_setting_rule_t eap_anyconnect_xml_setting_rule_t;

struct eap_anyconnect_tlv_t {
	uint16_t type;
	uint16_t length;
};

struct eap_anyconnect_data_t {
	eap_anyconnect_types_t type;
	chunk_t data;
	bool own_data;
};

struct eap_anyconnect_header_t {
	uint8_t code;
	uint8_t id;
	uint16_t length;
	uint8_t type;
	uint8_t vendor[3];
	uint32_t vendor_type;
};

struct eap_anyconnect_xml_setting_rule_t {
	bool mandatory;
	char *default_value;
	char *key;
};

eap_anyconnect_xml_setting_rule_t eap_anyconnect_xml_setting_rules[] = {
	{TRUE,	NULL,	"version"},
	{TRUE,	NULL,	"device-id.computer-name"},
	{TRUE,	NULL,	"device-id.device-type"},
	{TRUE,	NULL,	"device-id.platform-version"},
	{TRUE,	NULL,	"device-id.unique-id"},
	{TRUE,	NULL,	"device-id.unique-id-global"},
	{TRUE,	NULL,	"device-id.value"},
	{TRUE,	NULL,	"mac-address"},
	{TRUE,	NULL,	"group-access"},
	{FALSE,	NULL,	"opaque.tunnel-group"},
	{FALSE,	NULL,	"opaque.config-hash"},
	{FALSE,	NULL,	"token.file"},
	{FALSE,	NULL,	"token.server-hash"},
	{FALSE,	NULL,	"token.client-hash"},
	{TRUE,	NULL,	"csd-wrapper"},
};

#define EAP_VENDOR_HEADER_LEN 12
#define EAP_VENDOR_ENTRY_LEN 4
#define EAP_ANYCONNECT_XML_VERSION "1.0"
#define EAP_ANYCONNECT_XML_ENCODING "UTF-8"

/**
 * Private data of an eap_anyconnect_t object.
 */
struct private_eap_anyconnect_t {

	/**
	 * Public authenticator_t interface.
	 */
	eap_anyconnect_t public;

	/**
	 * ID of the server
	 */
	identification_t *server;

	/**
	 * ID of the peer
	 */
	identification_t *peer;

	/**
	 * challenge sent by the server
	 */
	chunk_t challenge;

	/**
	 * EAP message identifier
	 */
	uint8_t identifier;

	/**
	 * EAP anyconnect header
	 */
	eap_anyconnect_header_t header;

	/**
	 * array of TLVs
	 */
	array_t *tlvs;

	/**
	 * The nonce for authentication
	 */
	chunk_t nonce;

	/**
	 * The IKE_SA_INIT message for authentication
	 */
	chunk_t ike_sa_init;

	/**
	 * The reserved bytes for authentication
	 */
	char reserved[3];

	/**
	 * Whether the reserved bytes were set or not
	 */
	bool set_reserved_called;

	/**
	 * The mebedded pubkey authenticator
	 */
	authenticator_t *pubkey_authenticator;

	/**
	 * The XML document
	 */
	xmlDocPtr xml;

	/**
	 * The host scan token
	 */
	chunk_t host_scan_token;

	/**
	 * The opaque data from server
	 */
	chunk_t opaque;

	/**
	 * The settings
	 */
	char *settings[EAP_ANYCONNECT_SETTINGS_LAST+1];
};

typedef void (*array_callback_t)(void *data, int idx, void *user);

static void destroy_tlv(void *data, int idx, void *user)
{
	eap_anyconnect_data_t *data2 = data;
	if(data2)
	{
		if (data2->own_data)
		{
			free(data2->data.ptr);
		}
		free(data2);
	}
}

static void destroy_xml(private_eap_anyconnect_t *this)
{
	if (this->xml)
	{
		xmlFreeDoc(this->xml);
	}

	this->xml = NULL;
}

static void clear_array(array_t* array)
{
	if (array)
	{
		array_destroy_function(array, &destroy_tlv, NULL);
	}
}

static status_t parse_payload(private_eap_anyconnect_t *this, eap_payload_t *payload)
{
	clear_array(this->tlvs);
	this->tlvs = array_create(0, 2);
	chunk_t remaining_data = payload->get_data(payload);
	if (remaining_data.len < EAP_VENDOR_HEADER_LEN)
	{
		DBG1(DBG_IKE, "received EAP anyconnect tlvs with invalid header");
		return FAILED;
	}

	this->header = *(eap_anyconnect_header_t*)remaining_data.ptr;
	this->header.length = untoh16(&this->header.length);
	this->header.vendor_type = untoh32(&this->header.vendor_type);
	remaining_data = chunk_create(remaining_data.ptr + EAP_VENDOR_HEADER_LEN,
		remaining_data.len - EAP_VENDOR_HEADER_LEN);

	while (remaining_data.len > EAP_VENDOR_ENTRY_LEN)
	{
		eap_anyconnect_tlv_t header = *(eap_anyconnect_tlv_t*)remaining_data.ptr;
		header.length = untoh16(&header.length);
		header.type = untoh16(&header.type);
		if (header.length + EAP_VENDOR_ENTRY_LEN > remaining_data.len)
		{
			break;
		}

		switch (header.type)
		{
			case EAP_ANYCONNECT_XML:
				xmlInitParser();
				destroy_xml(this);
				this->xml = xmlReadMemory(remaining_data.ptr + EAP_VENDOR_ENTRY_LEN, header.length, "noname.xml", NULL, 0);
				xmlCleanupParser();
			case EAP_ANYCONNECT_SIGN:
			case EAP_ANYCONNECT_PKCS7:
			{
				eap_anyconnect_data_t *tlv = malloc(sizeof(eap_anyconnect_data_t));
				tlv->type = header.type;
				tlv->data = chunk_create(remaining_data.ptr + EAP_VENDOR_ENTRY_LEN, header.length);
				tlv->own_data = FALSE;
				array_insert(this->tlvs, ARRAY_TAIL, tlv);
				break;
			}
			default:
				DBG1(DBG_IKE, "received unknown EAP anyconnect tlv type %"PRIu16, header.type);
				break;
		}

		remaining_data = chunk_create(remaining_data.ptr + EAP_VENDOR_ENTRY_LEN + header.length,
				remaining_data.len - EAP_VENDOR_ENTRY_LEN - header.length);
	}

	array_compress(this->tlvs);
	if (remaining_data.len > 0)
	{
		DBG1(DBG_IKE, "received EAP anyconnect tlvs with invalid length, remaining length after parsing %"PRIu16, remaining_data.len);
		return FAILED;
	}

	return SUCCESS;
}

static eap_payload_t *encode_payload(private_eap_anyconnect_t *this, array_t *tlvs)
{
	chunk_t encoded_data = chunk_empty;
	eap_anyconnect_data_t* current;

	enumerator_t* enumerator = array_create_enumerator(tlvs);
	while (enumerator->enumerate(enumerator, &current))
	{
		eap_anyconnect_tlv_t tlv;
		tlv.length = current->data.len;
		tlv.length = untoh16(&tlv.length);
		tlv.type = current->type;
		tlv.type = untoh16(&tlv.type);
		chunk_t tlv_header = chunk_create((u_char*)&tlv, EAP_VENDOR_ENTRY_LEN);
		encoded_data = chunk_cat("mcc", encoded_data, tlv_header, current->data);
	}
	enumerator->destroy(enumerator);

	eap_anyconnect_header_t header = this->header;
	header.length= encoded_data.len + EAP_VENDOR_HEADER_LEN;
	header.length = untoh16(&header.length);
	header.vendor_type = untoh32(&header.vendor_type);
	encoded_data = chunk_cat("cm", chunk_create((u_char*)&header, EAP_VENDOR_HEADER_LEN), encoded_data);
	eap_payload_t *ret = eap_payload_create_data(encoded_data);
	chunk_free(&encoded_data);
	return ret;
}

static bool add_signature(private_eap_anyconnect_t *this)
{
	ike_sa_t *ike_sa = charon->bus->get_sa(charon->bus);
	if ((this->nonce.len > 0) && (this->ike_sa_init.len > 0) && this->set_reserved_called && ike_sa)
	{
		this->pubkey_authenticator = (authenticator_t *)pubkey_authenticator_create_builder(ike_sa,
								this->nonce, this->ike_sa_init, this->reserved);
	}

	if (!this->pubkey_authenticator)
	{
		DBG2(DBG_IKE, "the pubkey authenticator was not yet created for EAP anyconnect tlv");
		return FALSE;
	}

	message_t *msg = message_create(IKEV2_MAJOR_VERSION, IKEV2_MINOR_VERSION);
	if (!msg)
	{
		DBG2(DBG_IKE, "unable to create temporary mesage for RSA signature for EAP anyconnect tlv");
		return FALSE;
	}

	msg->set_exchange_type(msg, IKE_AUTH);
	if (this->pubkey_authenticator->build(this->pubkey_authenticator, msg) != SUCCESS)
	{
		DBG2(DBG_IKE, "unable to create RSA signature for EAP anyconnect tlv");
		msg->destroy(msg);
		return FALSE;
	}

	auth_payload_t *payload = (auth_payload_t *)msg->get_payload(msg, PLV2_AUTH);
	if (!payload)
	{
		DBG2(DBG_IKE, "unable to get AUTH payload to extract signature for EAP anyconnect tlv");
		msg->destroy(msg);
		return FALSE;
	}

	eap_anyconnect_data_t *tlv = malloc(sizeof(eap_anyconnect_data_t));
	tlv->type = EAP_ANYCONNECT_SIGN;
	tlv->data = chunk_clone(payload->get_data(payload));
	tlv->own_data = TRUE;
	array_insert(this->tlvs, ARRAY_TAIL, tlv);
	msg->destroy(msg);
	return TRUE;
}

METHOD(eap_method_t, initiate_peer, status_t,
	private_eap_anyconnect_t *this, eap_payload_t **out)
{
	return FAILED;
}

METHOD(eap_method_t, initiate_server, status_t,
	private_eap_anyconnect_t *this, eap_payload_t **out)
{
	DBG1(DBG_IKE, "eap_anyconnect on server is not supported");
	return FAILED;
}

static bool load_settings(private_eap_anyconnect_t *this)
{
	eap_anyconnect_settings_t i;
	char buffer[BUF_LEN];
	for (i = EAP_ANYCONNECT_SETTINGS_FIRST; i <= EAP_ANYCONNECT_SETTINGS_LAST; i++)
	{
		snprintf(buffer, BUF_LEN, "%s.plugins.eap-anyconnect.%s", lib->ns, eap_anyconnect_xml_setting_rules[i].key);
		this->settings[i] = lib->settings->get_str(lib->settings, buffer, eap_anyconnect_xml_setting_rules[i].default_value);
		if (eap_anyconnect_xml_setting_rules[i].mandatory && this->settings[i] == NULL)
		{
			DBG1(DBG_IKE, "eap_anyconnect missing mandatory configuration settings %s", buffer);
			return FALSE;
		}
	}
	return TRUE;
}

static bool xml_header(private_eap_anyconnect_t *this, xmlTextWriterPtr writer, eap_anyconnect_xml_types_t type)
{
	char *type_str = NULL;
	switch(type)
	{
		case EAP_ANYCONNECT_XML_INIT:
			type_str = "init";
			break;
		case EAP_ANYCONNECT_XML_AUTH_REPLY:
			type_str = "auth-reply";
			break;
		case EAP_ANYCONNECT_XML_ACK:
			type_str = "ack";
			break;
		default:
			return FALSE;
	}

	if (
		xmlTextWriterStartElement(writer, BAD_CAST "config-auth") < 0 ||
		xmlTextWriterWriteAttribute(writer, BAD_CAST "client", BAD_CAST "vpn") < 0 ||
		xmlTextWriterWriteAttribute(writer, BAD_CAST "type", BAD_CAST type_str) < 0 ||
		xmlTextWriterWriteAttribute(writer, BAD_CAST "aggregate-auth-version", BAD_CAST "2") < 0 ||

		xmlTextWriterStartElement(writer, BAD_CAST "version") < 0 ||
		xmlTextWriterWriteAttribute(writer, BAD_CAST "who", BAD_CAST "vpn") < 0 ||

		xmlTextWriterWriteString(writer, BAD_CAST this->settings[EAP_ANYCONNECT_SETTINGS_VERSION]) < 0 ||
		xmlTextWriterEndElement(writer) < 0 ||

		xmlTextWriterStartElement(writer, BAD_CAST "device-id") < 0 ||
		xmlTextWriterWriteAttribute(writer, BAD_CAST "computer-name", BAD_CAST this->settings[EAP_ANYCONNECT_SETTINGS_COMPUTER_NAME]) < 0 ||
		xmlTextWriterWriteAttribute(writer, BAD_CAST "device-type", BAD_CAST this->settings[EAP_ANYCONNECT_SETTINGS_DEVICE_TYPE]) < 0 ||
		xmlTextWriterWriteAttribute(writer, BAD_CAST "platform-version", BAD_CAST this->settings[EAP_ANYCONNECT_SETTINGS_PLATFORM_VERSION]) < 0 ||
		xmlTextWriterWriteAttribute(writer, BAD_CAST "unique-id", BAD_CAST this->settings[EAP_ANYCONNECT_SETTINGS_UNIQUE_ID]) < 0 ||
		xmlTextWriterWriteAttribute(writer, BAD_CAST "unique-id-global", BAD_CAST this->settings[EAP_ANYCONNECT_SETTINGS_UNIQUE_ID_GLOBAL]) < 0 ||
		xmlTextWriterWriteString(writer, BAD_CAST this->settings[EAP_ANYCONNECT_SETTINGS_DEVICE_ID]) < 0 ||
		xmlTextWriterEndElement(writer) < 0 ||

		xmlTextWriterStartElement(writer, BAD_CAST "mac-address-list") < 0 ||
		xmlTextWriterStartElement(writer, BAD_CAST "mac-address") < 0 ||
		xmlTextWriterWriteAttribute(writer, BAD_CAST "public-interface", BAD_CAST "true") < 0 ||
		xmlTextWriterWriteString(writer, BAD_CAST this->settings[EAP_ANYCONNECT_SETTINGS_MAC_ADDRESS]) < 0 ||
		xmlTextWriterEndElement(writer) < 0 ||
		xmlTextWriterEndElement(writer) < 0)
	{
		DBG1(DBG_IKE, "eap_anyconnect unable to create XML");
		return FALSE;
	}

	return TRUE;
}

static bool xml_session(xmlTextWriterPtr writer)
{
	if (
		xmlTextWriterStartElement(writer, BAD_CAST "session-token") < 0 ||
		xmlTextWriterEndElement(writer) < 0 ||
		xmlTextWriterStartElement(writer, BAD_CAST "session-id") < 0 ||
		xmlTextWriterEndElement(writer) < 0)
	{
		DBG1(DBG_IKE, "eap_anyconnect unable to create XML");
		return FALSE;
	}

	return TRUE;
}

static bool xml_opaque(private_eap_anyconnect_t *this, xmlTextWriterPtr writer)
{
	if (this->opaque.len > 0)
	{
		if (xmlTextWriterWriteRawLen(writer, BAD_CAST this->opaque.ptr, this->opaque.len) < 0)
		{
			DBG1(DBG_IKE, "eap_anyconnect unable to create XML");
			return FALSE;
		}
	}
	else if (this->settings[EAP_ANYCONNECT_SETTINGS_OPAQUE_TUNNEL_GROUP] && this->settings[EAP_ANYCONNECT_SETTINGS_OPAQUE_CONFIG_HASH])
	{
		if (
			xmlTextWriterStartElement(writer, BAD_CAST "opaque") < 0 ||
			xmlTextWriterWriteAttribute(writer, BAD_CAST "is-for", BAD_CAST "sg") < 0 ||
			xmlTextWriterStartElement(writer, BAD_CAST "tunnel-group") < 0 ||
			xmlTextWriterWriteString(writer, BAD_CAST this->settings[EAP_ANYCONNECT_SETTINGS_OPAQUE_TUNNEL_GROUP]) < 0 ||
			xmlTextWriterEndElement(writer) < 0 ||
			xmlTextWriterStartElement(writer, BAD_CAST "config-hash") < 0 ||
			xmlTextWriterWriteString(writer, BAD_CAST this->settings[EAP_ANYCONNECT_SETTINGS_OPAQUE_CONFIG_HASH]) < 0 ||
			xmlTextWriterEndElement(writer) < 0 ||
			xmlTextWriterEndElement(writer) < 0)
		{
			DBG1(DBG_IKE, "eap_anyconnect unable to create XML");
			return FALSE;
		}
	}
	return TRUE;
}

static bool xml_capabilities(private_eap_anyconnect_t *this, xmlTextWriterPtr writer)
{
	if (
		xmlTextWriterStartElement(writer, BAD_CAST "group-access") < 0 ||
		xmlTextWriterWriteString(writer, BAD_CAST this->settings[EAP_ANYCONNECT_SETTINGS_GROUP_ACCESS]) < 0 ||
		xmlTextWriterEndElement(writer) < 0 ||

		xmlTextWriterStartElement(writer, BAD_CAST "capabilities") < 0 ||
		xmlTextWriterStartElement(writer, BAD_CAST "auth-method") < 0 ||
		xmlTextWriterWriteString(writer, BAD_CAST "multiple-cert") < 0 ||
		xmlTextWriterEndElement(writer) < 0 ||
		xmlTextWriterStartElement(writer, BAD_CAST "auth-method") < 0 ||
		xmlTextWriterWriteString(writer, BAD_CAST "single-sign-on") < 0 ||
		xmlTextWriterEndElement(writer) < 0 ||
		xmlTextWriterStartElement(writer, BAD_CAST "auth-method") < 0 ||
		xmlTextWriterWriteString(writer, BAD_CAST "single-sign-on-v2") < 0 ||
		xmlTextWriterEndElement(writer) < 0 ||
		xmlTextWriterEndElement(writer) < 0)
	{
		DBG1(DBG_IKE, "eap_anyconnect unable to create XML");
		return FALSE;
	}

	return TRUE;
}

static bool xml_host_scan(private_eap_anyconnect_t *this, xmlTextWriterPtr writer)
{
	if (
		xmlTextWriterStartElement(writer, BAD_CAST "auth") < 0 ||
		xmlTextWriterEndElement(writer) < 0 ||
		xmlTextWriterStartElement(writer, BAD_CAST "host-scan-token") < 0 ||
		xmlTextWriterWriteRawLen(writer, BAD_CAST this->host_scan_token.ptr, this->host_scan_token.len) < 0 ||
		xmlTextWriterEndElement(writer) < 0)
	{
		DBG1(DBG_IKE, "eap_anyconnect unable to create XML");
		return FALSE;
	}

	return TRUE;
}

static bool xml_start(xmlTextWriterPtr *writer, xmlBufferPtr *buf)
{
	LIBXML_TEST_VERSION
	*buf = xmlBufferCreate();
	if (!*buf)
	{
		DBG1(DBG_IKE, "eap_anyconnect unable to allocate output buffer for XML writter");
		return FALSE;
	}

	*writer = xmlNewTextWriterMemory(*buf, 0);
	if (!*writer)
	{
		DBG1(DBG_IKE, "eap_anyconnect unable to create XML writer");
		xmlBufferFree(*buf);
		return FALSE;
	}

	if (xmlTextWriterStartDocument(*writer, EAP_ANYCONNECT_XML_VERSION, EAP_ANYCONNECT_XML_ENCODING, NULL) < 0)
	{
		DBG1(DBG_IKE, "eap_anyconnect unable to start XML document");
		xmlFreeTextWriter(*writer);
		xmlBufferFree(*buf);
		return FALSE;
	}

	return TRUE;
}

static void xml_footer(xmlTextWriterPtr writer)
{
	if (
		xmlTextWriterEndElement(writer) < 0 ||
		xmlTextWriterEndDocument(writer) < 0)
	{
		DBG1(DBG_IKE, "eap_anyconnect unable to close XML");
	}
}

static void xml_stop(xmlTextWriterPtr writer, xmlBufferPtr buf)
{
	xmlFreeTextWriter(writer);
	xmlBufferFree(buf);
}

static bool create_xml(private_eap_anyconnect_t *this, eap_anyconnect_xml_types_t type, chunk_t *output)
{
	DBG1(DBG_IKE, "eap_anyconnect create_init_xml");
	xmlTextWriterPtr writer;
	xmlBufferPtr buf;
	bool ret = TRUE;
	if (!xml_start(&writer, &buf))
	{
		return FALSE;
	}

	switch(type)
	{
		case EAP_ANYCONNECT_XML_INIT:
			ret = xml_header(this, writer, type) &&
				xml_opaque(this, writer) &&
				xml_capabilities(this, writer);
			break;
		case EAP_ANYCONNECT_XML_AUTH_REPLY:
			ret = xml_header(this, writer, type) &&
				xml_session(writer) &&
				xml_opaque(this, writer) &&
				xml_host_scan(this, writer);
			break;
		case EAP_ANYCONNECT_XML_ACK:
			ret = xml_header(this, writer, type);
			break;
		default:
			return FALSE;
	}

	xml_footer(writer);
	*output = chunk_clone(chunk_from_str(buf->content));
	xml_stop(writer, buf);
	return ret;
}

static bool add_cert_to_blob(private_eap_anyconnect_t *this, auth_rule_t rule, certificate_t **subject, chunk_t *blob)
{
	enumerator_t *enumerator;
	certificate_t *cert;
	auth_rule_t type;

	ike_sa_t *ike_sa = charon->bus->get_sa(charon->bus);
	auth_cfg_t *auth = ike_sa->get_auth_cfg(ike_sa, TRUE);

	enumerator = auth->create_enumerator(auth);
	while (enumerator->enumerate(enumerator, &type, &cert))
	{
		if (type == rule && (*subject == NULL || (*subject)->issued_by(*subject, cert, NULL)))
		{
			chunk_t encoded;
			if (!cert->get_encoding(cert, CERT_ASN1_DER, &encoded))
			{
				DBG1(DBG_IKE, "eap_anyconnect unable to encode certificate");
				return FALSE;
			}

			*subject = cert;
			*blob = chunk_cat("mm", *blob, encoded);
			return TRUE;
		}
	}

	return TRUE;
}

static bool add_certificate_to_tlvs(private_eap_anyconnect_t *this)
{
	chunk_t data = chunk_empty;
	certificate_t *cert = NULL;
	if (!add_cert_to_blob(this, AUTH_RULE_SUBJECT_CERT, &cert, &data) ||
		!add_cert_to_blob(this, AUTH_RULE_IM_CERT, &cert, &data) ||
		!add_cert_to_blob(this, AUTH_RULE_CA_CERT, &cert, &data))
	{
		DBG1(DBG_IKE, "eap_anyconnect unable prepare data for PKCS7 container");
		return FALSE;
	}

	data = asn1_wrap(ASN1_SEQUENCE, "mm",
			asn1_build_known_oid(OID_PKCS7_SIGNED_DATA),
			asn1_wrap(ASN1_CONTEXT_C_0, "m",
				asn1_wrap(ASN1_SEQUENCE, "cmmmm",
					ASN1_INTEGER_1,
					asn1_simple_object(ASN1_SET, chunk_empty),
					asn1_wrap(ASN1_SEQUENCE, "mm",
						asn1_build_known_oid(OID_PKCS7_DATA),
						asn1_wrap(ASN1_CONTEXT_C_0, "c", asn1_simple_object(ASN1_OCTET_STRING, chunk_empty))),
					asn1_wrap(ASN1_CONTEXT_C_0, "m", data),
					asn1_simple_object(ASN1_SET, chunk_empty)
				)));

	eap_anyconnect_data_t *tlv = malloc(sizeof(eap_anyconnect_data_t));
	tlv->type = EAP_ANYCONNECT_PKCS7;
	tlv->data = data;
	tlv->own_data = TRUE;
	array_insert(this->tlvs, ARRAY_TAIL, tlv);
	return TRUE;
}

static bool add_xml_to_tlvs(private_eap_anyconnect_t *this, eap_anyconnect_xml_types_t type)
{
	chunk_t xmldata = chunk_empty;
	create_xml(this, type, &xmldata);
	eap_anyconnect_data_t *tlv = malloc(sizeof(eap_anyconnect_data_t));
	tlv->type = EAP_ANYCONNECT_XML;
	tlv->data = xmldata;
	tlv->own_data = TRUE;
	array_insert(this->tlvs, ARRAY_TAIL, tlv);
	return TRUE;
}

static void create_fake_ticket_xml(private_eap_anyconnect_t *this, char *ticket, chunk_t token)
{
	if (this->settings[EAP_ANYCONNECT_SETTINGS_TOKEN_FILE] &&
		this->settings[EAP_ANYCONNECT_SETTINGS_TOKEN_SERVER_HASH] &&
		this->settings[EAP_ANYCONNECT_SETTINGS_TOKEN_CLIENT_HASH])
	{
		xmlTextWriterPtr writer = xmlNewTextWriterFilename(this->settings[EAP_ANYCONNECT_SETTINGS_TOKEN_FILE], 0);
		xmlTextWriterStartDocument(writer, EAP_ANYCONNECT_XML_VERSION, EAP_ANYCONNECT_XML_ENCODING, NULL);
		xmlTextWriterStartElement(writer, BAD_CAST "hostscan");
		xmlTextWriterStartElement(writer, BAD_CAST "ticket");
		xmlTextWriterWriteString(writer, ticket);
		xmlTextWriterEndElement(writer);
		xmlTextWriterStartElement(writer, BAD_CAST "token");
		xmlTextWriterWriteRawLen(writer, token.ptr, token.len);
		xmlTextWriterEndElement(writer);
		xmlTextWriterStartElement(writer, BAD_CAST "certhash");
		xmlTextWriterStartElement(writer, BAD_CAST "server");
		xmlTextWriterWriteString(writer, BAD_CAST this->settings[EAP_ANYCONNECT_SETTINGS_TOKEN_SERVER_HASH]);
		xmlTextWriterEndElement(writer);
		xmlTextWriterStartElement(writer, BAD_CAST "client");
		xmlTextWriterWriteString(writer, BAD_CAST this->settings[EAP_ANYCONNECT_SETTINGS_TOKEN_CLIENT_HASH]);
		xmlTextWriterEndElement(writer);
		xmlTextWriterEndElement(writer);
		xmlTextWriterEndElement(writer);
		xmlTextWriterEndDocument(writer);
		xmlFreeTextWriter(writer);
	}
}

static xmlNodePtr find_by_name(xmlNodePtr root, const char *name)
{
	xmlNodePtr cur = root->children;
	while (cur)
	{
		if ((!xmlStrcmp(cur->name, (const xmlChar *)name)))
		{
			break;
		}

		cur = cur->next;
	}

	return cur;
}

METHOD(eap_method_t, process_peer, status_t,
	private_eap_anyconnect_t *this, eap_payload_t *in, eap_payload_t **out)
{
	*out = NULL;
	bool add_certs_and_sign = FALSE;
	eap_anyconnect_xml_types_t add_xml = EAP_ANYCONNECT_XML_NONE;
	bool initiate_host_scan = FALSE;
	char buffer[1000];
	char *host_scan_ticket = NULL;
	ike_sa_t *ike_sa = charon->bus->get_sa(charon->bus);

	status_t ret = parse_payload(this, in);
	if (ret != SUCCESS)
	{
		return ret;
	}

	xmlNodePtr config_auth = xmlDocGetRootElement(this->xml);
	if (!config_auth)
	{
		DBG2(DBG_IKE, "eap_anyconnect received XML doesn't include config-auth element");
		return FAILED;
	}

	xmlNodePtr err = find_by_name(config_auth, "error");
	if (err)
	{
		char *errStr = (char *)xmlNodeGetContent(err->children);
		DBG1(DBG_IKE, "eap_anyconnect received the following error from server: %s", errStr);
		return FAILED;
	}

	xmlChar* value = xmlGetProp(config_auth, (const xmlChar *)"type");
	if (!xmlStrcmp(value, (const xmlChar *)"hello"))
	{
		DBG1(DBG_IKE, "eap_anyconnect hello received");
		add_xml = EAP_ANYCONNECT_XML_INIT;
	}
	else if (!xmlStrcmp(value, (const xmlChar *)"auth-request"))
	{
		DBG1(DBG_IKE, "eap_anyconnect auth-request received");
		xmlNodePtr opaque = find_by_name(config_auth, "opaque");
		if (opaque)
		{
			DBG1(DBG_IKE, "eap_anyconnect found opaque");
			xmlBufferPtr buf = xmlBufferCreate();
			xmlNodeDump(buf, this->xml, opaque, 0, 0);
			this->opaque = chunk_clone(chunk_from_str(buf->content));
			xmlBufferFree(buf);
		}

		xmlNodePtr cert_request = find_by_name(config_auth, "client-cert-request");
		if (cert_request)
		{
			DBG1(DBG_IKE, "eap_anyconnect client-cert-request received");
			add_xml = EAP_ANYCONNECT_XML_INIT;
			add_certs_and_sign = TRUE;
		}

		xmlNodePtr host_scan = find_by_name(config_auth, "host-scan");
		if (host_scan)
		{
			DBG1(DBG_IKE, "eap_anyconnect host-scan received");
			add_xml = EAP_ANYCONNECT_XML_AUTH_REPLY;
			initiate_host_scan = TRUE;
			xmlNodePtr host_scan_ticket_node = find_by_name(host_scan, "host-scan-ticket");
			if (host_scan_ticket_node)
			{
				host_scan_ticket = (char *)xmlNodeGetContent(host_scan_ticket_node->children);
			}

			xmlNodePtr host_scan_token = find_by_name(host_scan, "host-scan-token");
			if (host_scan_token)
			{
				chunk_free(&this->host_scan_token);
				this->host_scan_token = chunk_clone(chunk_from_str(xmlNodeGetContent(host_scan_token->children)));
			}

			create_fake_ticket_xml(this, host_scan_ticket, this->host_scan_token);
		}
	}
	else if (!xmlStrcmp(value, (const xmlChar *)"complete"))
	{
		DBG1(DBG_IKE, "eap_anyconnect complete received");
		add_xml = EAP_ANYCONNECT_XML_ACK;
	}

	clear_array(this->tlvs);
	this->tlvs = array_create(0, 2);
	if (add_certs_and_sign && (!add_certificate_to_tlvs(this) || !add_signature(this)))
	{
		DBG1(DBG_IKE, "eap_anyconnect unable to add certificate and signature");
		return FAILED;
	}

	if (initiate_host_scan)
	{
		host_t *other = ike_sa->get_other_host(ike_sa);
		snprintf(buffer, sizeof(buffer), "%s -host %H -ticket %s", this->settings[EAP_ANYCONNECT_SETTINGS_CSD_WRAPPER], other, host_scan_ticket);
		switch(system(buffer)){
			case 0:
				DBG2(DBG_IKE, "eap_anyconnect CSD wrapper finished successfully");
				break;
			case 1:
				DBG1(DBG_IKE, "eap_anyconnect CSD wrapper failed to get token");
				return FAILED;
			case 2:
				DBG1(DBG_IKE, "eap_anyconnect CSD wrapper failed to get proper response from wait");
				return FAILED;
			default:
				DBG1(DBG_IKE, "eap_anyconnect CSD wrapper failed due to unspecific reason");
				return FAILED;
		}
	}

	if (add_xml != EAP_ANYCONNECT_XML_NONE && !add_xml_to_tlvs(this, add_xml))
	{
		DBG1(DBG_IKE, "eap_anyconnect unable to add XML");
		return FAILED;
	}

	this->header.code = EAP_RESPONSE;
	*out = encode_payload(this, this->tlvs);
	return NEED_MORE;
}

METHOD(eap_method_t, process_server, status_t,
	private_eap_anyconnect_t *this, eap_payload_t *in, eap_payload_t **out)
{
	DBG1(DBG_IKE, "eap_anyconnect on server is not supported");
	return FAILED;
}

METHOD(eap_method_t, get_type, eap_type_t,
	private_eap_anyconnect_t *this, eap_vendor_t *vendor)
{
	*vendor = EAP_VENDOR_CISCO;
	return EAP_ANYCONNECT;
}

METHOD(eap_method_t, get_msk, status_t,
	private_eap_anyconnect_t *this, chunk_t *msk)
{
	return FAILED;
}

METHOD(eap_method_t, is_mutual, bool,
	private_eap_anyconnect_t *this)
{
	return FALSE;
}

METHOD(eap_method_t, get_identifier, uint8_t,
	private_eap_anyconnect_t *this)
{
	return this->identifier;
}

METHOD(eap_method_t, set_identifier, void,
	private_eap_anyconnect_t *this, uint8_t identifier)
{
	this->identifier = identifier;
}

METHOD(eap_method_t, destroy, void,
	private_eap_anyconnect_t *this)
{
	DESTROY_IF(this->pubkey_authenticator);
	this->peer->destroy(this->peer);
	this->server->destroy(this->server);
	chunk_free(&this->challenge);
	clear_array(this->tlvs);
	chunk_free(&this->ike_sa_init);
	chunk_free(&this->nonce);
	destroy_xml(this);
	chunk_free(&this->host_scan_token);
	chunk_free(&this->opaque);
	free(this);
}

METHOD(eap_method_t, set_nonce, void,
	private_eap_anyconnect_t *this, chunk_t nonce)
{
	this->nonce = chunk_clone(nonce);
}

METHOD(eap_method_t, set_ike_sa_init, void,
	private_eap_anyconnect_t *this, chunk_t ike_sa_init)
{
	this->ike_sa_init = chunk_clone(ike_sa_init);
}

METHOD(eap_method_t, set_reserved, void,
	private_eap_anyconnect_t *this, char *reserved)
{
	memcpy(this->reserved, reserved, sizeof(this->reserved));
	this->set_reserved_called = TRUE;
}

/*
 * See header
 */
eap_anyconnect_t *eap_anyconnect_create_server(identification_t *server, identification_t *peer)
{
	private_eap_anyconnect_t *this;

	INIT(this,
		.public = {
			.eap_method = {
				.initiate = _initiate_server,
				.process = _process_server,
				.get_type = _get_type,
				.is_mutual = _is_mutual,
				.get_msk = _get_msk,
				.get_identifier = _get_identifier,
				.set_identifier = _set_identifier,
				.destroy = _destroy,
				.set_nonce = _set_nonce,
				.set_ike_sa_init = _set_ike_sa_init,
				.set_reserved = _set_reserved,
			},
		},
		.peer = peer->clone(peer),
		.server = server->clone(server),
		.tlvs = NULL,
		.nonce = chunk_empty,
		.ike_sa_init = chunk_empty,
		.pubkey_authenticator = NULL,
		.set_reserved_called = FALSE,
		.xml = NULL,
		.host_scan_token = chunk_empty,
		.opaque = chunk_empty,
	);

	memset(this->reserved, 0, sizeof(this->reserved));
	/* generate a non-zero identifier */
	do {
		this->identifier = random();
	} while (!this->identifier);

	return &this->public;
}

/*
 * See header
 */
eap_anyconnect_t *eap_anyconnect_create_peer(identification_t *server, identification_t *peer)
{
	private_eap_anyconnect_t *this;

	INIT(this,
		.public = {
			.eap_method = {
				.initiate = _initiate_peer,
				.process = _process_peer,
				.get_type = _get_type,
				.is_mutual = _is_mutual,
				.get_msk = _get_msk,
				.destroy = _destroy,
				.set_nonce = _set_nonce,
				.set_ike_sa_init = _set_ike_sa_init,
				.set_reserved = _set_reserved,
			},
		},
		.peer = peer->clone(peer),
		.server = server->clone(server),
		.tlvs = NULL,
		.nonce = chunk_empty,
		.ike_sa_init = chunk_empty,
		.pubkey_authenticator = NULL,
		.set_reserved_called = FALSE,
		.xml = NULL,
		.host_scan_token = chunk_empty,
		.opaque = chunk_empty,
	);
	memset(this->reserved, 0, sizeof(this->reserved));
	if (!load_settings(this))
	{
		_destroy(this);
		return NULL;
	}

	return &this->public;
}
