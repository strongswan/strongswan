/**
 * @file eap_sim.c
 *
 * @brief Implementation of eap_sim_t.
 *
 */

/*
 * Copyright (C) 2007 Martin Willi
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

#include "eap_sim.h"

#include <dlfcn.h>

#include <daemon.h>
#include <library.h>

#define MAX_TRIES 3

ENUM(sim_subtype_names, SIM_START, SIM_CLIENT_ERROR,
	"SIM_START",
	"SIM_CHALLENGE",
	"SIM_NOTIFICATION",
	"SIM_13",
	"SIM_CLIENT_ERROR",
);

ENUM_BEGIN(sim_attribute_names, AT_END, AT_CLIENT_ERROR_CODE,
	"AT_END",
	"AT_0",
	"AT_RAND",
	"AT_AUTN",
	"AT_RES",
	"AT_AUTS",
	"AT_5",
	"AT_PADDING",
	"AT_NONCE_MT",
	"AT_8",
	"AT_9",
	"AT_PERMANENT_ID_REQ",
	"AT_MAC",
	"AT_NOTIFICATION",
	"AT_ANY_ID_REQ",
	"AT_IDENTITY",
	"AT_VERSION_LIST",
	"AT_SELECTED_VERSION",
	"AT_FULLAUTH_ID_REQ",
	"AT_18",
	"AT_COUNTER",
	"AT_COUNTER_TOO_SMALL",
	"AT_NONCE_S",
	"AT_CLIENT_ERROR_CODE");
ENUM_NEXT(sim_attribute_names, AT_IV, AT_RESULT_IND, AT_CLIENT_ERROR_CODE,
	"AT_IV",
	"AT_ENCR_DATA",
	"AT_131",
	"AT_NEXT_PSEUDONYM",
	"AT_NEXT_REAUTH_ID",
	"AT_CHECKCODE",
	"AT_RESULT_IND");
ENUM_END(sim_attribute_names, AT_RESULT_IND);


typedef struct private_eap_sim_t private_eap_sim_t;

/**
 * Private data of an eap_sim_t object.
 */
struct private_eap_sim_t {
	
	/**
	 * Public authenticator_t interface.
	 */
	eap_sim_t public;
	
	/**
	 * ID of ourself
	 */
	identification_t *peer;
	
	/**
	 * SIM cardreader function loaded from library
	 */
	sim_algo_t alg;
	
	/**
	 * handle of the loaded library
	 */
	void *handle;
	
	/**
	 * how many times we try to authenticate
	 */
	int tries;
	
	/**
	 * version this implementation uses
	 */
	chunk_t version;
	
	/**
	 * version list received from server
	 */
	chunk_t version_list;
	
	/**
	 * Nonce value used in AT_NONCE_MT
	 */
	chunk_t nonce;
	
	/**
	 * k_encr key derived from MK
	 */
	chunk_t k_encr;
	
	/**
	 * k_auth key derived from MK, used for AT_MAC verification
	 */
	chunk_t k_auth;
	
	/**
	 * MSK, used for EAP-SIM based IKEv2 authentication
	 */
	chunk_t msk;
	
	/**
	 * EMSK, extendes MSK for further uses
	 */
	chunk_t emsk;
};

/** length of the AT_NONCE_MT nonce value */
#define NONCE_LEN 16
/** length of the AT_MAC value */
#define MAC_LEN 16
/** length of the AT_RAND value */
#define RAND_LEN 16
/** length of the k_encr key */
#define KENCR_LEN 16
/** length of the k_auth key */
#define KAUTH_LEN 16
/** length of the MSK */
#define MSK_LEN 64
/** length of the EMSK */
#define EMSK_LEN 64

/* client error codes used in AT_CLIENT_ERROR_CODE */
char client_error_general_buf[] = {0x00, 0x01};
char client_error_unsupported_buf[] = {0x00, 0x02};
char client_error_insufficient_buf[] = {0x00, 0x03};
char client_error_notfresh_buf[] = {0x00, 0x04};
chunk_t client_error_general = chunk_from_buf(client_error_general_buf);
chunk_t client_error_unsupported = chunk_from_buf(client_error_unsupported_buf);
chunk_t client_error_insufficient = chunk_from_buf(client_error_insufficient_buf);
chunk_t client_error_notfresh = chunk_from_buf(client_error_notfresh_buf);

/**
 * Read EAP and EAP-SIM header, return SIM type
 */
static sim_subtype_t read_header(chunk_t *message)
{
	sim_subtype_t type;

	if (message->len < 8)
	{
		*message = chunk_empty;
		return 0;
	}
	type = *(message->ptr + 5);
	*message = chunk_skip(*message, 8);
	return type;
}

/**
 * read the next attribute from the chunk data
 */
static sim_attribute_t read_attribute(chunk_t *message, chunk_t *data)
{
	sim_attribute_t attribute;
	size_t length;
	
	DBG3(DBG_IKE, "reading attribute from %B", message);
	
	if (message->len < 2)
	{
		return AT_END;
	}
	attribute = *message->ptr++;
	length = *message->ptr++ * 4 - 2;
	message->len -= 2;
	DBG3(DBG_IKE, "found attribute %N with length %d",
		 sim_attribute_names, attribute, length);

	if (length > message->len)
	{
		return AT_END;
	}
	data->len = length;
	data->ptr = message->ptr;
	*message = chunk_skip(*message, length);
	return attribute;
}

/**
 * Build an EAP-SIM payload using a variable length attribute list.
 * The variable argument takes a sim_attribute_t followed by its data in a chunk.
 */
static eap_payload_t *build_payload(private_eap_sim_t *this, u_int8_t identifier,
									sim_subtype_t type, ...)
{
	chunk_t message = chunk_alloca(512);
	chunk_t pos = message;
	eap_payload_t *payload;
	va_list args;
	sim_attribute_t attr;
	u_int8_t *mac_pos = NULL;
	chunk_t mac_data = chunk_empty;
	
	/* write EAP header, skip length bytes */
	*pos.ptr++ = EAP_RESPONSE;
	*pos.ptr++ = identifier;
	pos.ptr += 2;
	pos.len -= 4;
	/* write SIM header with type and subtype, zero reserved bytes */
	*pos.ptr++ = EAP_SIM;
	*pos.ptr++ = type;
	*pos.ptr++ = 0;
	*pos.ptr++ = 0;
	pos.len -= 4;
	
	va_start(args, type);
	while ((attr = va_arg(args, sim_attribute_t)) != AT_END)
	{
		chunk_t data = va_arg(args, chunk_t);
		
		DBG3(DBG_IKE, "building %N %B", sim_attribute_names, attr, &data);
		
		/* write attribute header */
		*pos.ptr++ = attr;
		pos.len--;
		
		switch (attr)
		{
			case AT_CLIENT_ERROR_CODE:
			case AT_SELECTED_VERSION:
			{
				*pos.ptr = data.len/4 + 1;
				pos = chunk_skip(pos, 1);
				memcpy(pos.ptr, data.ptr, data.len);
				pos = chunk_skip(pos, data.len);
				break;
			}
			case AT_IDENTITY:
			{
				/* align up to four byte */
				if (data.len % 4)
				{
					chunk_t tmp = chunk_alloca((data.len/4)*4 + 4);
					memset(tmp.ptr, 0, tmp.len);
					memcpy(tmp.ptr, data.ptr, data.len);
					data = tmp;
				}
				*pos.ptr = data.len/4 + 1;
				pos = chunk_skip(pos, 1);
				/* actual length in bytes */
				*(u_int16_t*)pos.ptr = htons(data.len);
				pos = chunk_skip(pos, sizeof(u_int16_t));
				memcpy(pos.ptr, data.ptr, data.len);
				pos = chunk_skip(pos, data.len);
				break;
			}
			case AT_NONCE_MT:
			{
				*pos.ptr = data.len/4 + 1;
				pos = chunk_skip(pos, 1);
				memset(pos.ptr, 0, 2);
				pos = chunk_skip(pos, 2);
				memcpy(pos.ptr, data.ptr, data.len);
				pos = chunk_skip(pos, data.len);
				break;
			}
			case AT_MAC:
			{
				*pos.ptr++ = 5; pos.len--;
				*pos.ptr++ = 0; pos.len--;
				*pos.ptr++ = 0; pos.len--;
				mac_pos = pos.ptr;
				memset(mac_pos, 0, MAC_LEN);
				pos = chunk_skip(pos, MAC_LEN);
				mac_data = data;
				break;
			}
			case AT_RAND:
			{
				*pos.ptr++ = data.len/4 + 1; pos.len--;
				*pos.ptr++ = 0; pos.len--;
				*pos.ptr++ = 0; pos.len--;
				memcpy(pos.ptr, data.ptr, data.len);
				pos = chunk_skip(pos, data.len);
				break;
			}
			default:
				DBG1(DBG_IKE, "no rule to build EAP_SIM attribute %N, skipped",
					 sim_attribute_names, attr);
				break;
		}
	}
	va_end(args);
	
	/* calculate message length, write into header */
	message.len = pos.ptr - message.ptr;
	*(u_int16_t*)(message.ptr + 2) = htons(message.len);
	
	/* create MAC if AT_MAC attribte was included. Append supplied va_arg
	 * chunk mac_data to "to-sign" chunk */
	if (mac_pos)
	{
		signer_t *signer = signer_create(AUTH_HMAC_SHA1_128);
		signer->set_key(signer, this->k_auth);
		mac_data = chunk_cata("cc", message, mac_data);
		signer->get_signature(signer, mac_data, mac_pos);
		DBG3(DBG_IKE, "AT_MAC signature of %B\n is %b",
			 &mac_data, mac_pos, MAC_LEN);
		signer->destroy(signer);
	}
	
	payload = eap_payload_create_data(message);
	
	DBG3(DBG_IKE, "created EAP message %B", &message);
	return payload;
}

/**
 * process an EAP-SIM/Request/Start message
 */
static status_t process_start(private_eap_sim_t *this, eap_payload_t *in,
							  eap_payload_t **out)
{
	chunk_t message, data;
	sim_attribute_t attribute, include_id = AT_END;
	u_int8_t identifier;

	identifier = in->get_identifier(in);
	message = in->get_data(in);
	read_header(&message);

	while ((attribute = read_attribute(&message, &data)) != AT_END)
	{
		switch (attribute)
		{
			case AT_VERSION_LIST:
			{
				/* check if server supports our implementation */
				bool found = FALSE;
				if (data.len > 2)
				{
					/* read actual length first */
					data.len = min(data.len, ntohs(*(u_int16_t*)data.ptr) + 2);
					data = chunk_skip(data, 2);
					chunk_free(&this->version_list);
					this->version_list = chunk_clone(data);
					while (data.len >= this->version.len)
					{
						if (memeq(data.ptr, this->version.ptr, this->version.len))
						{
							found = TRUE;
							break;
						}
						data = chunk_skip(data, this->version.len);
					}
				}
				if (!found)
				{
					DBG1(DBG_IKE, "server does not support EAP_SIM "
						 "version number %#B", &this->version);
					*out = build_payload(this, identifier, SIM_CLIENT_ERROR,
							AT_CLIENT_ERROR_CODE, client_error_unsupported,
							AT_END);
					return NEED_MORE;
				}
				break;
			}
			case AT_PERMANENT_ID_REQ:
			case AT_FULLAUTH_ID_REQ:
			case AT_ANY_ID_REQ:
				/* only include AT_IDENTITY if requested */
				include_id = AT_IDENTITY;
				break;
			case AT_NOTIFICATION:
			{
				u_int16_t code = 0;
				if (data.len == 2)
				{
					code = ntohs(*(u_int16_t*)data.ptr);
				}
				if (code <= 32767) /* no success bit */
				{
					DBG1(DBG_IKE, "received %N error %d",
				 		 sim_attribute_names, attribute, code);
					*out = build_payload(this,
									in->get_identifier(in), SIM_CLIENT_ERROR,
						 			AT_CLIENT_ERROR_CODE, client_error_general,
									AT_END);
					return NEED_MORE;
				}
				else
				{
					DBG1(DBG_IKE, "received %N code %d",
				 		 sim_attribute_names, attribute, code);
				}
				break;
			}
			default:
				DBG1(DBG_IKE, "ignoring EAP_SIM attribute %N",
					 sim_attribute_names, attribute);
				break;
		}
	}
	
	/* build payload. If "include_id" is AT_END, AT_IDENTITY is ommited */
	*out = build_payload(this, identifier, SIM_START,
						 AT_SELECTED_VERSION, this->version,
						 AT_NONCE_MT, this->nonce,
						 include_id, this->peer->get_encoding(this->peer),
						 AT_END);
	return NEED_MORE;
}

/**
 * process an EAP-SIM/Request/Challenge message
 */
static status_t process_challenge(private_eap_sim_t *this, eap_payload_t *in,
								  eap_payload_t **out)
{
	chunk_t message, data, tmp, kcs, kc, sreses, sres, mk;
	sim_attribute_t attribute;
	u_int8_t identifier, i;
	chunk_t mac = chunk_empty, rands = chunk_empty;
	signer_t *signer;
	hasher_t *hasher;
	prf_t *prf;
	
	if (this->tries-- <= 0)
	{
		/* give up without notification. This hack is required as some buggy
		 * server implementations won't respect our client-error. */
		return FAILED;
	}

	identifier = in->get_identifier(in);
	message = in->get_data(in);
	read_header(&message);

	while ((attribute = read_attribute(&message, &data)) != AT_END)
	{
		switch (attribute)
		{
			case AT_RAND:
			{
				rands = chunk_skip(data, 2);
				break;
			}
			case AT_MAC:
			{
				/* backup MAC, zero it inline for later verification */
				data = chunk_skip(data, 2);
				mac = chunk_clonea(data);
				memset(data.ptr, 0, data.len);
				break;
			}
			case AT_NOTIFICATION:
			{
				u_int16_t code = 0;
				if (data.len == 2)
				{
					code = ntohs(*(u_int16_t*)data.ptr);
				}
				if (code <= 32767) /* no success bit */
				{
					DBG1(DBG_IKE, "received %N error %d",
				 		 sim_attribute_names, attribute, code);
					*out = build_payload(this,
									in->get_identifier(in), SIM_CLIENT_ERROR,
						 			AT_CLIENT_ERROR_CODE, client_error_general,
									AT_END);
					return NEED_MORE;
				}
				else
				{
					DBG1(DBG_IKE, "received %N code %d",
				 		 sim_attribute_names, attribute, code);
				}
				break;
			}
			default:
				DBG1(DBG_IKE, "ignoring EAP_SIM attribute %N",
					 sim_attribute_names, attribute);
				break;
		}
	}
	
	/* excepting two or three RAND, each 16 bytes. We require two valid
	 * and different RANDs */
	if ((rands.len != 2 * RAND_LEN && rands.len != 3 * RAND_LEN) ||
		memeq(rands.ptr, rands.ptr + RAND_LEN, RAND_LEN))
	{
		DBG1(DBG_IKE, "no valid AT_RAND received");
		*out = build_payload(this, identifier, SIM_CLIENT_ERROR,
							 AT_CLIENT_ERROR_CODE, client_error_insufficient,
							 AT_END);
		return NEED_MORE;
	}
	if (mac.len != MAC_LEN)
	{
		DBG1(DBG_IKE, "no valid AT_MAC received");
		*out = build_payload(this, identifier, SIM_CLIENT_ERROR,
							 AT_CLIENT_ERROR_CODE, client_error_general,
							 AT_END);
		return NEED_MORE;
	}
	
	/* get two or three KCs/SRESes from SIM using RANDs */
	kcs = kc = chunk_alloca(rands.len / 2);
	sreses = sres = chunk_alloca(rands.len / 4);
	while (rands.len > 0)
	{
		int kc_len = kc.len, sres_len = sres.len;
		
		if (this->alg(rands.ptr, RAND_LEN, sres.ptr, &sres_len, kc.ptr, &kc_len))
		{
			DBG1(DBG_IKE, "unable to get triplets from SIM");
			*out = build_payload(this, identifier, SIM_CLIENT_ERROR,
								 AT_CLIENT_ERROR_CODE, client_error_general,
								 AT_END);
			return NEED_MORE;
		}
		DBG3(DBG_IKE, "got triplet for RAND %b\n  Kc %b\n  SRES %b",
			 rands.ptr, RAND_LEN, sres.ptr, sres_len, kc.ptr, kc_len);
		kc = chunk_skip(kc, kc_len);
		sres = chunk_skip(sres, sres_len);
		rands = chunk_skip(rands, RAND_LEN);
	}
	
	/* build MK = SHA1(Identity|n*Kc|NONCE_MT|Version List|Selected Version) */
	tmp = chunk_cata("ccccc", this->peer->get_encoding(this->peer), kcs,
					 this->nonce, this->version_list, this->version);
	hasher = hasher_create(HASH_SHA1);
	mk = chunk_alloca(hasher->get_hash_size(hasher));
	hasher->get_hash(hasher, tmp, mk.ptr);
	hasher->destroy(hasher);
	DBG3(DBG_IKE, "MK = SHA1(%B\n) = %B", &tmp, &mk);
	
	/* K_encr | K_auth | MSK | EMSK = prf() | prf() | prf() | prf()
	 * FIPS PRF has 320 bit block size, we need 160 byte for keys
	 *  => run prf four times */
	prf = prf_create(PRF_FIPS_SHA1_160);
	prf->set_key(prf, mk);
	tmp = chunk_alloca(prf->get_block_size(prf) * 4);
	for (i = 0; i < 4; i++)
	{
		prf->get_bytes(prf, chunk_empty, tmp.ptr + tmp.len / 4 * i);
	}
	prf->destroy(prf);
	chunk_free(&this->k_encr);
	chunk_free(&this->k_auth);
	chunk_free(&this->msk);
	chunk_free(&this->emsk);
	chunk_split(tmp, "aaaa", KENCR_LEN, &this->k_encr, KAUTH_LEN, &this->k_auth,
				MSK_LEN, &this->msk, EMSK_LEN, &this->emsk);
	DBG3(DBG_IKE, "K_encr %B\nK_auth %B\nMSK %B\nEMSK %B",
		 &this->k_encr, &this->k_auth, &this->msk, &this->emsk);
	
	/* verify AT_MAC attribute, signature is over "EAP packet | NONCE_MT"  */
	signer = signer_create(AUTH_HMAC_SHA1_128);
	signer->set_key(signer, this->k_auth);
	tmp = chunk_cata("cc", in->get_data(in), this->nonce);
	if (!signer->verify_signature(signer, tmp, mac))
	{
		DBG1(DBG_IKE, "AT_MAC verification failed");
		signer->destroy(signer);
		*out = build_payload(this, identifier, SIM_CLIENT_ERROR,
							 AT_CLIENT_ERROR_CODE, client_error_general,
							 AT_END);
		return NEED_MORE;
	}
	signer->destroy(signer);
	
	/* build response, AT_MAC is built over "EAP packet | n*SRES" */
	*out = build_payload(this, identifier, SIM_CHALLENGE,
						 AT_MAC, sreses,
						 AT_END);
	return NEED_MORE;
}

/**
 * process an EAP-SIM/Request/Notification message
 */
static status_t process_notification(private_eap_sim_t *this, eap_payload_t *in,
									 eap_payload_t **out)
{
	chunk_t message, data;
	sim_attribute_t attribute;
	
	message = in->get_data(in);
	read_header(&message);

	while ((attribute = read_attribute(&message, &data)) != AT_END)
	{
		switch (attribute)
		{
			case AT_NOTIFICATION:
			{
				u_int16_t code = 0;
				if (data.len == 2)
				{
					code = ntohs(*(u_int16_t*)data.ptr);
				}
				if (code <= 32767) /* no success bit */
				{
					DBG1(DBG_IKE, "received %N error %d",
				 		 sim_attribute_names, attribute, code);
					*out = build_payload(this,
									in->get_identifier(in), SIM_CLIENT_ERROR,
						 			AT_CLIENT_ERROR_CODE, client_error_general,
									AT_END);
					return NEED_MORE;
				}
				else
				{
					DBG1(DBG_IKE, "received %N code %d",
				 		 sim_attribute_names, attribute, code);
				}
				break;
			}
			default:
				DBG1(DBG_IKE, "ignoring EAP_SIM attribute %N",
					 sim_attribute_names, attribute);
				break;
		}
	}
	/* reply with empty notification */
	*out = build_payload(this, in->get_identifier(in), SIM_NOTIFICATION, AT_END);
	return NEED_MORE;
}


/**
 * Implementation of eap_method_t.process for the peer
 */
static status_t process(private_eap_sim_t *this,
						eap_payload_t *in, eap_payload_t **out)
{
	sim_subtype_t type;
	chunk_t message;
	
	message = in->get_data(in);
	type = read_header(&message);
	
	switch (type)
	{
		case SIM_START:
			return process_start(this, in, out);
		case SIM_CHALLENGE:
			return process_challenge(this, in, out);
		case SIM_NOTIFICATION:
			return process_notification(this, in, out);
		default:
			DBG1(DBG_IKE, "unable to process EAP_SIM subtype %N",
				 sim_subtype_names, type);
			*out = build_payload(this, in->get_identifier(in), SIM_CLIENT_ERROR,
					AT_CLIENT_ERROR_CODE, client_error_general, AT_END);
			return NEED_MORE;
	}
}

/**
 * Implementation of eap_method_t.initiate for the peer
 */
static status_t initiate(private_eap_sim_t *this, eap_payload_t **out)
{
	/* peer never initiates */
	return FAILED;
}

/**
 * Implementation of eap_method_t.get_type.
 */
static eap_type_t get_type(private_eap_sim_t *this)
{
	return EAP_SIM;
}

/**
 * Implementation of eap_method_t.get_msk.
 */
static status_t get_msk(private_eap_sim_t *this, chunk_t *msk)
{
	if (this->msk.ptr)
	{
		*msk = this->msk;
		return SUCCESS;
	}
	return FAILED;
}

/**
 * Implementation of eap_method_t.is_mutual.
 */
static bool is_mutual(private_eap_sim_t *this)
{
	return TRUE;
}

/**
 * Implementation of eap_method_t.destroy.
 */
static void destroy(private_eap_sim_t *this)
{
	dlclose(this->handle);
	chunk_free(&this->nonce);
	chunk_free(&this->version_list);
	chunk_free(&this->k_auth);
	chunk_free(&this->k_encr);
	chunk_free(&this->msk);
	chunk_free(&this->emsk);
	free(this);
}

/*
 * Described in header.
 */
eap_sim_t *eap_create(eap_role_t role,
					  identification_t *server, identification_t *peer)
{
	private_eap_sim_t *this;
	randomizer_t *randomizer;
	static char version[] = {0x00,0x01};
	
	if (role != EAP_PEER)
	{
		return NULL;
	}	
	this = malloc_thing(private_eap_sim_t);
	
	this->handle = dlopen(SIM_READER_LIB, RTLD_LAZY);
	if (this->handle == NULL)
	{
		DBG1(DBG_IKE, "unable to open SIM reader '%s'", SIM_READER_LIB);		
		free(this);
		return NULL;
	}
	this->alg = dlsym(this->handle, SIM_READER_ALG);
	if (this->alg == NULL)
	{
		DBG1(DBG_IKE, "unable to open SIM reader function '%s' in '%s'",
			 SIM_READER_ALG, SIM_READER_LIB);
		dlclose(this->handle);
		free(this);
		return NULL;
	}
	
	randomizer = randomizer_create();
	if (randomizer->allocate_pseudo_random_bytes(randomizer, NONCE_LEN,
												 &this->nonce))
	{
		DBG1(DBG_IKE, "unable to generate NONCE for EAP_SIM");		
		randomizer->destroy(randomizer);
		free(this);
		return NULL;
	}
	randomizer->destroy(randomizer);
	
	/* public functions */
	this->public.eap_method_interface.initiate = (status_t(*)(eap_method_t*,eap_payload_t**))initiate;
	this->public.eap_method_interface.process = (status_t(*)(eap_method_t*,eap_payload_t*,eap_payload_t**))process;
	this->public.eap_method_interface.get_type = (eap_type_t(*)(eap_method_t*))get_type;
	this->public.eap_method_interface.is_mutual = (bool(*)(eap_method_t*))is_mutual;
	this->public.eap_method_interface.get_msk = (status_t(*)(eap_method_t*,chunk_t*))get_msk;
	this->public.eap_method_interface.destroy = (void(*)(eap_method_t*))destroy;
	
	/* private data */
	this->peer = peer;
	this->tries = MAX_TRIES;
	this->version.ptr = version;
	this->version.len = sizeof(version);
	this->version_list = chunk_empty;
	this->k_auth = chunk_empty;
	this->k_encr = chunk_empty;
	this->msk = chunk_empty;
	this->emsk = chunk_empty;
	
	return &this->public;
}
