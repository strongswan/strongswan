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


/* The EAP-AKA method uses it's own simple parser for processing EAP-AKA
 * payloads, as the IKEv2 parser is not suitable for that job. There are
 * two simple methods for parsing payloads, read_header() and read_attribute().
 * Every EAP-AKA payload consists of a header and a list of attributes. Those
 * functions mentioned read the data and return the type of the found
 * attribute/EAP-AKA-type. For generating a EAP-AKA message, we have a
 * build_aka_payload(), which builds the whole message from a variable
 * argument list containing its attributes.
 * The processing of messages is split up in various functions:
 * - peer_process() - General processing multiplexer for the peer
 *   - peer_process_challenge() - Specific AKA-Challenge processor
 *   - peer_process_notification() - Processing of AKA-Notification
 * - server_process() - General processing multiplexer for the server
 *   - peer_process_challenge() - Processing of a received Challenge response
 *   - peer_process_synchronize() - Process a sequence number synchronization
 * - server_initiate() - Initiation method for the server, calls
 *   - server_initiate_challenge() - Initiation of AKA-Challenge
 */

#include <limits.h>
#include <string.h>
#include <unistd.h>
#include <gmp.h>

#include "eap_aka.h"

#include <daemon.h>
#include <library.h>
#include <crypto/hashers/hasher.h>

/* Use test vectors specified in S.S0055
#define TEST_VECTORS */

#define RAND_LENGTH		16
#define RES_LENGTH		16
#define SQN_LENGTH		 6
#define K_LENGTH		16
#define MAC_LENGTH 		 8
#define CK_LENGTH		16
#define IK_LENGTH		16
#define AK_LENGTH		 6
#define AMF_LENGTH		 2
#define FMK_LENGTH		 4
#define AUTN_LENGTH 	(SQN_LENGTH + AMF_LENGTH + MAC_LENGTH)
#define AUTS_LENGTH 	(SQN_LENGTH + MAC_LENGTH)
#define PAYLOAD_LENGTH	64
#define MK_LENGTH		20
#define MSK_LENGTH		64
#define EMSK_LENGTH		64
#define KAUTH_LENGTH	16
#define KENCR_LENGTH	16
#define AT_MAC_LENGTH	16

#define F1			  0x42
#define F1STAR		  0x43
#define F2			  0x44
#define F3			  0x45
#define F4			  0x46
#define F5			  0x47
#define F5STAR		  0x48

typedef enum aka_subtype_t aka_subtype_t;
typedef enum aka_attribute_t aka_attribute_t;

/**
 * Subtypes of AKA messages
 */
enum aka_subtype_t {
	AKA_CHALLENGE = 1,
	AKA_AUTHENTICATION_REJECT = 2,
	AKA_SYNCHRONIZATION_FAILURE = 4,
	AKA_IDENTITY = 5,
	AKA_NOTIFICATION = 12,
	AKA_REAUTHENTICATION = 13,
	AKA_CLIENT_ERROR = 14,
};

/**
 * Attribute types in AKA messages
 */
enum aka_attribute_t {
	/** defines the end of attribute list */
	AT_END = -1,
	AT_RAND = 1,
	AT_AUTN = 2,
	AT_RES = 3,
	AT_AUTS = 4,
	AT_PADDING = 6,
	AT_NONCE_MT = 7,
	AT_PERMANENT_ID_REQ = 10,
	AT_MAC = 11,
	AT_NOTIFICATION = 12,
	AT_ANY_ID_REQ = 13,
	AT_IDENTITY = 14,
	AT_VERSION_LIST = 15,
	AT_SELECTED_VERSION = 16,
	AT_FULLAUTH_ID_REQ = 17,
	AT_COUNTER = 19,
	AT_COUNTER_TOO_SMALL = 20,
	AT_NONCE_S = 21,
	AT_CLIENT_ERROR_CODE = 22,
	AT_IV = 129,
	AT_ENCR_DATA = 130,
	AT_NEXT_PSEUDONYM = 132,
	AT_NEXT_REAUTH_ID = 133,
	AT_CHECKCODE = 134,
	AT_RESULT_IND = 135,
};

ENUM_BEGIN(aka_subtype_names, AKA_CHALLENGE, AKA_IDENTITY,
	"AKA_CHALLENGE",
	"AKA_AUTHENTICATION_REJECT",
	"AKA_3",
	"AKA_SYNCHRONIZATION_FAILURE",
	"AKA_IDENTITY");
ENUM_NEXT(aka_subtype_names, AKA_NOTIFICATION, AKA_CLIENT_ERROR, AKA_IDENTITY,
	"AKA_NOTIFICATION",
	"AKA_REAUTHENTICATION",
	"AKA_CLIENT_ERROR");
ENUM_END(aka_subtype_names, AKA_CLIENT_ERROR);


ENUM_BEGIN(aka_attribute_names, AT_END, AT_CLIENT_ERROR_CODE,
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
ENUM_NEXT(aka_attribute_names, AT_IV, AT_RESULT_IND, AT_CLIENT_ERROR_CODE,
	"AT_IV",
	"AT_ENCR_DATA",
	"AT_131",
	"AT_NEXT_PSEUDONYM",
	"AT_NEXT_REAUTH_ID",
	"AT_CHECKCODE",
	"AT_RESULT_IND");
ENUM_END(aka_attribute_names, AT_RESULT_IND);


typedef struct private_eap_aka_t private_eap_aka_t;

/**
 * Private data of an eap_aka_t object.
 */
struct private_eap_aka_t {

	/**
	 * Public authenticator_t interface.
	 */
	eap_aka_t public;

	/**
	 * ID of the server
	 */
	identification_t *server;

	/**
	 * ID of the peer
	 */
	identification_t *peer;

	/**
	 * SHA11 hasher
	 */
	hasher_t *sha1;

	/**
	 * MAC function used in EAP-AKA
	 */
	signer_t *signer;

	/**
	 * pseudo random function used in EAP-aka
	 */
	prf_t *prf;

	/**
	 * Special keyed SHA1 hasher used in EAP-AKA, implemented as PRF
	 */
	prf_t *keyed_prf;

	/**
	 * Key for EAP MAC
	 */
	chunk_t k_auth;

	/**
	 * Key for EAP encryption
	 */
	chunk_t k_encr;

	/**
	 * MSK
	 */
	chunk_t msk;

	/**
	 * Extendend MSK
	 */
	chunk_t emsk;

	/**
	 * Expected result from client XRES
	 */
	chunk_t xres;

	/**
	 * Shared secret K from ipsec.conf (padded)
	 */
	chunk_t k;

	/**
	 * random value RAND generated by server
	 */
	 chunk_t rand;
};

/** Family key, as proposed in S.S0055 */
static chunk_t fmk = chunk_from_chars(0x41, 0x48, 0x41, 0x47);

/** Authentication management field */
static chunk_t amf = chunk_from_chars(0x00, 0x01);

/** AT_CLIENT_ERROR_CODE AKA attribute */
static chunk_t client_error_code = chunk_from_chars(0, 0);

/** previously used sqn by peer, next one must be greater */
static u_int8_t peer_sqn_buf[6];
static chunk_t peer_sqn = {peer_sqn_buf, sizeof(peer_sqn_buf)};

/** set SQN to the current time */
static void update_sqn(u_int8_t *sqn, time_t offset)
{
	timeval_t time;

	time_monotonic(&time);
	/* set sqb_sqn to an integer containing seconds followed by most
	 * significant useconds */
	time.tv_sec = htonl(time.tv_sec + offset);
	/* usec's are never larger than 0x000f423f, so we shift the 12 first bits */
	time.tv_usec <<= 12;
	time.tv_usec = htonl(time.tv_usec);
	memcpy(sqn, &time.tv_sec, 4);
	memcpy(sqn + 4, &time.tv_usec, 2);
}

/** initialize peers SQN to the current system time at startup */
static void __attribute__ ((constructor))init_sqn(void)
{
	update_sqn(peer_sqn_buf, 0);
}

/**
 * Binary represnation of the polynom T^160 + T^5 + T^3 + T^2 + 1
 */
static u_int8_t g[] = {
	0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x2d
};

/**
 * Predefined random bits from the RAND Corporation book
 */
static u_int8_t a[] = {
	0x9d, 0xe9, 0xc9, 0xc8, 0xef, 0xd5, 0x78, 0x11,
	0x48, 0x23, 0x14, 0x01, 0x90, 0x1f, 0x2d, 0x49,
	0x3f, 0x4c, 0x63, 0x65
};

/**
 * Predefined random bits from the RAND Corporation book
 */
static u_int8_t b[] = {
	0x75, 0xef, 0xd1, 0x5c, 0x4b, 0x8f, 0x8f, 0x51,
	0x4e, 0xf3, 0xbc, 0xc3, 0x79, 0x4a, 0x76, 0x5e,
	0x7e, 0xec, 0x45, 0xe0
};

/**
 * Multiplicate two mpz_t with bits interpreted as polynoms.
 */
static void mpz_mul_poly(mpz_t r, mpz_t a, mpz_t b)
{
	mpz_t bm, rm;
	int current = 0, shifted = 0, shift;

	mpz_init_set(bm, b);
	mpz_init_set_ui(rm, 0);
	/* scan through a, for each found bit: */
	while ((current = mpz_scan1(a, current)) != ULONG_MAX)
	{
		/* XOR shifted b into r */
		shift = current - shifted;
		mpz_mul_2exp(bm, bm, shift);
		shifted += shift;
		mpz_xor(rm, rm, bm);
		current++;
	}

	mpz_swap(r, rm);
	mpz_clear(rm);
	mpz_clear(bm);
}

/**
 * Calculate the sum of a + b interpreted as polynoms.
 */
static void mpz_add_poly(mpz_t res, mpz_t a, mpz_t b)
{
	/* addition of polynominals is just the XOR */
	mpz_xor(res, a, b);
}

/**
 * Calculate the remainder of a/b interpreted as polynoms.
 */
static void mpz_mod_poly(mpz_t r, mpz_t a, mpz_t b)
{
	/* Example:
	 * a = 10001010
	 * b = 00000101
	 */
	int a_bit, b_bit, diff;
	mpz_t bm, am;

	mpz_init_set(am, a);
	mpz_init(bm);

	a_bit = mpz_sizeinbase(a, 2);
	b_bit = mpz_sizeinbase(b, 2);

	/* don't do anything if b > a */
	if (a_bit >= b_bit)
	{
		/* shift b left to align up most signaficant "1" to a:
		 * a = 10001010
		 * b = 10100000
		 */
		mpz_mul_2exp(bm, b, a_bit - b_bit);
		do
		{
			/* XOR b into a, this kills the most significant "1":
			 * a = 00101010
			 */
			mpz_xor(am, am, bm);
			/* find the next most significant "1" in a, and align up b:
			 * a = 00101010
			 * b = 00101000
			 */
			diff = a_bit - mpz_sizeinbase(am, 2);
			mpz_div_2exp(bm, bm, diff);
			a_bit -= diff;
		}
		while (b_bit <= mpz_sizeinbase(bm, 2));
		/* While b is not shifted to its original value */
	}
	/* after another iteration:
	 * a = 00000010
	 * which is the polynomial modulo
	 */

	mpz_swap(r, am);
	mpz_clear(am);
	mpz_clear(bm);
}

/**
 * Step 4 of the various fx() functions:
 * Polynomial whiten calculations
 */
static void step4(private_eap_aka_t *this, u_int8_t x[])
{
	mpz_t xm, am, bm, gm;

	mpz_init(xm);
	mpz_init(am);
	mpz_init(bm);
	mpz_init(gm);

	mpz_import(xm, HASH_SIZE_SHA1, 1, 1, 1, 0, x);
	mpz_import(am, sizeof(a), 1, 1, 1, 0, a);
	mpz_import(bm, sizeof(b), 1, 1, 1, 0, b);
	mpz_import(gm, sizeof(g), 1, 1, 1, 0, g);

	mpz_mul_poly(xm, am, xm);
	mpz_add_poly(xm, bm, xm);
	mpz_mod_poly(xm, xm, gm);

	mpz_export(x, NULL, 1, HASH_SIZE_SHA1, 1, 0, xm);

	mpz_clear(xm);
	mpz_clear(am);
	mpz_clear(bm);
	mpz_clear(gm);
}

/**
 * Step 3 of the various fx() functions:
 * XOR the key into the SHA1 IV
 */
static void step3(private_eap_aka_t *this,
				  chunk_t k, chunk_t payload, u_int8_t h[])
{
	u_int8_t buf[64];

	if (payload.len < sizeof(buf))
	{
		/* pad c with zeros */
		memset(buf, 0, sizeof(buf));
		memcpy(buf, payload.ptr, payload.len);
		payload.ptr = buf;
		payload.len = sizeof(buf);
	}
	else
	{
		/* not more than 512 bits can be G()-ed */
		payload.len = sizeof(buf);
	}

	/* use the keyed hasher to build the hash */
	this->keyed_prf->set_key(this->keyed_prf, k);
	this->keyed_prf->get_bytes(this->keyed_prf, payload, h);
}

/**
 * Calculation function for f2(), f3(), f4()
 */
static void fx(private_eap_aka_t *this,
			   u_int8_t f, chunk_t k, chunk_t rand, u_int8_t out[])
{
	chunk_t payload = chunk_alloca(PAYLOAD_LENGTH);
	u_int8_t h[HASH_SIZE_SHA1];
	u_int8_t i;

	for (i = 0; i < 2; i++)
	{
		memset(payload.ptr, 0x5c, payload.len);
		payload.ptr[11] ^= f;
		memxor(payload.ptr + 12, fmk.ptr, fmk.len);
		memxor(payload.ptr + 24, rand.ptr, rand.len);

		payload.ptr[3]  ^= i;
		payload.ptr[19] ^= i;
		payload.ptr[35] ^= i;
		payload.ptr[51] ^= i;

		step3(this, k, payload, h);
		step4(this, h);
		memcpy(out + i * 8, h, 8);
	}
}

/**
 * Calculation function of f1() and f1star()
 */
static void f1x(private_eap_aka_t *this,
				u_int8_t f, chunk_t k, chunk_t rand, chunk_t sqn,
				chunk_t amf, u_int8_t mac[])
{
	/* generate MAC = f1(FMK, SQN, RAND, AMF)
	 * K is loaded into hashers IV; FMK, RAND, SQN, AMF are XORed in a 512-bit
	 * payload which gets hashed
	 */
	chunk_t payload = chunk_alloca(PAYLOAD_LENGTH);
	u_int8_t h[HASH_SIZE_SHA1];

	memset(payload.ptr, 0x5c, PAYLOAD_LENGTH);
	payload.ptr[11] ^= f;
	memxor(payload.ptr + 12, fmk.ptr, fmk.len);
	memxor(payload.ptr + 16, rand.ptr, rand.len);
	memxor(payload.ptr + 34, sqn.ptr, sqn.len);
	memxor(payload.ptr + 42, amf.ptr, amf.len);

	step3(this, k, payload, h);
	step4(this, h);
	memcpy(mac, h, MAC_LENGTH);
}

/**
 * Calculation function of f5() and f5star()
 */
static void f5x(private_eap_aka_t *this,
				u_int8_t f, chunk_t k, chunk_t rand, u_int8_t ak[])
{
	chunk_t payload = chunk_alloca(PAYLOAD_LENGTH);
	u_int8_t h[HASH_SIZE_SHA1];

	memset(payload.ptr, 0x5c, payload.len);
	payload.ptr[11] ^= f;
	memxor(payload.ptr + 12, fmk.ptr, fmk.len);
	memxor(payload.ptr + 16, rand.ptr, rand.len);

	step3(this, k, payload, h);
	step4(this, h);
	memcpy(ak, h, AK_LENGTH);
}

/**
 * Calculate the MAC from a RAND, SQN, AMF value using K
 */
static void f1(private_eap_aka_t *this, chunk_t k, chunk_t rand, chunk_t sqn,
			   chunk_t amf, u_int8_t mac[])
{
	f1x(this, F1, k, rand, sqn, amf, mac);
	DBG3(DBG_IKE, "MAC %b", mac, MAC_LENGTH);
}

/**
 * Calculate the MACS from a RAND, SQN, AMF value using K
 */
static void f1star(private_eap_aka_t *this, chunk_t k, chunk_t rand,
				   chunk_t sqn, chunk_t amf, u_int8_t macs[])
{
	f1x(this, F1STAR, k, rand, sqn, amf, macs);
	DBG3(DBG_IKE, "MACS %b", macs, MAC_LENGTH);
}

/**
 * Calculate RES from RAND using K
 */
static void f2(private_eap_aka_t *this, chunk_t k, chunk_t rand, u_int8_t res[])
{
	fx(this, F2, k, rand, res);
	DBG3(DBG_IKE, "RES %b", res, RES_LENGTH);
}

/**
 * Calculate CK from RAND using K
 */
static void f3(private_eap_aka_t *this, chunk_t k, chunk_t rand, u_int8_t ck[])
{
	fx(this, F3, k, rand, ck);
	DBG3(DBG_IKE, "CK %b", ck, CK_LENGTH);
}

/**
 * Calculate IK from RAND using K
 */
static void f4(private_eap_aka_t *this, chunk_t k, chunk_t rand, u_int8_t ik[])
{
	fx(this, F4, k, rand, ik);
	DBG3(DBG_IKE, "IK %b", ik, IK_LENGTH);
}

/**
 * Calculate AK from a RAND using K
 */
static void f5(private_eap_aka_t *this, chunk_t k, chunk_t rand, u_int8_t ak[])
{
	f5x(this, F5, k, rand, ak);
	DBG3(DBG_IKE, "AK %b", ak, AK_LENGTH);
}

/**
 * Calculate AKS from a RAND using K
 */
static void f5star(private_eap_aka_t *this, chunk_t k, chunk_t rand, u_int8_t aks[])
{
	f5x(this, F5STAR, k, rand, aks);
	DBG3(DBG_IKE, "AKS %b", aks, AK_LENGTH);
}

/**
 * derive the keys needed for EAP_AKA
 */
static bool derive_keys(private_eap_aka_t *this, identification_t *id)
{
	chunk_t ck, ik, mk, identity, tmp;

	ck = chunk_alloca(CK_LENGTH);
	ik = chunk_alloca(IK_LENGTH);
	mk = chunk_alloca(MK_LENGTH);
	identity = id->get_encoding(id);

	/* MK = SHA1( Identity | IK | CK ) */
	f3(this, this->k, this->rand, ck.ptr);
	f4(this, this->k, this->rand, ik.ptr);
	DBG3(DBG_IKE, "Identity %B", &identity);
	tmp = chunk_cata("ccc", identity, ik, ck);
	DBG3(DBG_IKE, "Identity|IK|CK %B", &tmp);
	this->sha1->get_hash(this->sha1, tmp, mk.ptr);

	/* K_encr | K_auth | MSK | EMSK = prf(0) | prf(0)
	 * FIPS PRF has 320 bit block size, we need 160 byte for keys
	 *  => run prf four times */
	this->prf->set_key(this->prf, mk);
	tmp = chunk_alloca(this->prf->get_block_size(this->prf) * 4);
	this->prf->get_bytes(this->prf, chunk_empty, tmp.ptr);
	this->prf->get_bytes(this->prf, chunk_empty, tmp.ptr + tmp.len / 4 * 1);
	this->prf->get_bytes(this->prf, chunk_empty, tmp.ptr + tmp.len / 4 * 2);
	this->prf->get_bytes(this->prf, chunk_empty, tmp.ptr + tmp.len / 4 * 3);
	chunk_free(&this->k_encr);
	chunk_free(&this->k_auth);
	chunk_free(&this->msk);
	chunk_free(&this->emsk);
	chunk_split(tmp, "aaaa", 16, &this->k_encr, 16, &this->k_auth,
				64, &this->msk, 64, &this->emsk);
	DBG3(DBG_IKE, "MK %B", &mk);
	DBG3(DBG_IKE, "PRF res %B", &tmp);
	DBG3(DBG_IKE, "K_encr %B", &this->k_encr);
	DBG3(DBG_IKE, "K_auth %B", &this->k_auth);
	DBG3(DBG_IKE, "MSK %B", &this->msk);
	DBG3(DBG_IKE, "EMSK %B", &this->emsk);
	return TRUE;
}

/*
 * Get a shared key from ipsec.secrets.
 * We use the standard keys as used in preshared key authentication. As
 * these keys have an undefined length, we:
 * - strip them if they are longer
 * - fill them up with '\0' if they are shorter
 */
static status_t load_key(identification_t *me, identification_t *other, chunk_t *k)
{
	shared_key_t *shared;
	chunk_t key;

	shared = charon->credentials->get_shared(charon->credentials, SHARED_EAP,
											 me, other);
	if (shared == NULL)
	{
		return NOT_FOUND;
	}
	key = shared->get_key(shared);
	chunk_free(k);
	*k = chunk_alloc(K_LENGTH);
	memset(k->ptr, '\0', k->len);
	memcpy(k->ptr, key.ptr, min(key.len, k->len));
	shared->destroy(shared);
	return SUCCESS;
}

/**
 * skip EAP_AKA header in message and returns its AKA subtype
 */
static aka_subtype_t read_header(chunk_t *message)
{
	aka_subtype_t type;

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
static aka_attribute_t read_attribute(chunk_t *data, chunk_t *attr_data)
{
	aka_attribute_t attribute;
	size_t length;

	DBG3(DBG_IKE, "reading attribute from %B", data);

	if (data->len < 2)
	{
		return AT_END;
	}
	/* read attribute and length */
	attribute = *data->ptr++;
	length = *data->ptr++ * 4 - 2;
	data->len -= 2;
	DBG3(DBG_IKE, "found attribute %N with length %d",
		 aka_attribute_names, attribute, length);
	if (length > data->len)
	{
		return AT_END;
	}
	/* apply attribute value to attr_data */
	attr_data->len = length;
	attr_data->ptr = data->ptr;
	/* update data to point to next attribute */
	*data = chunk_skip(*data, length);
	return attribute;
}

/**
 * Build an AKA payload from different attributes.
 * The variable argument takes an aka_attribute_t
 * followed by its data in a chunk.
 */
static eap_payload_t *build_aka_payload(private_eap_aka_t *this, eap_code_t code,
										u_int8_t identifier, aka_subtype_t type, ...)
{
	chunk_t message = chunk_alloca(512); /* is enought for all current messages */
	chunk_t pos = message;
	eap_payload_t *payload;
	va_list args;
	aka_attribute_t attr;
	u_int8_t *mac_pos = NULL;

	/* write EAP header, skip length bytes */
	*pos.ptr++ = code;
	*pos.ptr++ = identifier;
	pos.ptr += 2;
	pos.len -= 4;
	/* write AKA header with type and subtype, null reserved bytes */
	*pos.ptr++ = EAP_AKA;
	*pos.ptr++ = type;
	*pos.ptr++ = 0;
	*pos.ptr++ = 0;
	pos.len -= 4;

	va_start(args, type);
	while ((attr = va_arg(args, aka_attribute_t)) != AT_END)
	{
		chunk_t data = va_arg(args, chunk_t);

		DBG3(DBG_IKE, "building %N %B", aka_attribute_names, attr, &data);

		/* write attribute header */
		*pos.ptr++ = attr;
		pos.len--;

		switch (attr)
		{
			case AT_RES:
			{
				/* attribute length in 4byte words */
				*pos.ptr = data.len/4 + 1;
				pos = chunk_skip(pos, 1);
				/* RES length in bits */
				*(u_int16_t*)pos.ptr = htons(data.len * 8);
				pos = chunk_skip(pos, sizeof(u_int16_t));
				memcpy(pos.ptr, data.ptr, data.len);
				pos = chunk_skip(pos, data.len);
				break;
			}
			case AT_AUTN:
			case AT_RAND:
			{
				*pos.ptr++ = data.len/4 + 1; pos.len--;
				*pos.ptr++ = 0; pos.len--;
				*pos.ptr++ = 0; pos.len--;
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
				/* MAC is calculated over message including zeroed AT_MAC attribute */
				memset(mac_pos, 0, AT_MAC_LENGTH);
				pos.ptr += AT_MAC_LENGTH;
				pos.len -= AT_MAC_LENGTH;
				break;
			}
			case AT_IDENTITY:
			{
				u_int16_t act_len = data.len;
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
				*(u_int16_t*)pos.ptr = htons(act_len);
				pos = chunk_skip(pos, sizeof(u_int16_t));
				memcpy(pos.ptr, data.ptr, data.len);
				pos = chunk_skip(pos, data.len);
				break;
			}
			default:
			{
				/* length is data length in 4-bytes + 1 for header */
				*pos.ptr = data.len/4 + 1;
				pos = chunk_skip(pos, 1);
				memcpy(pos.ptr, data.ptr, data.len);
				pos = chunk_skip(pos, data.len);
			}
		}
	}
	va_end(args);

	/* calculate message length, write into header */
	message.len = pos.ptr - message.ptr;
	*(u_int16_t*)(message.ptr + 2) = htons(message.len);

	/* create MAC if AT_MAC attribte was included */
	if (mac_pos)
	{
		this->signer->set_key(this->signer, this->k_auth);
		DBG3(DBG_IKE, "AT_MAC signature of %B", &message);
		DBG3(DBG_IKE, "using key %B", &this->k_auth);
		this->signer->get_signature(this->signer, message, mac_pos);
		DBG3(DBG_IKE, "is %b", mac_pos, AT_MAC_LENGTH);
	}

	/* payload constructor takes data with some bytes skipped */
	payload = eap_payload_create_data(message);

	DBG3(DBG_IKE, "created EAP message %B", &message);
	return payload;
}

/**
 * check if an unknown attribute is skippable
 */
static bool attribute_skippable(aka_attribute_t attribute)
{
	if (attribute >= 0 && attribute <= 127)
	{
		DBG1(DBG_IKE, "ignoring skippable attribute %N",
			 aka_attribute_names, attribute);
		return TRUE;
	}
	return FALSE;
}

/**
 * build the error response if we received an unknown non-skippable attribute
 */
static eap_payload_t *build_non_skippable_error(private_eap_aka_t *this,
								aka_attribute_t attribute, u_char identifier)
{
	DBG1(DBG_IKE, "found non skippable attribute %N, sending %N %d",
		 aka_attribute_names, attribute,
		 aka_attribute_names, AT_CLIENT_ERROR_CODE, 0);
	return build_aka_payload(this, EAP_RESPONSE, identifier, AKA_CLIENT_ERROR,
							 AT_CLIENT_ERROR_CODE, client_error_code, AT_END);
}

/**
 * generate a new non-zero identifier
 */
static u_char get_identifier()
{
	u_char id;

	do {
		id = random();
	} while (!id);
	return id;
}

/**
 * Initiate a AKA-Challenge using SQN
 */
static status_t server_initiate_challenge(private_eap_aka_t *this, chunk_t sqn,
										  eap_payload_t **out)
{
	rng_t *rng;
	chunk_t mac, ak, autn;

	mac = chunk_alloca(MAC_LENGTH);
	ak = chunk_alloca(AK_LENGTH);
	chunk_free(&this->rand);
	chunk_free(&this->xres);

	/* generate RAND:
	 * we use a registered RNG, not f0() proposed in S.S0055
	 */
	rng = lib->crypto->create_rng(lib->crypto, RNG_WEAK);
	if (!rng)
	{
		DBG1(DBG_IKE, "generating RAND for EAP-AKA authentication failed");
		return FAILED;
	}
	rng->allocate_bytes(rng, RAND_LENGTH, &this->rand);
	rng->destroy(rng);

#	ifdef TEST_VECTORS
	/* Test vector for RAND */
	u_int8_t test_rand[] = {
		0x4b,0x05,0x2b,0x20,0xe2,0xa0,0x6c,0x8f,
		0xf7,0x00,0xda,0x51,0x2b,0x4e,0x11,0x1e,
	};
	memcpy(this->rand.ptr, test_rand, this->rand.len);
#	endif /* TEST_VECTORS */

	/* Get the shared key K: */
	if (load_key(this->server, this->peer, &this->k) != SUCCESS)
	{
		DBG1(DBG_IKE, "no shared key found for IDs '%Y' - '%Y' to authenticate "
				"with EAP-AKA", this->server, this->peer);
		return FAILED;
	}

#	ifdef TEST_VECTORS
	/* Test vector for K */
	u_int8_t test_k[] = {
		0xad,0x1b,0x5a,0x15,0x9b,0xe8,0x6b,0x2c,
		0xa6,0x6c,0x7a,0xe4,0x0b,0xba,0x9b,0x9d,
	};
	memcpy(this->k.ptr, test_k, this->k.len);
#	endif /* TEST_VECTORS */

	/* generate MAC */
	f1(this, this->k, this->rand, sqn, amf, mac.ptr);

	/* generate AK */
	f5(this, this->k, this->rand, ak.ptr);

	/* precalculate XRES as expected from client */
	this->xres = chunk_alloc(RES_LENGTH);
	f2(this, this->k, this->rand, this->xres.ptr);

	/* calculate AUTN = (SQN xor AK) || AMF || MAC */
	autn = chunk_cata("ccc", sqn, amf, mac);
	memxor(autn.ptr, ak.ptr, ak.len);
	DBG3(DBG_IKE, "AUTN %B", &autn);


	/* derive K_encr, K_auth, MSK, EMSK  */
	derive_keys(this, this->peer);

	/* build payload */
	*out = build_aka_payload(this, EAP_REQUEST, get_identifier(), AKA_CHALLENGE,
							 AT_RAND, this->rand, AT_AUTN, autn, AT_MAC,
							 chunk_empty, AT_END);
	return NEED_MORE;
}

/**
 * Implementation of eap_method_t.initiate for an EAP_AKA server
 */
static status_t server_initiate(private_eap_aka_t *this, eap_payload_t **out)
{
	chunk_t sqn = chunk_alloca(SQN_LENGTH);

	/* we use an offset of 3 minutes to tolerate clock inaccuracy
	 * without the need to synchronize sequence numbers */
	update_sqn(sqn.ptr, 180);

#	ifdef TEST_VECTORS
	/* Test vector for SQN */
	u_int8_t test_sqn[] = {0x00,0x00,0x00,0x00,0x00,0x01};
	memcpy(sqn.ptr, test_sqn, sqn.len);
#	endif /* TEST_VECTORS */

	return server_initiate_challenge(this, sqn, out);
}

static status_t server_process_synchronize(private_eap_aka_t *this,
										   eap_payload_t *in, eap_payload_t **out)
{
	chunk_t attr, auts = chunk_empty, pos, message, macs, xmacs, sqn, aks, amf;
	u_int i;

	message = in->get_data(in);
	pos = message;
	read_header(&pos);

	/* iterate over attributes */
	while (TRUE)
	{
		aka_attribute_t attribute = read_attribute(&pos, &attr);
		switch (attribute)
		{
			case AT_END:
				break;
			case AT_AUTS:
				auts = attr;
				continue;
			default:
				if (attribute_skippable(attribute))
				{
					continue;
				}
				DBG1(DBG_IKE, "found non skippable attribute %N",
					 aka_attribute_names, attribute);
				return FAILED;
		}
		break;
	}

	if (auts.len != AUTS_LENGTH)
	{
		DBG1(DBG_IKE, "synchronization request didn't contain useable AUTS");
		return FAILED;
	}

	chunk_split(auts, "mm", SQN_LENGTH, &sqn, MAC_LENGTH, &macs);
	aks = chunk_alloca(AK_LENGTH);
	f5star(this, this->k, this->rand, aks.ptr);
	/* decrypt serial number by XORing AKS */
	memxor(sqn.ptr, aks.ptr, aks.len);

	/* verify MACS */
	xmacs = chunk_alloca(MAC_LENGTH);
	amf = chunk_alloca(AMF_LENGTH);
	/* an AMF of zero is used for MACS calculation */
	memset(amf.ptr, 0, amf.len);
	f1star(this, this->k, this->rand, sqn, amf, xmacs.ptr);
	if (!chunk_equals(macs, xmacs))
	{
		DBG1(DBG_IKE, "received MACS does not match XMACS");
		DBG3(DBG_IKE, "MACS %B XMACS %B", &macs, &xmacs);
		return FAILED;
	}

	/* retry the challenge with the received SQN + 1*/
	for (i = SQN_LENGTH - 1; i >= 0; i--)
	{
		if (++sqn.ptr[i] != 0)
		{
			break;
		}
	}
	return server_initiate_challenge(this, sqn, out);
}

/**
 * process an AKA_Challenge response
 */
static status_t server_process_challenge(private_eap_aka_t *this, eap_payload_t *in)
{
	chunk_t attr, res = chunk_empty, at_mac = chunk_empty, pos, message;

	message = in->get_data(in);
	pos = message;
	read_header(&pos);

	/* iterate over attributes */
	while (TRUE)
	{
		aka_attribute_t attribute = read_attribute(&pos, &attr);
		switch (attribute)
		{
			case AT_END:
				break;
			case AT_RES:
				res = attr;
				if (attr.len == 2 + RES_LENGTH &&
					*(u_int16_t*)attr.ptr == htons(RES_LENGTH * 8))
				{
					res = chunk_skip(attr, 2);
				}
				continue;

			case AT_MAC:
				attr = chunk_skip(attr, 2);
				at_mac = chunk_clonea(attr);
				/* zero MAC in message for MAC verification */
				memset(attr.ptr, 0, attr.len);
				continue;
			default:
				if (attribute_skippable(attribute))
				{
					continue;
				}
				DBG1(DBG_IKE, "found non skippable attribute %N",
					 aka_attribute_names, attribute);
				return FAILED;
		}
		break;
	}

	/* verify EAP message MAC AT_MAC */
	{
		this->signer->set_key(this->signer, this->k_auth);
		DBG3(DBG_IKE, "verifying AT_MAC signature of %B", &message);
		DBG3(DBG_IKE, "using key %B", &this->k_auth);
		if (!this->signer->verify_signature(this->signer, message, at_mac))
		{
			DBG1(DBG_IKE, "MAC in AT_MAC attribute verification failed");
			return FAILED;
		}
	}

	/* compare received RES against stored precalculated XRES */
	if (!chunk_equals(res, this->xres))
	{
		DBG1(DBG_IKE, "received RES does not match XRES");
		DBG3(DBG_IKE, "RES %Bb XRES %B", &res, &this->xres);
		return FAILED;
	}
	return SUCCESS;
}

/**
 * Implementation of eap_method_t.process for EAP_AKA servers
 */
static status_t server_process(private_eap_aka_t *this,
							   eap_payload_t *in, eap_payload_t **out)
{
	chunk_t message;
	aka_subtype_t type;

	message = in->get_data(in);
	type = read_header(&message);

	DBG3(DBG_IKE, "received EAP message %B",  &message);

	switch (type)
	{
		case AKA_CHALLENGE:
		{
			return server_process_challenge(this, in);
		}
		case AKA_AUTHENTICATION_REJECT:
		case AKA_CLIENT_ERROR:
		{
			DBG1(DBG_IKE, "received %N, authentication failed",
				 aka_subtype_names, type);
			return FAILED;
		}
		case AKA_SYNCHRONIZATION_FAILURE:
		{
			DBG1(DBG_IKE, "received %N, retrying with received SQN",
				 aka_subtype_names, type);
			return server_process_synchronize(this, in, out);
		}
		default:
			DBG1(DBG_IKE, "received unknown AKA subtype %N, authentication failed",
				 aka_subtype_names, type);
			return FAILED;
	}
}

/**
 * Process an incoming AKA-Challenge client side
 */
static status_t peer_process_challenge(private_eap_aka_t *this,
									   eap_payload_t *in, eap_payload_t **out)
{
	chunk_t attr = chunk_empty;
	chunk_t autn = chunk_empty, at_mac = chunk_empty;
	chunk_t ak, sqn, sqn_ak, mac, xmac, res, amf, message, pos;
	u_int8_t identifier;

	ak = chunk_alloca(AK_LENGTH);
	xmac = chunk_alloca(MAC_LENGTH);
	res = chunk_alloca(RES_LENGTH);
	chunk_free(&this->rand);

	message = in->get_data(in);
	pos = message;
	read_header(&pos);
	identifier = in->get_identifier(in);

	DBG3(DBG_IKE, "reading attributes from %B", &pos);

	/* iterate over attributes */
	while (TRUE)
	{
		aka_attribute_t attribute = read_attribute(&pos, &attr);
		switch (attribute)
		{
			case AT_END:
				break;
			case AT_RAND:
				this->rand = chunk_clone(chunk_skip(attr, 2));
				continue;
			case AT_AUTN:
				autn = chunk_skip(attr, 2);
				continue;
			case AT_MAC:
				attr = chunk_skip(attr, 2);
				at_mac = chunk_clonea(attr);
				/* set MAC in message to zero for own MAC verification */
				memset(attr.ptr, 0, attr.len);
				continue;
			default:
				if (attribute_skippable(attribute))
				{
					continue;
				}
				*out = build_non_skippable_error(this, attribute, identifier);
				return NEED_MORE;
		}
		break;
	}

	if (this->rand.len != RAND_LENGTH || autn.len != AUTN_LENGTH)
	{
		/* required attributes wrong/not found, abort */
		*out = build_aka_payload(this, EAP_RESPONSE, identifier, AKA_CLIENT_ERROR,
					AT_CLIENT_ERROR_CODE, client_error_code, AT_END);
		DBG1(DBG_IKE, "could not find valid RAND/AUTN attribute, sending %N %d",
			 aka_attribute_names, AT_CLIENT_ERROR_CODE, 0);
		return NEED_MORE;
	}

	DBG3(DBG_IKE, "using autn %B", &autn);
	/* split up AUTN = SQN xor AK | AMF | MAC */
	chunk_split(autn, "mmm", SQN_LENGTH, &sqn_ak, AMF_LENGTH, &amf, MAC_LENGTH, &mac);

	/* Get the shared key K: */
	chunk_free(&this->k);
	if (load_key(this->peer, this->server, &this->k) != SUCCESS)
	{
		*out = build_aka_payload(this, EAP_RESPONSE, identifier,
								 AKA_AUTHENTICATION_REJECT, AT_END);
		DBG3(DBG_IKE, "no shared key found for IDs '%Y' - '%Y' to authenticate "
			 "with EAP-AKA, sending %N", this->peer, this->server,
			 aka_subtype_names, AKA_AUTHENTICATION_REJECT);
		return NEED_MORE;
	}
	DBG3(DBG_IKE, "using K %B", &this->k);
#	ifdef TEST_VECTORS
	/* Test vector for K */
	u_int8_t test_k[] = {
		0xad,0x1b,0x5a,0x15,0x9b,0xe8,0x6b,0x2c,
		0xa6,0x6c,0x7a,0xe4,0x0b,0xba,0x9b,0x9d,
	};
	memcpy(this->k.ptr, test_k, this->k.len);
#	endif /* TEST_VECTORS */

	/* calculate anonymity key AK */
	f5(this, this->k, this->rand, ak.ptr);
	DBG3(DBG_IKE, "using rand %B", &this->rand);
	DBG3(DBG_IKE, "using ak %B", &ak);
	/* XOR AK into SQN to decrypt it */

	sqn = chunk_clonea(sqn_ak);

	DBG3(DBG_IKE, "using ak xor sqn %B", &sqn_ak);
	memxor(sqn.ptr, ak.ptr, sqn.len);
	DBG3(DBG_IKE, "using sqn %B", &sqn);

	/* calculate expected MAC and compare against received one */
	f1(this, this->k, this->rand, sqn, amf, xmac.ptr);
	if (!chunk_equals(mac, xmac))
	{
		*out = build_aka_payload(this, EAP_RESPONSE, identifier,
								 AKA_AUTHENTICATION_REJECT, AT_END);
		DBG1(DBG_IKE, "received MAC does not match XMAC, sending %N",
			 aka_subtype_names, AKA_AUTHENTICATION_REJECT);
		DBG3(DBG_IKE, "MAC %B\nXMAC %B", &mac, &xmac);
		return NEED_MORE;
	}

#if SEQ_CHECK
	if (memcmp(peer_sqn.ptr, sqn.ptr, sqn.len) >= 0)
	{
		/* sequence number invalid. send AUTS */
		chunk_t auts, macs, aks, amf;

		macs = chunk_alloca(MAC_LENGTH);
		aks = chunk_alloca(AK_LENGTH);
		amf = chunk_alloca(AMF_LENGTH);

		/* AMF is set to zero in AKA_SYNCHRONIZATION_FAILURE */
		memset(amf.ptr, 0, amf.len);
		/* AKS = f5*(RAND) */
		f5star(this, this->k, this->rand, aks.ptr);
		/* MACS = f1*(RAND) */
		f1star(this, this->k, this->rand, peer_sqn, amf, macs.ptr);
		/* AUTS = SQN xor AKS | MACS */
		memxor(aks.ptr, peer_sqn.ptr, aks.len);
		auts = chunk_cata("cc", aks, macs);

		*out = build_aka_payload(this, EAP_RESPONSE, identifier,
								 AKA_SYNCHRONIZATION_FAILURE,
								 AT_AUTS, auts, AT_END);
		DBG1(DBG_IKE, "received SQN invalid, sending %N",
			 aka_subtype_names, AKA_SYNCHRONIZATION_FAILURE);
		DBG3(DBG_IKE, "received SQN %B\ncurrent SQN %B", &sqn, &peer_sqn);
		return NEED_MORE;
	}
#endif /* SEQ_CHECK */

	/* derive K_encr, K_auth, MSK, EMSK  */
	derive_keys(this, this->peer);

	/* verify EAP message MAC AT_MAC */
	DBG3(DBG_IKE, "verifying AT_MAC signature of %B", &message);
	DBG3(DBG_IKE, "using key %B", &this->k_auth);
	this->signer->set_key(this->signer, this->k_auth);
	if (!this->signer->verify_signature(this->signer, message, at_mac))
	{
		*out = build_aka_payload(this, EAP_RESPONSE, identifier, AKA_CLIENT_ERROR,
						AT_CLIENT_ERROR_CODE, client_error_code, AT_END);
		DBG1(DBG_IKE, "MAC in AT_MAC attribute verification "
			 "failed, sending %N %d", aka_attribute_names,
			 AT_CLIENT_ERROR_CODE, 0);
		return NEED_MORE;
	}

	/* update stored SQN to the received one */
	memcpy(peer_sqn.ptr, sqn.ptr, sqn.len);

	/* calculate RES */
	f2(this, this->k, this->rand, res.ptr);

	/* build response */
	*out = build_aka_payload(this, EAP_RESPONSE, identifier, AKA_CHALLENGE,
							 AT_RES, res, AT_MAC, chunk_empty, AT_END);
	return NEED_MORE;
}

/**
 * Process an incoming AKA-Identity client side
 */
static status_t peer_process_identity(private_eap_aka_t *this,
									  eap_payload_t *in, eap_payload_t **out)
{
	chunk_t identity = chunk_empty, message, pos, attr;
	u_int8_t identifier;

	identifier = in->get_identifier(in);
	pos = message = in->get_data(in);
	read_header(&pos);

	DBG3(DBG_IKE, "reading attributes from %B", &pos);

	/* iterate over attributes */
	while (TRUE)
	{
		aka_attribute_t attribute = read_attribute(&pos, &attr);

		switch (attribute)
		{
			case AT_END:
				break;
			case AT_PERMANENT_ID_REQ:
			case AT_FULLAUTH_ID_REQ:
			case AT_ANY_ID_REQ:
				/* always respond with full identity */
				identity = this->peer->get_encoding(this->peer);
				DBG1(DBG_IKE, "server requested %N, sending '%Y'",
					 aka_attribute_names, attribute, this->peer);
				continue;
			default:
				if (attribute_skippable(attribute))
				{
					continue;
				}
				*out = build_non_skippable_error(this, attribute, identifier);
				return NEED_MORE;
		}
		break;
	}

	/* build response */
	*out = build_aka_payload(this, EAP_RESPONSE, identifier, AKA_IDENTITY,
							 AT_IDENTITY, identity, AT_END);
	return NEED_MORE;
}

/**
 * Process an incoming AKA-Notification as client
 */
static status_t peer_process_notification(private_eap_aka_t *this,
										  eap_payload_t *in, eap_payload_t **out)
{
	chunk_t message, pos, attr;
	u_int8_t identifier;

	message = in->get_data(in);
	pos = message;
	read_header(&pos);
	identifier = in->get_identifier(in);

	DBG3(DBG_IKE, "reading attributes from %B", &pos);

	/* iterate over attributes */
	while (TRUE)
	{
		aka_attribute_t attribute = read_attribute(&pos, &attr);
		switch (attribute)
		{
			case AT_END:
				break;
			case AT_NOTIFICATION:
			{
				u_int16_t code;

				if (attr.len != 2)
				{
					DBG1(DBG_IKE, "received invalid AKA notification, ignored");
					continue;
				}
				code = ntohs(*(u_int16_t*)attr.ptr);
				switch (code)
				{
					case 0:
						DBG1(DBG_IKE, "received AKA notification 'general "
							 "failure after authentication' (%d)", code);
						return FAILED;
					case 16384:
						DBG1(DBG_IKE, "received AKA notification 'general "
							 "failure' (%d)", code);
						return FAILED;
					case 32768:
						DBG1(DBG_IKE, "received AKA notification 'successfully "
							 "authenticated' (%d)", code);
						continue;
					case 1026:
						DBG1(DBG_IKE, "received AKA notification 'access "
							 "temporarily denied' (%d)", code);
						return FAILED;
					case 1031:
						DBG1(DBG_IKE, "received AKA notification 'not "
							 "subscribed to service' (%d)", code);
						return FAILED;
					default:
						DBG1(DBG_IKE, "received AKA notification code %d, "
							 "ignored", code);
					continue;
				}
			}
			default:
				if (!attribute_skippable(attribute))
				{
					DBG1(DBG_IKE, "ignoring non-skippable attribute %N in %N",
						 aka_attribute_names, attribute, aka_subtype_names,
						 AKA_NOTIFICATION);
				}
				continue;
		}
		break;
	}
	return NEED_MORE;
}

/**
 * Implementation of eap_method_t.process for an EAP_AKA peer
 */
static status_t peer_process(private_eap_aka_t *this,
							 eap_payload_t *in, eap_payload_t **out)
{
	aka_subtype_t type;
	chunk_t message;
	u_int8_t identifier;

	message = in->get_data(in);
	type = read_header(&message);
	identifier = in->get_identifier(in);

	DBG3(DBG_IKE, "received EAP message %B",  &message);

	switch (type)
	{
		case AKA_CHALLENGE:
		{
			return peer_process_challenge(this, in, out);
		}
		case AKA_IDENTITY:
		{
			return peer_process_identity(this, in, out);
		}
		case AKA_NOTIFICATION:
		{
			return peer_process_notification(this, in, out);
		}
		default:
		{
			*out = build_aka_payload(this, EAP_RESPONSE, identifier, AKA_CLIENT_ERROR,
						AT_CLIENT_ERROR_CODE, client_error_code, AT_END);
			DBG1(DBG_IKE, "received unsupported %N request, sending %N %d",
				 aka_subtype_names, type,
				 aka_attribute_names, AT_CLIENT_ERROR_CODE, 0);
			return NEED_MORE;
		}
	}
}

/**
 * Implementation of eap_method_t.initiate for an EAP AKA peer
 */
static status_t peer_initiate(private_eap_aka_t *this, eap_payload_t **out)
{
	/* peer never initiates */
	return FAILED;
}

/**
 * Implementation of eap_method_t.get_type.
 */
static eap_type_t get_type(private_eap_aka_t *this, u_int32_t *vendor)
{
	*vendor = 0;
	return EAP_AKA;
}

/**
 * Implementation of eap_method_t.get_msk.
 */
static status_t get_msk(private_eap_aka_t *this, chunk_t *msk)
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
static bool is_mutual(private_eap_aka_t *this)
{
	return TRUE;
}

/**
 * Implementation of eap_method_t.destroy.
 */
static void destroy(private_eap_aka_t *this)
{
	this->server->destroy(this->server);
	this->peer->destroy(this->peer);
	DESTROY_IF(this->sha1);
	DESTROY_IF(this->signer);
	DESTROY_IF(this->prf);
	DESTROY_IF(this->keyed_prf);
	chunk_free(&this->k_encr);
	chunk_free(&this->k_auth);
	chunk_free(&this->msk);
	chunk_free(&this->emsk);
	chunk_free(&this->xres);
	chunk_free(&this->k);
	chunk_free(&this->rand);
	free(this);
}

/**
 * generic constructor used by client & server
 */
static private_eap_aka_t *eap_aka_create_generic(identification_t *server,
												 identification_t *peer)
{
	private_eap_aka_t *this = malloc_thing(private_eap_aka_t);

	this->public.eap_method_interface.initiate = NULL;
	this->public.eap_method_interface.process = NULL;
	this->public.eap_method_interface.get_type = (eap_type_t(*)(eap_method_t*,u_int32_t*))get_type;
	this->public.eap_method_interface.is_mutual = (bool(*)(eap_method_t*))is_mutual;
	this->public.eap_method_interface.get_msk = (status_t(*)(eap_method_t*,chunk_t*))get_msk;
	this->public.eap_method_interface.destroy = (void(*)(eap_method_t*))destroy;

	/* private data */
	this->server = server->clone(server);
	this->peer = peer->clone(peer);
	this->k_encr = chunk_empty;
	this->k_auth = chunk_empty;
	this->msk = chunk_empty;
	this->emsk = chunk_empty;
	this->xres = chunk_empty;
	this->k = chunk_empty;
	this->rand = chunk_empty;

	this->sha1 = lib->crypto->create_hasher(lib->crypto, HASH_SHA1);
	this->signer = lib->crypto->create_signer(lib->crypto, AUTH_HMAC_SHA1_128);
	this->prf = lib->crypto->create_prf(lib->crypto, PRF_FIPS_SHA1_160);
	this->keyed_prf = lib->crypto->create_prf(lib->crypto, PRF_KEYED_SHA1);

	if (!this->sha1 || !this->signer || !this->prf || !this->keyed_prf)
	{
		DBG1(DBG_IKE, "unable to initiate EAP-AKA, FIPS-PRF/SHA1 not supported");
		DESTROY_IF(this->sha1);
		DESTROY_IF(this->signer);
		DESTROY_IF(this->prf);
		DESTROY_IF(this->keyed_prf);
		destroy(this);
		return NULL;
	}
	return this;
}

/*
 * Described in header.
 */
eap_aka_t *eap_aka_create_server(identification_t *server, identification_t *peer)
{
	private_eap_aka_t *this = eap_aka_create_generic(server, peer);

	if (this)
	{
		this->public.eap_method_interface.initiate = (status_t(*)(eap_method_t*,eap_payload_t**))server_initiate;
		this->public.eap_method_interface.process = (status_t(*)(eap_method_t*,eap_payload_t*,eap_payload_t**))server_process;
	}
	return (eap_aka_t*)this;
}

/*
 * Described in header.
 */
eap_aka_t *eap_aka_create_peer(identification_t *server, identification_t *peer)
{
	private_eap_aka_t *this = eap_aka_create_generic(server, peer);

	if (this)
	{
		this->public.eap_method_interface.initiate = (status_t(*)(eap_method_t*,eap_payload_t**))peer_initiate;
		this->public.eap_method_interface.process = (status_t(*)(eap_method_t*,eap_payload_t*,eap_payload_t**))peer_process;
	}
	return (eap_aka_t*)this;
}

