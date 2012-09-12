/*
 * Copyright (C) 2012 Reto Buerki
 * Copyright (C) 2012 Adrian-Ken Rueegsegger
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

#include <check.h>
#include <daemon.h>
#include <hydra.h>
#include <config/proposal.h>
#include <encoding/payloads/ike_header.h>
#include <plugins/kernel_netlink/kernel_netlink_net.h>
#include <tkm/client.h>

#include "tkm.h"
#include "tkm_nonceg.h"
#include "tkm_diffie_hellman.h"
#include "tkm_keymat.h"
#include "tkm_kernel_ipsec.h"

START_TEST(test_derive_ike_keys)
{
	fail_if(!library_init(NULL), "Unable to init library");
	fail_if(!libhydra_init("tkm-tests"), "Unable to init libhydra");
	fail_if(!libcharon_init("tkm-tests"), "Unable to init libcharon");

	/* Register TKM specific plugins */
	static plugin_feature_t features[] = {
		PLUGIN_REGISTER(NONCE_GEN, tkm_nonceg_create),
			PLUGIN_PROVIDE(NONCE_GEN),
		PLUGIN_REGISTER(DH, tkm_diffie_hellman_create),
			PLUGIN_PROVIDE(DH, MODP_3072_BIT),
			PLUGIN_PROVIDE(DH, MODP_4096_BIT),
		PLUGIN_CALLBACK(kernel_ipsec_register, tkm_kernel_ipsec_create),
			PLUGIN_PROVIDE(CUSTOM, "kernel-ipsec"),
			PLUGIN_DEPENDS(RNG, RNG_WEAK),
		PLUGIN_CALLBACK(kernel_net_register, kernel_netlink_net_create),
			PLUGIN_PROVIDE(CUSTOM, "kernel-net"),
	};
	lib->plugins->add_static_features(lib->plugins, "tkm-tests", features,
			countof(features), TRUE);

	fail_if(!charon->initialize(charon, PLUGINS), "Unable to init charon");

	proposal_t *proposal = proposal_create_from_string(PROTO_IKE,
			"aes256-sha512-modp4096");
	fail_if(!proposal, "Unable to create proposal");
	ike_sa_id_t *ike_sa_id = ike_sa_id_create(IKEV2_MAJOR_VERSION,
			123912312312, 32312313122, TRUE);
	fail_if(!ike_sa_id, "Unable to create IKE SA ID");

	tkm_keymat_t *keymat = tkm_keymat_create(TRUE);
	fail_if(!keymat, "Unable to create keymat");
	fail_if(!keymat->get_isa_id(keymat), "Invalid ISA context id (0)");

	chunk_t nonce;
	tkm_nonceg_t *ng = tkm_nonceg_create();
	fail_if(!ng, "Unable to create nonce generator");
	fail_unless(ng->nonce_gen.allocate_nonce(&ng->nonce_gen, 32, &nonce),
			"Unable to allocate nonce");
	ng->nonce_gen.destroy(&ng->nonce_gen);

	tkm_diffie_hellman_t *dh = tkm_diffie_hellman_create(MODP_4096_BIT);
	fail_if(!dh, "Unable to create DH");

	/* Use the same pubvalue for both sides */
	chunk_t pubvalue;
	dh->dh.get_my_public_value(&dh->dh, &pubvalue);
	dh->dh.set_other_public_value(&dh->dh, pubvalue);

	fail_unless(keymat->derive_ike_keys(keymat, proposal, &dh->dh, nonce, nonce,
				ike_sa_id, PRF_UNDEFINED, chunk_empty), "Key derivation failed");
	chunk_free(&nonce);

	aead_t * const aead = keymat->keymat.get_aead(&keymat->keymat, TRUE);
	fail_if(!aead, "AEAD is NULL");

	fail_if(aead->get_key_size(aead) != 96, "Key size mismatch %d",
			aead->get_key_size(aead));
	fail_if(aead->get_block_size(aead) != 16, "Block size mismatch %d",
			aead->get_block_size(aead));

	proposal->destroy(proposal);
	dh->dh.destroy(&dh->dh);
	ike_sa_id->destroy(ike_sa_id);
	keymat->keymat.destroy(&keymat->keymat);
	chunk_free(&pubvalue);

	libcharon_deinit();
	libhydra_deinit();
	library_deinit();
}
END_TEST

TCase *make_keymat_tests(void)
{
	TCase *tc = tcase_create("Keymat tests");
	tcase_add_test(tc, test_derive_ike_keys);

	return tc;
}
