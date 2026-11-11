/*
 * Copyright (C) 2026 raghu netrakar
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

#include "test_suite.h"

#include <tpm_tss_quote_info.h>

/* TPML_PCR_SELECTION with a single SHA-256 bank and a 3 byte bitmap */
#define PCR_SELECTION(b0, b1, b2) \
	0x00,0x00,0x00,0x01, 0x00,0x0b, 0x03, b0,b1,b2

static struct {
	chunk_t pcr_select;
	bool valid;
} tpm2_select_tests[] = {
	/* PCR 10, which is what the verifier evaluated */
	{ chunk_from_chars(PCR_SELECTION(0x00,0x04,0x00)), TRUE  },
	/* PCR 16, resettable, the same value could be replayed into it */
	{ chunk_from_chars(PCR_SELECTION(0x00,0x00,0x01)), FALSE },
	/* PCR 23, also resettable */
	{ chunk_from_chars(PCR_SELECTION(0x00,0x00,0x80)), FALSE },
	/* PCRs 10 and 16 */
	{ chunk_from_chars(PCR_SELECTION(0x00,0x04,0x01)), FALSE },
	/* no PCRs */
	{ chunk_from_chars(PCR_SELECTION(0x00,0x00,0x00)), FALSE },
	/* two banks */
	{ chunk_from_chars(0x00,0x00,0x00,0x02, 0x00,0x0b, 0x03, 0x00,0x04,0x00),
	  FALSE },
	/* longer bitmap */
	{ chunk_from_chars(0x00,0x00,0x00,0x01, 0x00,0x0b, 0x04,
					   0x00,0x04,0x00,0x00), FALSE },
	/* truncated bitmap */
	{ chunk_from_chars(0x00,0x00,0x00,0x01, 0x00,0x0b, 0x03, 0x00,0x04),
	  FALSE },
	/* trailing data */
	{ chunk_from_chars(PCR_SELECTION(0x00,0x04,0x00), 0x00), FALSE },
	/* empty */
	{ { NULL, 0 }, FALSE },
};

START_TEST(test_imcv_quote_tpm2_pcr_select)
{
	tpm_tss_pcr_composite_t composite = {
		.pcr_select = chunk_from_chars(0x00,0x04,0x00),
		.pcr_composite = chunk_alloca(HASH_SIZE_SHA256),
	};
	tpm_tss_quote_info_t *quote_info;
	hasher_t *hasher;
	chunk_t nonce = chunk_from_chars(0x01,0x02,0x03,0x04), digest, quoted;
	bool success;

	memset(composite.pcr_composite.ptr, 0xaa, composite.pcr_composite.len);

	hasher = lib->crypto->create_hasher(lib->crypto, HASH_SHA256);
	ck_assert(hasher);
	ck_assert(hasher->allocate_hash(hasher, composite.pcr_composite, &digest));
	hasher->destroy(hasher);

	quote_info = tpm_tss_quote_info_create(TPM_QUOTE_TPM2, HASH_SHA256, digest);
	quote_info->set_tpm2_info(quote_info, chunk_from_chars(0x05),
							  chunk_from_chars(0x06),
							  tpm2_select_tests[_i].pcr_select);
	quote_info->set_version_info(quote_info, chunk_from_chars(0x07));

	success = quote_info->get_quote(quote_info, nonce, &composite, &quoted);
	ck_assert(success == tpm2_select_tests[_i].valid);
	if (success)
	{
		chunk_free(&quoted);
	}
	quote_info->destroy(quote_info);
	chunk_free(&digest);
}
END_TEST

Suite *imcv_quote_suite_create()
{
	Suite *s;
	TCase *tc;

	s = suite_create("imcv_quote");

	tc = tcase_create("tpm2_pcr_select");
	tcase_add_loop_test(tc, test_imcv_quote_tpm2_pcr_select, 0,
						countof(tpm2_select_tests));
	suite_add_tcase(s, tc);

	return s;
}
