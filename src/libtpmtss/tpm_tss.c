/*
 * Copyright (C) 2016 Andreas Steffen
 * HSR Hochschule fuer Technik Rapperswil
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

#include "tpm_tss.h"
#include "tpm_tss_tss2.h"
#include "tpm_tss_trousers.h"

/**
 * Described in header.
 */
void libtpmtss_init(void)
{
	/* empty */
}

typedef tpm_tss_t*(*tpm_tss_create)();

/**
 * See header.
 */
tpm_tss_t *tpm_tss_probe(tpm_version_t version)
{
	tpm_tss_create stacks[] = {
		tpm_tss_tss2_create,
		tpm_tss_trousers_create,
	};
	tpm_tss_t *tpm;
	int i;

	for (i = 0; i < countof(stacks); i++)
	{
		tpm = stacks[i]();
		if (tpm)
		{
			if (version == TPM_VERSION_ANY || version == tpm->get_version(tpm))
			{
				return tpm;
			}
		}
	}
	return NULL;
}
