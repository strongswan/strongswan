/*
 * Copyright (C) 2016-2019 Tobias Brunner
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

package org.strongswan.android.ui.adapter;

import android.content.Context;
import android.widget.ArrayAdapter;

import org.strongswan.android.security.TrustedCertificateEntry;

public class CertificateIdentitiesAdapter extends ArrayAdapter<String>
{
	TrustedCertificateEntry mCertificate;

	public CertificateIdentitiesAdapter(Context context)
	{
		super(context, android.R.layout.simple_dropdown_item_1line);
		extractIdentities();
	}

	/**
	 * Set a new certificate for this adapter.
	 *
	 * @param certificate the certificate to extract identities from (null to clear)
	 */
	public void setCertificate(TrustedCertificateEntry certificate)
	{
		mCertificate = certificate;
		clear();
		extractIdentities();
	}

	private void extractIdentities()
	{
		if (mCertificate != null)
		{
			addAll(mCertificate.getSubjectAltNames());
		}
	}
}
