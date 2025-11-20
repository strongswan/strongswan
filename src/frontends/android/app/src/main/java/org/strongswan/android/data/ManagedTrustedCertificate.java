/*
 * Copyright (C) 2023 Relution GmbH
 *
 * Copyright (C) secunet Security Networks AG
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

package org.strongswan.android.data;

import android.database.Cursor;

import org.strongswan.android.utils.Certificates;

import java.security.KeyStore;
import java.security.cert.X509Certificate;
import java.util.Objects;

import androidx.annotation.NonNull;

public class ManagedTrustedCertificate extends ManagedCertificate
{
	public ManagedTrustedCertificate(
		@NonNull final String vpnProfileUuid,
		@NonNull final String data)
	{
		super(vpnProfileUuid, determineAlias(vpnProfileUuid, data), data);
	}

	public ManagedTrustedCertificate(@NonNull final Cursor cursor)
	{
		super(cursor);
	}

	private static String determineAlias(String vpnProfileUuid, String data)
	{
		/* fallback in case the certificate is invalid */
		String certAlias = "trusted:" + vpnProfileUuid;
		try
		{
			X509Certificate cert = Certificates.from(data);
			KeyStore store = KeyStore.getInstance("LocalCertificateStore");
			store.load(null, null);
			certAlias = store.getCertificateAlias(cert);
		}
		catch (Exception e)
		{
			e.printStackTrace();
		}
		return certAlias;
	}

	@Override
	public boolean equals(Object o)
	{
		if (this == o)
		{
			return true;
		}
		if (o == null || getClass() != o.getClass())
		{
			return false;
		}
		ManagedTrustedCertificate that = (ManagedTrustedCertificate)o;
		return Objects.equals(vpnProfileUuid, that.vpnProfileUuid) &&
			   Objects.equals(data, that.data);
	}

	@Override
	public int hashCode()
	{
		return Objects.hash(vpnProfileUuid, data);
	}

	@NonNull
	@Override
	public String toString()
	{
		return "ManagedTrustedCertificate {" + vpnProfileUuid + ", " + alias + "}";
	}
}
