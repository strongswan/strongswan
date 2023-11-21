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

import org.strongswan.android.logic.TrustedCertificateManager;

import java.security.cert.X509Certificate;

import androidx.annotation.NonNull;
import androidx.annotation.Nullable;

public class ManagedTrustedCertificateRepository extends ManagedCertificateRepository<ManagedTrustedCertificate>
{
	private static final DatabaseHelper.DbTable TABLE = DatabaseHelper.TABLE_TRUSTED_CERTIFICATE;

	public ManagedTrustedCertificateRepository(
		@NonNull final ManagedConfigurationService managedConfigurationService,
		@NonNull final DatabaseHelper databaseHelper)
	{
		super(managedConfigurationService, databaseHelper, TABLE);
	}

	@Nullable
	@Override
	protected ManagedTrustedCertificate getCertificate(@NonNull ManagedVpnProfile vpnProfile)
	{
		return vpnProfile.getTrustedCertificate();
	}

	@NonNull
	@Override
	protected ManagedTrustedCertificate createCertificate(@NonNull Cursor cursor)
	{
		return new ManagedTrustedCertificate(cursor);
	}

	@Override
	protected boolean isInstalled(@NonNull ManagedTrustedCertificate certificate)
	{
		TrustedCertificateManager certificateManager = TrustedCertificateManager.getInstance();
		final X509Certificate x509Certificate = certificateManager.getCACertificateFromAlias(certificate.getAlias());

		return x509Certificate != null;
	}
}
