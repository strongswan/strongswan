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

import android.app.admin.DevicePolicyManager;
import android.database.Cursor;
import android.os.Build;

import androidx.annotation.NonNull;
import androidx.annotation.Nullable;

public class ManagedUserCertificateRepository extends ManagedCertificateRepository<ManagedUserCertificate>
{
	private static final DatabaseHelper.DbTable TABLE = DatabaseHelper.TABLE_USER_CERTIFICATE;

	@NonNull
	private final DevicePolicyManager devicePolicyManager;

	public ManagedUserCertificateRepository(
		@NonNull final ManagedConfigurationService managedConfigurationService,
		@NonNull final DevicePolicyManager devicePolicyManager,
		@NonNull final DatabaseHelper databaseHelper)
	{
		super(managedConfigurationService, databaseHelper, TABLE);
		this.devicePolicyManager = devicePolicyManager;
	}

	@Nullable
	@Override
	protected ManagedUserCertificate getCertificate(@NonNull ManagedVpnProfile vpnProfile)
	{
		return vpnProfile.getUserCertificate();
	}

	@NonNull
	@Override
	protected ManagedUserCertificate createCertificate(@NonNull Cursor cursor)
	{
		return new ManagedUserCertificate(cursor);
	}

	@Override
	protected boolean isInstalled(@NonNull ManagedUserCertificate certificate)
	{
		if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S)
		{
			return devicePolicyManager.hasKeyPair(certificate.getAlias());
		}
		/* We don't know, so we assume a certificate we installed may have been removed by the
		 * user, so we install it again to make sure it's still there */
		return false;
	}
}
