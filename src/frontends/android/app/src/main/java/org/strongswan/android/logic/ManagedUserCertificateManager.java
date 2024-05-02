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

package org.strongswan.android.logic;

import android.app.admin.DevicePolicyManager;
import android.content.Context;
import android.util.Log;

import org.strongswan.android.data.DatabaseHelper;
import org.strongswan.android.data.ManagedConfigurationService;
import org.strongswan.android.data.ManagedUserCertificate;
import org.strongswan.android.data.ManagedUserCertificateRepository;
import org.strongswan.android.utils.Difference;

import java.util.List;

import androidx.annotation.NonNull;
import androidx.core.util.Pair;

public class ManagedUserCertificateManager
{
	private static final String TAG = ManagedUserCertificateManager.class.getSimpleName();

	@NonNull
	private final ManagedUserCertificateRepository certificateRepository;
	@NonNull
	private final ManagedUserCertificateInstaller certificateInstaller;

	public ManagedUserCertificateManager(
		@NonNull final Context context,
		@NonNull final ManagedConfigurationService managedConfigurationService,
		@NonNull final DatabaseHelper databaseHelper)
	{
		final DevicePolicyManager devicePolicyManager = (DevicePolicyManager)context.getSystemService(Context.DEVICE_POLICY_SERVICE);

		this.certificateRepository = new ManagedUserCertificateRepository(managedConfigurationService, devicePolicyManager, databaseHelper);
		this.certificateInstaller = new ManagedUserCertificateInstaller(context);
	}

	public void update()
	{
		final List<ManagedUserCertificate> configured = certificateRepository.getConfiguredCertificates();
		final List<ManagedUserCertificate> installed = certificateRepository.getInstalledCertificates();

		final Difference<ManagedUserCertificate> diff = Difference.between(installed, configured, ManagedUserCertificate::getVpnProfileUuid);
		if (diff.isEmpty())
		{
			Log.d(TAG, "No key pairs changed, nothing to do");
			return;
		}
		Log.d(TAG, "Key pairs changed " + diff);

		for (final ManagedUserCertificate delete : diff.getDeletes())
		{
			remove(delete);
		}

		for (final Pair<ManagedUserCertificate, ManagedUserCertificate> update : diff.getUpdates())
		{
			remove(update.first);
			install(update.second);
		}

		for (final ManagedUserCertificate insert : diff.getInserts())
		{
			install(insert);
		}
	}

	private void install(@NonNull final ManagedUserCertificate userCertificate)
	{
		if (certificateInstaller.tryInstall(userCertificate))
		{
			certificateRepository.addInstalledCertificate(userCertificate);
		}
	}

	private void remove(@NonNull final ManagedUserCertificate userCertificate)
	{
		certificateInstaller.tryRemove(userCertificate);
		certificateRepository.removeInstalledCertificate(userCertificate);
	}
}
