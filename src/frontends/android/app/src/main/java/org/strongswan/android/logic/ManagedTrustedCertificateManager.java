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

import android.content.Context;
import android.os.Handler;
import android.util.Log;

import org.strongswan.android.data.DatabaseHelper;
import org.strongswan.android.data.ManagedConfigurationService;
import org.strongswan.android.data.ManagedTrustedCertificate;
import org.strongswan.android.data.ManagedTrustedCertificateRepository;
import org.strongswan.android.utils.Difference;

import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ExecutorService;

import androidx.annotation.NonNull;
import androidx.core.util.Pair;

public class ManagedTrustedCertificateManager
{
	private static final String TAG = ManagedTrustedCertificateManager.class.getSimpleName();

	@NonNull
	private final ExecutorService executorService;
	@NonNull
	private final Handler handler;

	@NonNull
	private final ManagedTrustedCertificateRepository certificateRepository;
	@NonNull
	private final ManagedTrustedCertificateInstaller certificateInstaller;

	public ManagedTrustedCertificateManager(
		@NonNull final Context context,
		@NonNull final ExecutorService executorService,
		@NonNull final Handler handler,
		@NonNull final ManagedConfigurationService managedConfigurationService,
		@NonNull final DatabaseHelper databaseHelper)
	{
		this.executorService = executorService;
		this.handler = handler;

		this.certificateRepository = new ManagedTrustedCertificateRepository(managedConfigurationService, databaseHelper);
		this.certificateInstaller = new ManagedTrustedCertificateInstaller(context);
	}

	public void update(@NonNull final Runnable onUpdateCompleted)
	{
		executorService.execute(() -> {
			final List<ManagedTrustedCertificate> configured = certificateRepository.getConfiguredCertificates();
			final List<ManagedTrustedCertificate> installed = certificateRepository.getInstalledCertificates();

			final Difference<ManagedTrustedCertificate> diff = Difference.between(installed, configured, ManagedTrustedCertificate::getVpnProfileUuid);
			if (diff.isEmpty())
			{
				Log.d(TAG, "No trusted certificates changed, nothing to do");
				handler.post(onUpdateCompleted);
				return;
			}
			Log.d(TAG, "Trusted certificates changed " + diff);

			final Set<String> protectedAliases = new HashSet<>();
			for (final ManagedTrustedCertificate unchanged : diff.getUnchanged())
			{
				protectedAliases.add(unchanged.getAlias());
			}

			for (final ManagedTrustedCertificate delete : diff.getDeletes())
			{
				remove(delete, !protectedAliases.contains(delete.getAlias()));
			}

			for (final Pair<ManagedTrustedCertificate, ManagedTrustedCertificate> update : diff.getUpdates())
			{
				remove(update.first, !protectedAliases.contains(update.first.getAlias()));
				install(update.second);
			}

			for (final ManagedTrustedCertificate insert : diff.getInserts())
			{
				install(insert);
			}

			TrustedCertificateManager.getInstance().reset();
			TrustedCertificateManager.getInstance().load();
			handler.post(onUpdateCompleted);
		});
	}

	private void install(@NonNull final ManagedTrustedCertificate trustedCertificate)
	{
		if (certificateInstaller.tryInstall(trustedCertificate))
		{
			certificateRepository.addInstalledCertificate(trustedCertificate);
		}
	}

	private void remove(@NonNull final ManagedTrustedCertificate trustedCertificate, boolean uninstall)
	{
		if (uninstall)
		{
			certificateInstaller.tryRemove(trustedCertificate);
		}
		certificateRepository.removeInstalledCertificate(trustedCertificate);
	}
}
