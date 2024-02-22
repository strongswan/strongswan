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

import android.content.ContentValues;
import android.database.Cursor;
import android.database.sqlite.SQLiteDatabase;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import androidx.annotation.NonNull;
import androidx.annotation.Nullable;

public abstract class ManagedCertificateRepository<T extends ManagedCertificate>
{
	@NonNull
	private final ManagedConfigurationService managedConfigurationService;

	@NonNull
	private final SQLiteDatabase database;
	@NonNull
	private final DatabaseHelper.DbTable table;

	protected ManagedCertificateRepository(
		@NonNull final ManagedConfigurationService managedConfigurationService,
		@NonNull final DatabaseHelper databaseHelper,
		@NonNull final DatabaseHelper.DbTable table)
	{
		this.managedConfigurationService = managedConfigurationService;

		this.database = databaseHelper.getReadableDatabase();
		this.table = table;
	}

	@Nullable
	protected abstract T getCertificate(@NonNull final ManagedVpnProfile vpnProfile);

	@NonNull
	protected abstract T createCertificate(@NonNull Cursor cursor);

	protected abstract boolean isInstalled(@NonNull T certificate);

	private boolean exists(@NonNull T certificate)
	{
		final String vpnProfileUuid = certificate.getVpnProfileUuid();
		try (final Cursor cursor = database.query(table.Name, table.columnNames(), ManagedCertificate.KEY_VPN_PROFILE_UUID + " = ?", new String[]{vpnProfileUuid}, null, null, null))
		{
			cursor.moveToFirst();
			if (!cursor.isAfterLast())
			{
				return true;
			}
		}
		return false;
	}

	@NonNull
	public List<T> getConfiguredCertificates()
	{
		managedConfigurationService.loadConfiguration();

		final Map<String, ManagedVpnProfile> managedVpnProfiles = managedConfigurationService.getManagedProfiles();
		final List<T> certificates = new ArrayList<>(managedVpnProfiles.size());

		for (final ManagedVpnProfile vpnProfile : managedVpnProfiles.values())
		{
			final T certificate = getCertificate(vpnProfile);
			if (certificate != null)
			{
				certificates.add(certificate);
			}
		}

		return certificates;
	}

	/**
	 * @return the collection of certificates that were previously installed.
	 * @see #addInstalledCertificate(ManagedCertificate)
	 */
	@NonNull
	private List<T> getCertificates()
	{
		try (final Cursor cursor = database.query(table.Name, table.columnNames(), null, null, null, null, null))
		{
			final List<T> certificates = new ArrayList<>();

			cursor.moveToFirst();
			while (!cursor.isAfterLast())
			{
				final T certificate = createCertificate(cursor);
				certificates.add(certificate);
				cursor.moveToNext();
			}
			return certificates;
		}
	}

	/**
	 * Returns the collection of certificates that were previously marked as installed and are still
	 * reported as installed by the OS.
	 *
	 * @return the collection of installed certificates.
	 * @see #addInstalledCertificate(ManagedCertificate)
	 */
	@NonNull
	public List<T> getInstalledCertificates()
	{
		final List<T> certificates = getCertificates();
		final List<T> installed = new ArrayList<>(certificates.size());

		for (final T certificate : certificates)
		{
			if (isInstalled(certificate))
			{
				installed.add(certificate);
			}
		}

		return installed;
	}

	/**
	 * Returns a map containing certificates previously marked as installed, indexed by the
	 * unique identifier of the VPN profile they are associated with.
	 *
	 * @return a map containing installed certificates, index by the VPN profile's unique
	 * identifier.
	 */
	@NonNull
	public Map<String, T> getCertificateMap()
	{
		final List<T> certificates = getCertificates();
		final Map<String, T> map = new HashMap<>(certificates.size());

		for (final T certificate : certificates)
		{
			map.put(certificate.getVpnProfileUuid(), certificate);
		}

		return map;
	}

	public void addInstalledCertificate(@NonNull final T certificate)
	{
		final ContentValues values = certificate.asContentValues();

		if (exists(certificate))
		{
			final String vpnProfileUuid = certificate.getVpnProfileUuid();
			database.update(table.Name, values, ManagedCertificate.KEY_VPN_PROFILE_UUID + " = ?", new String[]{vpnProfileUuid});
		}
		else
		{
			database.insert(table.Name, null, values);
		}
	}

	public void removeInstalledCertificate(@NonNull final T certificate)
	{
		final String vpnProfileUuid = certificate.getVpnProfileUuid();
		database.delete(table.Name, ManagedCertificate.KEY_VPN_PROFILE_UUID + " = ?", new String[]{vpnProfileUuid});
	}
}
