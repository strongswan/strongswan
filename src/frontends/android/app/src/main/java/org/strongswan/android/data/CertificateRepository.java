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

public abstract class CertificateRepository<T extends PkcsCertificate>
{
	@NonNull
	private final ManagedConfigurationService managedConfigurationService;

	@NonNull
	private final SQLiteDatabase database;
	@NonNull
	private final DatabaseHelper.DbTable table;

	protected CertificateRepository(
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

	@NonNull
	public List<T> getConfiguredCertificates()
	{
		managedConfigurationService.loadConfiguration();

		final List<ManagedVpnProfile> managedVpnProfiles = managedConfigurationService.getManagedProfiles();
		final List<T> certificates = new ArrayList<>(managedVpnProfiles.size());

		for (final ManagedVpnProfile vpnProfile : managedVpnProfiles)
		{
			final T certificate = getCertificate(vpnProfile);
			if (certificate != null)
			{
				certificates.add(certificate);
			}
		}

		return certificates;
	}

	@NonNull
	public List<T> getInstalledCertificates()
	{
		final Cursor cursor = database.query(table.Name, table.columnNames(), null, null, null, null, null);

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

	@NonNull
	public Map<String, T> getInstalledCertificateMap()
	{
		final List<T> certificates = getInstalledCertificates();
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
		database.insert(table.Name, null, values);
	}

	public void removeInstalledCertificate(@NonNull final T certificate)
	{
		final String vpnProfileUuid = certificate.getVpnProfileUuid();
		database.delete(table.Name, PkcsCertificate.KEY_VPN_PROFILE_UUID + " = ?", new String[]{vpnProfileUuid});
	}
}
