package org.strongswan.android.data;

import android.content.ContentValues;
import android.database.Cursor;
import android.database.sqlite.SQLiteDatabase;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import androidx.annotation.NonNull;

public class CaCertificateRepository
{
	private static final DatabaseHelper.DbTable TABLE = DatabaseHelper.TABLE_CA_CERTIFICATE;

	@NonNull
	private final ManagedConfigurationService managedConfigurationService;
	@NonNull
	private final SQLiteDatabase database;

	public CaCertificateRepository(
		@NonNull final ManagedConfigurationService managedConfigurationService,
		@NonNull final DatabaseHelper databaseHelper)
	{
		this.managedConfigurationService = managedConfigurationService;
		this.database = databaseHelper.getWritableDatabase();
	}

	@NonNull
	public List<CaCertificate> getConfiguredCertificates()
	{
		managedConfigurationService.loadConfiguration();

		final List<ManagedVpnProfile> managedVpnProfiles = managedConfigurationService.getManagedProfiles();
		final List<CaCertificate> keyStores = new ArrayList<>(managedVpnProfiles.size());

		for (final ManagedVpnProfile vpnProfile : managedVpnProfiles)
		{
			final CaCertificate caCertificate = vpnProfile.getCaCertificate();
			if (caCertificate != null)
			{
				keyStores.add(caCertificate);
			}
		}

		return keyStores;
	}

	@NonNull
	public List<CaCertificate> getInstalledCertificates()
	{
		final List<CaCertificate> certificates = new ArrayList<>();

		final Cursor cursor = database.query(TABLE.Name, TABLE.columnNames(), null, null, null, null, null);

		cursor.moveToFirst();
		while (!cursor.isAfterLast())
		{
			final CaCertificate certificate = new CaCertificate(cursor);
			certificates.add(certificate);
			cursor.moveToNext();
		}
		return certificates;
	}

	@NonNull
	public Map<String, CaCertificate> getInstalledCertificateMap()
	{
		final List<CaCertificate> certificates = getInstalledCertificates();
		final Map<String, CaCertificate> map = new HashMap<>(certificates.size());

		for (final CaCertificate caCertificate : certificates)
		{
			map.put(caCertificate.getVpnProfileUuid(), caCertificate);
		}

		return map;
	}

	public void addInstalledCertificate(@NonNull final CaCertificate caCertificate)
	{
		final ContentValues values = caCertificate.asContentValues();
		database.insert(TABLE.Name, null, values);
	}

	public void removeInstalledCertificate(@NonNull final CaCertificate caCertificate)
	{
		final String vpnProfileUuid = caCertificate.getVpnProfileUuid();
		database.delete(TABLE.Name, PkcsCertificate.KEY_VPN_PROFILE_UUID + " = ?", new String[]{vpnProfileUuid});
	}
}
