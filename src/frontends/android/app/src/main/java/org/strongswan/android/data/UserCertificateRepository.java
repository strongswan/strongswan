package org.strongswan.android.data;

import android.content.ContentValues;
import android.database.Cursor;
import android.database.sqlite.SQLiteDatabase;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import androidx.annotation.NonNull;

public class UserCertificateRepository
{
	private static final DatabaseHelper.DbTable TABLE = DatabaseHelper.TABLE_USER_CERTIFICATE;

	@NonNull
	private final ManagedConfigurationService managedConfigurationService;
	@NonNull
	private final SQLiteDatabase database;

	public UserCertificateRepository(
		@NonNull final ManagedConfigurationService managedConfigurationService,
		@NonNull final DatabaseHelper databaseHelper)
	{
		this.managedConfigurationService = managedConfigurationService;
		this.database = databaseHelper.getWritableDatabase();
	}

	@NonNull
	public List<UserCertificate> getConfiguredKeyStores()
	{
		managedConfigurationService.loadConfiguration();

		final List<ManagedVpnProfile> managedVpnProfiles = managedConfigurationService.getManagedProfiles();
		final List<UserCertificate> keyStores = new ArrayList<>(managedVpnProfiles.size());

		for (final ManagedVpnProfile vpnProfile : managedVpnProfiles)
		{
			final UserCertificate userCertificate = vpnProfile.getUserCertificate();
			if (userCertificate != null)
			{
				keyStores.add(userCertificate);
			}
		}

		return keyStores;
	}

	@NonNull
	public List<UserCertificate> getInstalledKeyStores()
	{
		final List<UserCertificate> certificates = new ArrayList<>();

		final Cursor cursor = database.query(TABLE.Name, TABLE.columnNames(), null, null, null, null, null);

		cursor.moveToFirst();
		while (!cursor.isAfterLast())
		{
			final UserCertificate certificate = new UserCertificate(cursor);
			certificates.add(certificate);
			cursor.moveToNext();
		}
		return certificates;
	}

	@NonNull
	public Map<String, UserCertificate> getInstalledKeyStoreMap()
	{
		final List<UserCertificate> keyStores = getInstalledKeyStores();
		final Map<String, UserCertificate> map = new HashMap<>(keyStores.size());

		for (final UserCertificate keyStore : keyStores)
		{
			map.put(keyStore.getVpnProfileUuid(), keyStore);
		}

		return map;
	}

	public void addInstalledKeyStore(@NonNull final UserCertificate userCertificate)
	{
		final ContentValues values = userCertificate.asContentValues();
		database.insert(TABLE.Name, null, values);
	}

	public void removeInstalledKeyStore(@NonNull final UserCertificate userCertificate)
	{
		final String vpnProfileUuid = userCertificate.getVpnProfileUuid();
		database.delete(TABLE.Name, PkcsCertificate.KEY_VPN_PROFILE_UUID + " = ?", new String[]{vpnProfileUuid});
	}
}
