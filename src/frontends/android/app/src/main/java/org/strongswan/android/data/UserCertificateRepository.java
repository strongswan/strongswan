package org.strongswan.android.data;

import android.database.Cursor;

import androidx.annotation.NonNull;
import androidx.annotation.Nullable;

public class UserCertificateRepository extends CertificateRepository<UserCertificate>
{
	private static final DatabaseHelper.DbTable TABLE = DatabaseHelper.TABLE_USER_CERTIFICATE;

	public UserCertificateRepository(
		@NonNull final ManagedConfigurationService managedConfigurationService,
		@NonNull final DatabaseHelper databaseHelper)
	{
		super(managedConfigurationService, databaseHelper, TABLE);
	}

	@Nullable
	@Override
	protected UserCertificate getCertificate(@NonNull ManagedVpnProfile vpnProfile)
	{
		return vpnProfile.getUserCertificate();
	}

	@NonNull
	@Override
	protected UserCertificate createCertificate(@NonNull Cursor cursor)
	{
		return new UserCertificate(cursor);
	}
}
