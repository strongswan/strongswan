package org.strongswan.android.data;

import android.app.admin.DevicePolicyManager;
import android.database.Cursor;
import android.os.Build;

import androidx.annotation.NonNull;
import androidx.annotation.Nullable;

public class UserCertificateRepository extends CertificateRepository<UserCertificate>
{
	private static final DatabaseHelper.DbTable TABLE = DatabaseHelper.TABLE_USER_CERTIFICATE;

	@NonNull
	private final DevicePolicyManager devicePolicyManager;

	public UserCertificateRepository(
		@NonNull final ManagedConfigurationService managedConfigurationService,
		@NonNull final DevicePolicyManager devicePolicyManager,
		@NonNull final DatabaseHelper databaseHelper)
	{
		super(managedConfigurationService, databaseHelper, TABLE);
		this.devicePolicyManager = devicePolicyManager;
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

	@Override
	protected boolean isInstalled(@NonNull UserCertificate certificate)
	{
		if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S)
		{
			return devicePolicyManager.hasKeyPair(certificate.getAlias());
		}

		// We don't know, so we assume a certificate we installed may have been removed by the
		// user, so we install it again to make sure it's still there
		return false;
	}
}
