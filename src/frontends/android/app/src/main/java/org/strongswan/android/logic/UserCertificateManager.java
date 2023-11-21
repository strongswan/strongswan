package org.strongswan.android.logic;

import android.app.admin.DevicePolicyManager;
import android.content.Context;
import android.util.Log;

import org.strongswan.android.data.DatabaseHelper;
import org.strongswan.android.data.ManagedConfigurationService;
import org.strongswan.android.data.UserCertificate;
import org.strongswan.android.data.UserCertificateRepository;
import org.strongswan.android.utils.Difference;

import java.util.List;

import androidx.annotation.NonNull;
import androidx.core.util.Pair;

public class UserCertificateManager
{
	private static final String TAG = UserCertificateManager.class.getSimpleName();

	@NonNull
	private final UserCertificateRepository userCertificateRepository;
	@NonNull
	private final UserCertificateInstaller userCertificateInstaller;

	public UserCertificateManager(
		@NonNull final Context context,
		@NonNull final ManagedConfigurationService managedConfigurationService,
		@NonNull final DatabaseHelper databaseHelper)
	{
		final DevicePolicyManager devicePolicyManager = (DevicePolicyManager)context.getSystemService(Context.DEVICE_POLICY_SERVICE);

		this.userCertificateRepository = new UserCertificateRepository(managedConfigurationService, devicePolicyManager, databaseHelper);
		this.userCertificateInstaller = new UserCertificateInstaller(context);
	}

	public void update()
	{
		final List<UserCertificate> configured = userCertificateRepository.getConfiguredCertificates();
		final List<UserCertificate> installed = userCertificateRepository.getInstalledCertificates();

		final Difference<UserCertificate> diff = Difference.between(installed, configured, UserCertificate::getVpnProfileUuid);
		if (diff.isEmpty())
		{
			Log.d(TAG, "No key pairs changed, nothing to do");
			return;
		}
		Log.d(TAG, "Key pairs changed " + diff);

		for (final UserCertificate delete : diff.getDeletes())
		{
			remove(delete);
		}

		for (final Pair<UserCertificate, UserCertificate> update : diff.getUpdates())
		{
			remove(update.first);
			install(update.second);
		}

		for (final UserCertificate insert : diff.getInserts())
		{
			install(insert);
		}
	}

	private void install(@NonNull final UserCertificate userCertificate)
	{
		if (userCertificateInstaller.tryInstall(userCertificate))
		{
			userCertificateRepository.addInstalledCertificate(userCertificate);
		}
	}

	private void remove(@NonNull final UserCertificate userCertificate)
	{
		userCertificateInstaller.tryRemove(userCertificate);
		userCertificateRepository.removeInstalledCertificate(userCertificate);
	}
}
