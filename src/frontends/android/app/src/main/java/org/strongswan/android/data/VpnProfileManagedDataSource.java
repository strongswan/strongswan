package org.strongswan.android.data;

import android.app.admin.DevicePolicyManager;
import android.content.Context;
import android.content.SharedPreferences;
import android.database.SQLException;

import org.strongswan.android.logic.StrongSwanApplication;

import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.UUID;

public class VpnProfileManagedDataSource implements VpnProfileDataSource
{
	private static final String NAME_MANAGED_VPN_PROFILES = "org.strongswan.android.data.VpnProfileManagedDataSource.preferences";

	private final ManagedConfigurationService mManagedConfigurationService;
	private final SharedPreferences mSharedPreferences;

	private final CaCertificateRepository mCaCertificateRepository;
	private final UserCertificateRepository mUserCertificateRepository;

	public VpnProfileManagedDataSource(final Context context)
	{
		final StrongSwanApplication application = (StrongSwanApplication)context.getApplicationContext();

		this.mManagedConfigurationService = application.getManagedConfigurationService();
		this.mSharedPreferences = context.getSharedPreferences(NAME_MANAGED_VPN_PROFILES, Context.MODE_PRIVATE);

		final DatabaseHelper databaseHelper = application.getDatabaseHelper();
		final DevicePolicyManager devicePolicyManager = (DevicePolicyManager)application.getSystemService(Context.DEVICE_POLICY_SERVICE);

		this.mCaCertificateRepository = new CaCertificateRepository(mManagedConfigurationService, databaseHelper);
		this.mUserCertificateRepository = new UserCertificateRepository(mManagedConfigurationService, devicePolicyManager, databaseHelper);
	}

	@Override
	public VpnProfileDataSource open() throws SQLException
	{
		// Do nothing
		return this;
	}

	@Override
	public void close()
	{
		// Remove passwords that are no longer referenced by a VPN profile
		final Set<String> actualKeys = new HashSet<>();
		for (final VpnProfile profile : getAllVpnProfiles())
		{
			actualKeys.add(profile.getUUID().toString());
		}

		final Set<String> storedKeys = new HashSet<>(mSharedPreferences.getAll().keySet());
		storedKeys.removeAll(actualKeys);

		final SharedPreferences.Editor editor = mSharedPreferences.edit();
		for (final String key : storedKeys)
		{
			editor.remove(key);
		}

		editor.apply();
	}

	@Override
	public VpnProfile insertProfile(VpnProfile profile)
	{
		return null;
	}

	@Override
	public boolean updateVpnProfile(VpnProfile profile)
	{
		final VpnProfile existingProfile = getVpnProfile(profile.getUUID());
		if (existingProfile == null)
		{
			return false;
		}

		final String password = profile.getPassword();
		existingProfile.setPassword(password);

		final SharedPreferences.Editor editor = mSharedPreferences.edit();
		editor.putString(profile.getUUID().toString(), password);
		return editor.commit();
	}

	@Override
	public boolean deleteVpnProfile(VpnProfile profile)
	{
		return false;
	}

	@Override
	public ManagedVpnProfile getVpnProfile(UUID uuid)
	{
		for (final ManagedVpnProfile vpnProfile : getAllVpnProfiles())
		{
			if (uuid != null && uuid.equals(vpnProfile.getUUID()))
			{
				return vpnProfile;
			}
		}
		return null;
	}

	@Override
	public List<ManagedVpnProfile> getAllVpnProfiles()
	{
		mManagedConfigurationService.loadConfiguration();

		final Map<String, CaCertificate> caCertificateMap = mCaCertificateRepository.getInstalledCertificateMap();
		final Map<String, UserCertificate> userCertificateMap = mUserCertificateRepository.getInstalledCertificateMap();

		final List<ManagedVpnProfile> managedVpnProfiles = mManagedConfigurationService.getManagedProfiles();
		for (final ManagedVpnProfile vpnProfile : managedVpnProfiles)
		{
			final String uuid = vpnProfile.getUUID().toString();
			final String password = mSharedPreferences.getString(uuid, vpnProfile.getPassword());
			final CaCertificate caCertificate = caCertificateMap.get(uuid);
			if (caCertificate != null)
			{
				vpnProfile.setCertificateAlias(caCertificate.getAlias());
			}
			final UserCertificate userCertificate = userCertificateMap.get(uuid);
			if (userCertificate != null)
			{
				vpnProfile.setUserCertificateAlias(userCertificate.getAlias());
			}

			vpnProfile.setPassword(password);
			vpnProfile.setDataSource(this);
			vpnProfile.setReadOnly(true);
		}
		return managedVpnProfiles;
	}

	public boolean areUnmanagedSourcesAllowed()
	{
		mManagedConfigurationService.loadConfiguration();

		final ManagedConfiguration managedConfiguration = mManagedConfigurationService.getManagedConfiguration();
		return managedConfiguration.isAllowExistingProfiles();
	}
}
