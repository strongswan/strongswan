package org.strongswan.android.data;

import android.os.Build;
import android.os.Bundle;
import android.os.Parcelable;

import org.strongswan.android.utils.Constants;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.regex.Pattern;

import androidx.annotation.NonNull;

public class ManagedConfiguration
{
	private static final Pattern UUID_PATTERN = Pattern.compile("[0-9a-fA-F]{8}-(?:[0-9a-fA-F]{4}-){3}[0-9a-fA-F]{12}");

	private static final String KEY_ALLOW_PROFILE_CREATE = "allow_profile_create";
	private static final String KEY_ALLOW_PROFILE_IMPORT = "allow_profile_import";
	private static final String KEY_ALLOW_EXISTING_PROFILES = "allow_existing_profiles";
	private static final String KEY_ALLOW_CERTIFICATE_IMPORT = "allow_certificate_import";
	private static final String KEY_ALLOW_SETTINGS_ACCESS = "allow_settings_access";
	private static final String KEY_MANAGED_PROFILES = "managed_profiles";

	private final boolean mAllowProfileCreation;
	private final boolean mAllowProfileImport;
	private final boolean mAllowExistingProfiles;
	private final boolean mAllowCertificateImport;

	private final boolean mAllowSettingsAccess;
	private final String mDefaultVpnProfile;
	private final boolean mIgnoreBatteryOptimizations;

	private final List<ManagedVpnProfile> mManagedVpnProfiles;

	private final Set<String> mProfileUuids = new HashSet<>();
	private final Set<String> mInvalidProfiles = new HashSet<>();

	ManagedConfiguration()
	{
		mAllowProfileCreation = true;
		mAllowProfileImport = true;
		mAllowExistingProfiles = true;
		mAllowCertificateImport = true;

		mAllowSettingsAccess = true;
		mDefaultVpnProfile = null;
		mIgnoreBatteryOptimizations = false;

		mManagedVpnProfiles = Collections.emptyList();
	}

	ManagedConfiguration(final Bundle bundle)
	{
		mAllowProfileCreation = bundle.getBoolean(KEY_ALLOW_PROFILE_CREATE, true);
		mAllowProfileImport = bundle.getBoolean(KEY_ALLOW_PROFILE_IMPORT, true);
		mAllowExistingProfiles = bundle.getBoolean(KEY_ALLOW_EXISTING_PROFILES, true);

		mAllowCertificateImport = bundle.getBoolean(KEY_ALLOW_CERTIFICATE_IMPORT, true);

		mAllowSettingsAccess = bundle.getBoolean(KEY_ALLOW_SETTINGS_ACCESS, true);
		mDefaultVpnProfile = bundle.getString(Constants.PREF_DEFAULT_VPN_PROFILE, null);
		mIgnoreBatteryOptimizations = bundle.getBoolean(Constants.PREF_IGNORE_POWER_WHITELIST, false);

		final List<Bundle> managedProfileBundles = getBundleArrayList(bundle, KEY_MANAGED_PROFILES);
		mManagedVpnProfiles = new ArrayList<>(managedProfileBundles.size());

		for (final Bundle managedProfileBundle : managedProfileBundles)
		{
			addManagedProfile(managedProfileBundle);
		}
	}

	private void addManagedProfile(Bundle managedProfileBundle)
	{
		final String uuid = managedProfileBundle.getString(VpnProfileDataSource.KEY_UUID);

		if (isInvalid(managedProfileBundle) || mProfileUuids.contains(uuid))
		{
			mInvalidProfiles.add(uuid);
			return;
		}

		assert uuid != null;

		final ManagedVpnProfile vpnProfile = new ManagedVpnProfile(managedProfileBundle, uuid);
		mManagedVpnProfiles.add(vpnProfile);
		mProfileUuids.add(uuid);
	}

	private static boolean isInvalid(Bundle managedProfileBundle)
	{
		final String uuid = managedProfileBundle.getString(VpnProfileDataSource.KEY_UUID);
		return uuid == null || !UUID_PATTERN.matcher(uuid).matches();
	}

	private List<Bundle> getBundleArrayList(final Bundle bundle, final String key)
	{
		if (Build.VERSION.SDK_INT < Build.VERSION_CODES.TIRAMISU)
		{
			return getBundleArrayListCompat(bundle, key);
		}

		final Bundle[] bundles = bundle.getParcelableArray(key, Bundle.class);
		if (bundles == null)
		{
			return Collections.emptyList();
		}
		return Arrays.asList(bundles);
	}

	@NonNull
	private static List<Bundle> getBundleArrayListCompat(final Bundle bundle, final String key)
	{
		final Parcelable[] parcelables = bundle.getParcelableArray(key);
		if (parcelables == null)
		{
			return Collections.emptyList();
		}
		final Bundle[] bundles = Arrays.copyOf(parcelables, parcelables.length, Bundle[].class);
		return Arrays.asList(bundles);
	}

	public boolean isAllowProfileCreation()
	{
		return mAllowProfileCreation;
	}

	public boolean isAllowProfileImport()
	{
		return mAllowProfileImport;
	}

	public boolean isAllowExistingProfiles()
	{
		return mAllowExistingProfiles;
	}

	public boolean isAllowCertificateImport()
	{
		return mAllowCertificateImport;
	}

	public boolean isAllowSettingsAccess()
	{
		return mAllowSettingsAccess;
	}

	public String getDefaultVpnProfile()
	{
		if (mDefaultVpnProfile != null && mDefaultVpnProfile.equalsIgnoreCase("mru"))
		{
			return Constants.PREF_DEFAULT_VPN_PROFILE_MRU;
		}
		return mDefaultVpnProfile;
	}

	public boolean isIgnoreBatteryOptimizations()
	{
		return mIgnoreBatteryOptimizations;
	}

	public List<ManagedVpnProfile> getVpnProfiles()
	{
		return mManagedVpnProfiles;
	}

	public Set<String> getInvalidProfiles()
	{
		return mInvalidProfiles;
	}
}
