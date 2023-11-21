package org.strongswan.android.data;

import android.os.Bundle;
import android.text.TextUtils;

import java.util.Objects;
import java.util.UUID;

import androidx.annotation.NonNull;
import androidx.annotation.Nullable;

public class ManagedVpnProfile extends VpnProfile
{
	private static final String KEY_REMOTE = "remote";
	private static final String KEY_LOCAL = "local";
	private static final String KEY_INCLUDED_APPS = "included_apps";
	private static final String KEY_EXCLUDED_APPS = "excluded_apps";

	private static final String KEY_TRANSPORT_IPV6_FLAG = "transport_IPv6";
	private static final String KEY_REMOTE_CERT_REQ_FLAG = "remote_cert_req";
	private static final String KEY_REMOTE_REVOCATION_CRL_FLAG = "remote_revocation_crl";
	private static final String KEY_REMOTE_REVOCATION_OCSP_FLAG = "remote_revocation_ocsp";
	private static final String KEY_REMOTE_REVOCATION_STRICT_FLAG = "remote_revocation_strict";
	private static final String KEY_LOCAL_RSA_PSS_FLAG = "local_rsa_pss";

	private static final String KEY_SPLIT_TUNNELLING_BLOCK_IPV4_FLAG = "split_tunnelling_block_IPv4";
	private static final String KEY_SPLIT_TUNNELLING_BLOCK_IPV6_FLAG = "split_tunnelling_block_IPv6";

	private CaCertificate caCertificate;
	private UserCertificate userCertificate;

	ManagedVpnProfile(@NonNull final Bundle bundle, @NonNull final String uuid)
	{
		int flags = 0;
		int splitFlags = 0;

		setUUID(UUID.fromString(uuid));
		setName(bundle.getString(VpnProfileDataSource.KEY_NAME));
		setVpnType(VpnType.fromIdentifier(bundle.getString(VpnProfileDataSource.KEY_VPN_TYPE)));

		final Bundle remote = bundle.getBundle(KEY_REMOTE);
		flags = configureRemote(uuid, remote, flags);

		final Bundle local = bundle.getBundle(KEY_LOCAL);
		flags = configureLocal(uuid, local, flags);

		final String includedPackageNames = bundle.getString(KEY_INCLUDED_APPS);
		final String excludedPackageNames = bundle.getString(KEY_EXCLUDED_APPS);
		configureSelectedApps(includedPackageNames, excludedPackageNames);

		setMTU(getInt(bundle, VpnProfileDataSource.KEY_MTU, 1280, 1500));
		setNATKeepAlive(getInt(bundle, VpnProfileDataSource.KEY_NAT_KEEPALIVE, 10, 120));
		setIkeProposal(bundle.getString(VpnProfileDataSource.KEY_IKE_PROPOSAL));
		setEspProposal(bundle.getString(VpnProfileDataSource.KEY_ESP_PROPOSAL));
		setDnsServers(bundle.getString(VpnProfileDataSource.KEY_DNS_SERVERS));
		flags = addPositiveFlag(flags, bundle, KEY_TRANSPORT_IPV6_FLAG, VpnProfile.FLAGS_IPv6_TRANSPORT);

		final Bundle splitTunneling = bundle.getBundle(VpnProfileDataSource.KEY_SPLIT_TUNNELING);
		if (splitTunneling != null)
		{
			splitFlags = addPositiveFlag(splitFlags, splitTunneling, KEY_SPLIT_TUNNELLING_BLOCK_IPV4_FLAG, VpnProfile.SPLIT_TUNNELING_BLOCK_IPV4);
			splitFlags = addPositiveFlag(splitFlags, splitTunneling, KEY_SPLIT_TUNNELLING_BLOCK_IPV6_FLAG, VpnProfile.SPLIT_TUNNELING_BLOCK_IPV6);

			setExcludedSubnets(splitTunneling.getString(VpnProfileDataSource.KEY_INCLUDED_SUBNETS));
			setIncludedSubnets(splitTunneling.getString(VpnProfileDataSource.KEY_EXCLUDED_SUBNETS));
		}

		setSplitTunneling(splitFlags);
		setFlags(flags);
	}

	private void configureSelectedApps(String includedPackageNames, String excludedPackageNames)
	{
		if (!TextUtils.isEmpty(includedPackageNames))
		{
			setSelectedAppsHandling(SelectedAppsHandling.SELECTED_APPS_ONLY);
			setSelectedApps(includedPackageNames);
		}
		else if (!TextUtils.isEmpty(excludedPackageNames))
		{
			setSelectedAppsHandling(SelectedAppsHandling.SELECTED_APPS_EXCLUDE);
			setSelectedApps(excludedPackageNames);
		}
	}

	private int configureRemote(@NonNull String uuid, @Nullable Bundle remote, int flags)
	{
		if (remote == null)
		{
			return flags;
		}

		setGateway(remote.getString(VpnProfileDataSource.KEY_GATEWAY));
		setPort(getInt(remote, VpnProfileDataSource.KEY_PORT, 1, 65_535));
		setRemoteId(remote.getString(VpnProfileDataSource.KEY_REMOTE_ID));

		final String certificateAlias = remote.getString(VpnProfileDataSource.KEY_CERTIFICATE_ALIAS, "remote:" + uuid);
		final String certificateData = remote.getString(VpnProfileDataSource.KEY_CERTIFICATE);

		if (!TextUtils.isEmpty(certificateAlias) && !TextUtils.isEmpty(certificateData))
		{
			setCertificateAlias(certificateAlias);
			caCertificate = new CaCertificate(
				getUUID().toString(),
				certificateAlias,
				certificateData);
		}

		flags = addNegativeFlag(flags, remote, KEY_REMOTE_CERT_REQ_FLAG, VpnProfile.FLAGS_SUPPRESS_CERT_REQS);
		flags = addNegativeFlag(flags, remote, KEY_REMOTE_REVOCATION_CRL_FLAG, VpnProfile.FLAGS_DISABLE_CRL);
		flags = addNegativeFlag(flags, remote, KEY_REMOTE_REVOCATION_OCSP_FLAG, VpnProfile.FLAGS_DISABLE_OCSP);
		flags = addPositiveFlag(flags, remote, KEY_REMOTE_REVOCATION_STRICT_FLAG, VpnProfile.FLAGS_STRICT_REVOCATION);
		return flags;
	}

	private int configureLocal(@NonNull String uuid, @Nullable Bundle local, int flags)
	{
		if (local == null)
		{
			return flags;
		}

		setLocalId(local.getString(VpnProfileDataSource.KEY_LOCAL_ID));
		setUsername(local.getString(VpnProfileDataSource.KEY_USERNAME));

		final String userCertificateAlias = local.getString(VpnProfileDataSource.KEY_USER_CERTIFICATE_ALIAS, "local:" + uuid);
		final String userCertificateData = local.getString(VpnProfileDataSource.KEY_USER_CERTIFICATE);
		final String userCertificatePassword = local.getString(VpnProfileDataSource.KEY_USER_CERTIFICATE_PASSWORD);

		if (!TextUtils.isEmpty(userCertificateAlias) && !TextUtils.isEmpty(userCertificateData))
		{
			setUserCertificateAlias(userCertificateAlias);
			userCertificate = new UserCertificate(
				getUUID().toString(),
				userCertificateAlias,
				userCertificateData,
				userCertificatePassword);
		}

		flags = addPositiveFlag(flags, local, KEY_LOCAL_RSA_PSS_FLAG, VpnProfile.FLAGS_RSA_PSS);
		return flags;
	}

	private static Integer getInt(final Bundle bundle, final String name, int min, int max)
	{
		final int value = bundle.getInt(name);
		if (value >= min && value <= max)
		{
			return value;
		}
		return null;
	}

	private static int addPositiveFlag(int flags, Bundle bundle, String key, int flag)
	{
		if (bundle.getBoolean(key))
		{
			flags |= flag;
		}
		return flags;
	}

	private static int addNegativeFlag(int flags, Bundle bundle, String key, int flag)
	{
		if (!bundle.getBoolean(key))
		{
			flags |= flag;
		}
		return flags;
	}

	public CaCertificate getCaCertificate()
	{
		return caCertificate;
	}

	public UserCertificate getUserCertificate()
	{
		return userCertificate;
	}

	@Override
	public boolean equals(Object o)
	{
		if (o == this)
		{
			return true;
		}
		if (o == null || getClass() != o.getClass())
		{
			return false;
		}
		ManagedVpnProfile that = (ManagedVpnProfile)o;
		return Objects.equals(getUUID(), that.getUUID());
	}

	@Override
	public int hashCode()
	{
		return Objects.hash(getUUID());
	}
}
