package org.strongswan.android.data;

import android.os.Bundle;
import android.text.TextUtils;

import java.util.UUID;

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

	ManagedVpnProfile(final Bundle bundle)
	{
		int flags = 0;
		int splitFlags = 0;

		setUUID(UUID.fromString(bundle.getString(VpnProfileDataSource.KEY_UUID)));
		setName(bundle.getString(VpnProfileDataSource.KEY_NAME));
		setVpnType(VpnType.fromIdentifier(bundle.getString(VpnProfileDataSource.KEY_VPN_TYPE)));

		final Bundle remote = bundle.getBundle(KEY_REMOTE);
		if (remote != null)
		{
			setGateway(remote.getString(VpnProfileDataSource.KEY_GATEWAY));
			setPort(remote.getInt(VpnProfileDataSource.KEY_PORT));
			setRemoteId(remote.getString(VpnProfileDataSource.KEY_REMOTE_ID));
			setCertificateAlias(remote.getString(VpnProfileDataSource.KEY_CERTIFICATE));

			flags = addNegativeFlag(flags, remote, KEY_REMOTE_CERT_REQ_FLAG, VpnProfile.FLAGS_SUPPRESS_CERT_REQS);
			flags = addNegativeFlag(flags, remote, KEY_REMOTE_REVOCATION_CRL_FLAG, VpnProfile.FLAGS_DISABLE_CRL);
			flags = addNegativeFlag(flags, remote, KEY_REMOTE_REVOCATION_OCSP_FLAG, VpnProfile.FLAGS_DISABLE_OCSP);
			flags = addPositiveFlag(flags, remote, KEY_REMOTE_REVOCATION_STRICT_FLAG, VpnProfile.FLAGS_STRICT_REVOCATION);
		}

		final Bundle local = bundle.getBundle(KEY_LOCAL);
		if (local != null)
		{
			setLocalId(local.getString(VpnProfileDataSource.KEY_LOCAL_ID));
			setUsername(local.getString(VpnProfileDataSource.KEY_USERNAME));

			flags = addPositiveFlag(flags, local, KEY_LOCAL_RSA_PSS_FLAG, VpnProfile.FLAGS_RSA_PSS);
		}

		final String includedPackageNames = bundle.getString(KEY_INCLUDED_APPS);
		final String excludedPackageNames = bundle.getString(KEY_EXCLUDED_APPS);

		if (!TextUtils.isEmpty(includedPackageNames))
		{
			setSelectedAppsHandling(VpnProfile.SelectedAppsHandling.SELECTED_APPS_ONLY);
			setSelectedApps(includedPackageNames);
		}
		else if (!TextUtils.isEmpty(excludedPackageNames))
		{
			setSelectedAppsHandling(VpnProfile.SelectedAppsHandling.SELECTED_APPS_EXCLUDE);
			setSelectedApps(excludedPackageNames);
		}

		setMTU(bundle.getInt(VpnProfileDataSource.KEY_MTU));
		setNATKeepAlive(bundle.getInt(VpnProfileDataSource.KEY_NAT_KEEPALIVE));
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
}
