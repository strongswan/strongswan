/*
 * Copyright (C) 2023 Relution GmbH
 *
 * Copyright (C) secunet Security Networks AG
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the
 * Free Software Foundation; either version 2 of the License, or (at your
 * option) any later version.  See <http://www.fsf.org/copyleft/gpl.txt>.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
 * or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License
 * for more details.
 */

package org.strongswan.android.data;

import android.os.Bundle;
import android.text.TextUtils;

import org.strongswan.android.utils.Constants;

import java.util.Objects;
import java.util.UUID;

import androidx.annotation.Nullable;

public class ManagedVpnProfile extends VpnProfile
{
	private static final String KEY_REMOTE = "remote";
	private static final String KEY_LOCAL = "local";
	private static final String KEY_INCLUDED_APPS = "included_apps";
	private static final String KEY_EXCLUDED_APPS = "excluded_apps";

	private static final String KEY_TRANSPORT_IPV6_FLAG = "transport_ipv6";
	private static final String KEY_REMOTE_CERT_REQ_FLAG = "remote_cert_req";
	private static final String KEY_REMOTE_REVOCATION_CRL_FLAG = "remote_revocation_crl";
	private static final String KEY_REMOTE_REVOCATION_OCSP_FLAG = "remote_revocation_ocsp";
	private static final String KEY_REMOTE_REVOCATION_STRICT_FLAG = "remote_revocation_strict";
	private static final String KEY_LOCAL_RSA_PSS_FLAG = "local_rsa_pss";

	private static final String KEY_SPLIT_TUNNELLING_BLOCK_IPV4_FLAG = "split_tunnelling_block_ipv4";
	private static final String KEY_SPLIT_TUNNELLING_BLOCK_IPV6_FLAG = "split_tunnelling_block_ipv6";

	private ManagedTrustedCertificate trustedCertificate;
	private ManagedUserCertificate userCertificate;

	ManagedVpnProfile(final Bundle bundle, final UUID uuid)
	{
		int flags = 0;
		int splitFlags = 0;

		setReadOnly(true);
		setUUID(uuid);
		setName(bundle.getString(VpnProfileDataSource.KEY_NAME));
		setVpnType(VpnType.fromIdentifier(bundle.getString(VpnProfileDataSource.KEY_VPN_TYPE)));

		final Bundle remote = bundle.getBundle(KEY_REMOTE);
		flags = configureRemote(uuid, remote, flags);

		final Bundle local = bundle.getBundle(KEY_LOCAL);
		flags = configureLocal(uuid, local, flags);

		final String includedPackageNames = bundle.getString(KEY_INCLUDED_APPS);
		final String excludedPackageNames = bundle.getString(KEY_EXCLUDED_APPS);
		configureSelectedApps(includedPackageNames, excludedPackageNames);

		setMTU(getInt(bundle, VpnProfileDataSource.KEY_MTU, Constants.MTU_MIN, Constants.MTU_MAX));
		setNATKeepAlive(getInt(bundle, VpnProfileDataSource.KEY_NAT_KEEPALIVE, Constants.NAT_KEEPALIVE_MIN, Constants.NAT_KEEPALIVE_MAX));
		setIkeProposal(bundle.getString(VpnProfileDataSource.KEY_IKE_PROPOSAL));
		setEspProposal(bundle.getString(VpnProfileDataSource.KEY_ESP_PROPOSAL));
		setDnsServers(bundle.getString(VpnProfileDataSource.KEY_DNS_SERVERS));
		flags = addPositiveFlag(flags, bundle, KEY_TRANSPORT_IPV6_FLAG, VpnProfile.FLAGS_IPv6_TRANSPORT);

		final Bundle splitTunneling = bundle.getBundle(VpnProfileDataSource.KEY_SPLIT_TUNNELING);
		if (splitTunneling != null)
		{
			splitFlags = addPositiveFlag(splitFlags, splitTunneling, KEY_SPLIT_TUNNELLING_BLOCK_IPV4_FLAG, VpnProfile.SPLIT_TUNNELING_BLOCK_IPV4);
			splitFlags = addPositiveFlag(splitFlags, splitTunneling, KEY_SPLIT_TUNNELLING_BLOCK_IPV6_FLAG, VpnProfile.SPLIT_TUNNELING_BLOCK_IPV6);

			setExcludedSubnets(splitTunneling.getString(VpnProfileDataSource.KEY_EXCLUDED_SUBNETS));
			setIncludedSubnets(splitTunneling.getString(VpnProfileDataSource.KEY_INCLUDED_SUBNETS));
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

	private int configureRemote(final UUID uuid, @Nullable Bundle remote, int flags)
	{
		if (remote == null)
		{
			return flags;
		}

		setGateway(remote.getString(VpnProfileDataSource.KEY_GATEWAY));
		setPort(getInt(remote, VpnProfileDataSource.KEY_PORT, 1, 65_535));
		setRemoteId(remote.getString(VpnProfileDataSource.KEY_REMOTE_ID));

		final String certificateData = remote.getString(VpnProfileDataSource.KEY_CERTIFICATE);
		if (!TextUtils.isEmpty(certificateData))
		{
			trustedCertificate = new ManagedTrustedCertificate(uuid.toString(), certificateData);
			setCertificateAlias(trustedCertificate.getAlias());
		}

		flags = addNegativeFlag(flags, remote, KEY_REMOTE_CERT_REQ_FLAG, VpnProfile.FLAGS_SUPPRESS_CERT_REQS);
		flags = addNegativeFlag(flags, remote, KEY_REMOTE_REVOCATION_CRL_FLAG, VpnProfile.FLAGS_DISABLE_CRL);
		flags = addNegativeFlag(flags, remote, KEY_REMOTE_REVOCATION_OCSP_FLAG, VpnProfile.FLAGS_DISABLE_OCSP);
		flags = addPositiveFlag(flags, remote, KEY_REMOTE_REVOCATION_STRICT_FLAG, VpnProfile.FLAGS_STRICT_REVOCATION);
		return flags;
	}

	private int configureLocal(final UUID uuid, @Nullable Bundle local, int flags)
	{
		if (local == null)
		{
			return flags;
		}

		setLocalId(local.getString(VpnProfileDataSource.KEY_LOCAL_ID));
		setUsername(local.getString(VpnProfileDataSource.KEY_USERNAME));

		final String userCertificateData = local.getString(VpnProfileDataSource.KEY_USER_CERTIFICATE);
		final String userCertificatePassword = local.getString(VpnProfileDataSource.KEY_USER_CERTIFICATE_PASSWORD, "");
		if (!TextUtils.isEmpty(userCertificateData))
		{
			userCertificate = new ManagedUserCertificate(uuid.toString(), userCertificateData, userCertificatePassword);
			setUserCertificateAlias(userCertificate.getAlias());
		}

		flags = addPositiveFlag(flags, local, KEY_LOCAL_RSA_PSS_FLAG, VpnProfile.FLAGS_RSA_PSS);
		return flags;
	}

	private static Integer getInt(final Bundle bundle, final String key, final int min, final int max)
	{
		final int value = bundle.getInt(key);
		return value < min || value > max ? null : value;
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

	public ManagedTrustedCertificate getTrustedCertificate()
	{
		return trustedCertificate;
	}

	public ManagedUserCertificate getUserCertificate()
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
