package org.strongswan.android.data;

import static org.assertj.core.api.Assertions.assertThat;

import android.os.Bundle;

import org.junit.Test;

public class ManagedVpnProfileTest
{
	private static final String KEY_REMOTE = "remote";
	private static final String KEY_LOCAL = "local";
	private static final String KEY_INCLUDED_APPS = "included_apps";
	private static final String KEY_EXCLUDED_APPS = "excluded_apps";
	private static final String KEY_SPLIT_TUNNELING = "split_tunneling";
	private static final String KEY_SPLIT_TUNNELLING_BLOCK_IPV4 = "split_tunnelling_block_IPv4";
	private static final String KEY_SPLIT_TUNNELLING_BLOCK_IPV6 = "split_tunnelling_block_IPv6";

	private static final String KEY_TRANSPORT_IPV6_FLAG = "transport_IPv6";
	private static final String KEY_REMOTE_CERT_REQ_FLAG = "remote_cert_req";
	private static final String KEY_REMOTE_REVOCATION_CRL_FLAG = "remote_revocation_crl";
	private static final String KEY_REMOTE_REVOCATION_OCSP_FLAG = "remote_revocation_ocsp";
	private static final String KEY_REMOTE_REVOCATION_STRICT_FLAG = "remote_revocation_strict";
	private static final String KEY_LOCAL_RSA_PSS_FLAG = "local_rsa_pss";

	private static final String VPN_PROFILE_UUID = "00000000-0000-0000-0000-000000000001";
	private static final String VPN_PROFILE_NAME = "vpn-profile-name";
	private static final String GATEWAY = "gateway.example.com";
	private static final int PORT = 500;
	private static final String REMOTE_ID = "remote-id";
	private static final String CERTIFICATE = "x.509-certificate-base64";
	private static final String LOCAL_ID = "local-id";
	private static final String USERNAME = "username";
	private static final String USER_CERTIFICATE = "PKCS#12-user-certificate-base64";
	private static final String USER_CERTIFICATE_PASSWORD = "user-certificate-password";
	private static final String INCLUDED_APPS = "a b c";
	private static final String EXCLUDED_APPS = "d e f";
	private static final String IKE_PROPOSAL = "ike-proposal";
	private static final String ESP_PROPOSAL = "esp-proposal";
	private static final String DNS_SERVERS = "1.1.1.1 8.8.8.8";
	private static final String INCLUDED_SUBNETS = "included subnets";
	private static final String EXCLUDED_SUBNETS = "excluded subnets";

	@Test
	public void testDefaultValues()
	{
		final Bundle bundle = new Bundle();
		bundle.putString(VpnProfileDataSource.KEY_NAME, VPN_PROFILE_NAME);
		bundle.putInt(VpnProfileDataSource.KEY_MTU, 2000);
		bundle.putInt(VpnProfileDataSource.KEY_NAT_KEEPALIVE, 200);

		final ManagedVpnProfile vpnProfile = new ManagedVpnProfile(bundle, VPN_PROFILE_UUID);

		assertThat(vpnProfile.getUUID()).hasToString(VPN_PROFILE_UUID);
		assertThat(vpnProfile.getName()).isEqualTo(VPN_PROFILE_NAME);
		assertThat(vpnProfile.getVpnType()).isEqualTo(VpnType.IKEV2_EAP);

		assertThat(vpnProfile.getGateway()).isNull();
		assertThat(vpnProfile.getPort()).isNull();
		assertThat(vpnProfile.getRemoteId()).isNull();
		assertThat(vpnProfile.getCertificateAlias()).isNull();
		assertThat(vpnProfile.getCaCertificate()).isNull();

		assertThat(vpnProfile.getLocalId()).isNull();
		assertThat(vpnProfile.getUsername()).isNull();
		assertThat(vpnProfile.getUserCertificateAlias()).isNull();
		assertThat(vpnProfile.getUserCertificate()).isNull();

		assertThat(vpnProfile.getFlags()).isZero();

		assertThat(vpnProfile.getMTU()).isNull();
		assertThat(vpnProfile.getNATKeepAlive()).isNull();

		assertThat(vpnProfile.getIkeProposal()).isNull();
		assertThat(vpnProfile.getEspProposal()).isNull();
		assertThat(vpnProfile.getDnsServers()).isNull();

		assertThat(vpnProfile.getSelectedAppsHandling()).isEqualTo(VpnProfile.SelectedAppsHandling.SELECTED_APPS_DISABLE);
		assertThat(vpnProfile.getSelectedAppsSet()).isEmpty();

		assertThat(vpnProfile.getExcludedSubnets()).isNull();
		assertThat(vpnProfile.getIncludedSubnets()).isNull();

		assertThat(vpnProfile.getSplitTunneling()).isZero();
	}

	@Test
	public void testRemote()
	{
		final Bundle remote = new Bundle();
		remote.putString(VpnProfileDataSource.KEY_GATEWAY, GATEWAY);
		remote.putInt(VpnProfileDataSource.KEY_PORT, PORT);
		remote.putString(VpnProfileDataSource.KEY_REMOTE_ID, REMOTE_ID);
		remote.putString(VpnProfileDataSource.KEY_CERTIFICATE, CERTIFICATE);

		final Bundle bundle = new Bundle();
		bundle.putBundle(KEY_REMOTE, remote);

		final ManagedVpnProfile vpnProfile = new ManagedVpnProfile(bundle, VPN_PROFILE_UUID);

		assertThat(vpnProfile.getGateway()).isEqualTo(GATEWAY);
		assertThat(vpnProfile.getPort()).isEqualTo(PORT);
		assertThat(vpnProfile.getRemoteId()).isEqualTo(REMOTE_ID);
		assertThat(vpnProfile.getCertificateAlias()).isEqualTo("remote:" + VPN_PROFILE_UUID);
		assertThat(vpnProfile.getCaCertificate()).isEqualTo(new CaCertificate(
			VPN_PROFILE_UUID,
			"remote:" + VPN_PROFILE_UUID,
			CERTIFICATE)
		);
	}

	@Test
	public void testLocal()
	{
		final Bundle local = new Bundle();
		local.putString(VpnProfileDataSource.KEY_LOCAL_ID, LOCAL_ID);
		local.putString(VpnProfileDataSource.KEY_USERNAME, USERNAME);
		local.putString(VpnProfileDataSource.KEY_USER_CERTIFICATE, USER_CERTIFICATE);
		local.putString(VpnProfileDataSource.KEY_USER_CERTIFICATE_PASSWORD, USER_CERTIFICATE_PASSWORD);

		final Bundle bundle = new Bundle();
		bundle.putBundle(KEY_LOCAL, local);

		final ManagedVpnProfile vpnProfile = new ManagedVpnProfile(bundle, VPN_PROFILE_UUID);

		assertThat(vpnProfile.getLocalId()).isEqualTo(LOCAL_ID);
		assertThat(vpnProfile.getUsername()).isEqualTo(USERNAME);
		assertThat(vpnProfile.getUserCertificateAlias()).isEqualTo("local:" + VPN_PROFILE_UUID);
		assertThat(vpnProfile.getUserCertificate()).isEqualTo(new UserCertificate(
			VPN_PROFILE_UUID,
			"local:" + VPN_PROFILE_UUID,
			USER_CERTIFICATE,
			USER_CERTIFICATE_PASSWORD)
		);
	}

	@Test
	public void testIncludedApps()
	{
		final Bundle bundle = new Bundle();
		bundle.putString(KEY_INCLUDED_APPS, INCLUDED_APPS);
		bundle.putString(KEY_EXCLUDED_APPS, EXCLUDED_APPS);

		final ManagedVpnProfile vpnProfile = new ManagedVpnProfile(bundle, VPN_PROFILE_UUID);

		assertThat(vpnProfile.getSelectedApps()).isEqualTo(INCLUDED_APPS);
		assertThat(vpnProfile.getSelectedAppsSet()).contains("a", "b", "c");
		assertThat(vpnProfile.getSelectedAppsHandling()).isEqualTo(VpnProfile.SelectedAppsHandling.SELECTED_APPS_ONLY);
	}

	@Test
	public void testExcludedApps()
	{
		final Bundle bundle = new Bundle();
		bundle.putString(KEY_INCLUDED_APPS, null);
		bundle.putString(KEY_EXCLUDED_APPS, EXCLUDED_APPS);

		final ManagedVpnProfile vpnProfile = new ManagedVpnProfile(bundle, VPN_PROFILE_UUID);

		assertThat(vpnProfile.getSelectedApps()).isEqualTo(EXCLUDED_APPS);
		assertThat(vpnProfile.getSelectedAppsSet()).contains("d", "e", "f");
		assertThat(vpnProfile.getSelectedAppsHandling()).isEqualTo(VpnProfile.SelectedAppsHandling.SELECTED_APPS_EXCLUDE);
	}

	@Test
	public void testMtuKeepaliveProposals()
	{
		final Bundle bundle = new Bundle();
		bundle.putInt(VpnProfileDataSource.KEY_MTU, 1500);
		bundle.putInt(VpnProfileDataSource.KEY_NAT_KEEPALIVE, 120);
		bundle.putString(VpnProfileDataSource.KEY_IKE_PROPOSAL, IKE_PROPOSAL);
		bundle.putString(VpnProfileDataSource.KEY_ESP_PROPOSAL, ESP_PROPOSAL);
		bundle.putString(VpnProfileDataSource.KEY_DNS_SERVERS, DNS_SERVERS);

		final ManagedVpnProfile vpnProfile = new ManagedVpnProfile(bundle, VPN_PROFILE_UUID);

		assertThat(vpnProfile.getMTU()).isEqualTo(1500);
		assertThat(vpnProfile.getNATKeepAlive()).isEqualTo(120);
		assertThat(vpnProfile.getIkeProposal()).isEqualTo(IKE_PROPOSAL);
		assertThat(vpnProfile.getEspProposal()).isEqualTo(ESP_PROPOSAL);
		assertThat(vpnProfile.getDnsServers()).isEqualTo(DNS_SERVERS);
	}

	@Test
	public void testSplitTunneling()
	{
		final Bundle splitTunneling = new Bundle();
		splitTunneling.putBoolean(KEY_SPLIT_TUNNELLING_BLOCK_IPV4, true);
		splitTunneling.putBoolean(KEY_SPLIT_TUNNELLING_BLOCK_IPV6, true);
		splitTunneling.putString(VpnProfileDataSource.KEY_INCLUDED_SUBNETS, INCLUDED_SUBNETS);
		splitTunneling.putString(VpnProfileDataSource.KEY_EXCLUDED_SUBNETS, EXCLUDED_SUBNETS);

		final Bundle bundle = new Bundle();
		bundle.putBundle(KEY_SPLIT_TUNNELING, splitTunneling);

		final ManagedVpnProfile vpnProfile = new ManagedVpnProfile(bundle, VPN_PROFILE_UUID);

		assertThat(vpnProfile.getSplitTunneling()).isEqualTo(VpnProfile.SPLIT_TUNNELING_BLOCK_IPV4 | VpnProfile.SPLIT_TUNNELING_BLOCK_IPV6);
		assertThat(vpnProfile.getIncludedSubnets()).isEqualTo(INCLUDED_SUBNETS);
		assertThat(vpnProfile.getExcludedSubnets()).isEqualTo(EXCLUDED_SUBNETS);
	}

	@Test
	public void testSplitTunnelingIPv4()
	{
		final Bundle splitTunneling = new Bundle();
		splitTunneling.putBoolean(KEY_SPLIT_TUNNELLING_BLOCK_IPV4, true);

		final Bundle bundle = new Bundle();
		bundle.putBundle(KEY_SPLIT_TUNNELING, splitTunneling);

		final ManagedVpnProfile vpnProfile = new ManagedVpnProfile(bundle, VPN_PROFILE_UUID);

		assertThat(vpnProfile.getSplitTunneling()).isEqualTo(VpnProfile.SPLIT_TUNNELING_BLOCK_IPV4);
	}

	@Test
	public void testSplitTunnelingIPv6()
	{
		final Bundle splitTunneling = new Bundle();
		splitTunneling.putBoolean(KEY_SPLIT_TUNNELLING_BLOCK_IPV6, true);

		final Bundle bundle = new Bundle();
		bundle.putBundle(KEY_SPLIT_TUNNELING, splitTunneling);

		final ManagedVpnProfile vpnProfile = new ManagedVpnProfile(bundle, VPN_PROFILE_UUID);

		assertThat(vpnProfile.getSplitTunneling()).isEqualTo(VpnProfile.SPLIT_TUNNELING_BLOCK_IPV6);
	}

	@Test
	public void testNegativeFlags()
	{
		final Bundle remote = new Bundle();
		final Bundle local = new Bundle();

		final Bundle bundle = new Bundle();
		bundle.putBundle(KEY_REMOTE, remote);
		bundle.putBundle(KEY_LOCAL, local);

		final ManagedVpnProfile vpnProfile = new ManagedVpnProfile(bundle, VPN_PROFILE_UUID);

		assertThat(vpnProfile.getFlags()).isEqualTo(
			VpnProfile.FLAGS_SUPPRESS_CERT_REQS |
				VpnProfile.FLAGS_DISABLE_CRL |
				VpnProfile.FLAGS_DISABLE_OCSP);
	}

	@Test
	public void testPositiveFlags()
	{
		final Bundle remote = new Bundle();
		remote.putBoolean(KEY_REMOTE_CERT_REQ_FLAG, true);
		remote.putBoolean(KEY_REMOTE_REVOCATION_CRL_FLAG, true);
		remote.putBoolean(KEY_REMOTE_REVOCATION_OCSP_FLAG, true);
		remote.putBoolean(KEY_REMOTE_REVOCATION_STRICT_FLAG, true);

		final Bundle local = new Bundle();
		local.putBoolean(KEY_LOCAL_RSA_PSS_FLAG, true);

		final Bundle bundle = new Bundle();
		bundle.putBundle(KEY_REMOTE, remote);
		bundle.putBundle(KEY_LOCAL, local);
		bundle.putBoolean(KEY_TRANSPORT_IPV6_FLAG, true);

		final ManagedVpnProfile vpnProfile = new ManagedVpnProfile(bundle, VPN_PROFILE_UUID);

		assertThat(vpnProfile.getFlags()).isEqualTo(
			VpnProfile.FLAGS_STRICT_REVOCATION |
				VpnProfile.FLAGS_RSA_PSS |
				VpnProfile.FLAGS_IPv6_TRANSPORT);
	}
}
