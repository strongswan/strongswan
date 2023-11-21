package org.strongswan.android.logic;

import android.app.admin.DevicePolicyManager;
import android.content.Context;
import android.util.Log;

import org.strongswan.android.data.CaCertificate;
import org.strongswan.android.utils.Certificates;

import java.io.IOException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;

import androidx.annotation.NonNull;

public class CaCertificateInstaller
{
	private static final String TAG = CaCertificateInstaller.class.getSimpleName();

	@NonNull
	private final DevicePolicyManager policyManager;

	public CaCertificateInstaller(@NonNull final Context context)
	{
		this.policyManager = (DevicePolicyManager)context.getSystemService(Context.DEVICE_POLICY_SERVICE);
	}

	private boolean installCaCert(@NonNull CaCertificate caCertificate)
		throws CertificateException, IOException, KeyStoreException, NoSuchAlgorithmException
	{
		final X509Certificate certificate = Certificates.from(caCertificate);

		KeyStore store = KeyStore.getInstance("LocalCertificateStore");
		store.load(null, null);
		store.setCertificateEntry(caCertificate.getAlias(), certificate);
		caCertificate.setEffectiveAlias(store.getCertificateAlias(certificate));
		return true;
	}

	private void uninstallCaCert(@NonNull CaCertificate caCertificate)
		throws CertificateException, IOException
	{
		final X509Certificate certificate = Certificates.from(caCertificate);
		policyManager.uninstallCaCert(null, certificate.getEncoded());
	}

	public synchronized boolean tryInstall(@NonNull CaCertificate caCertificate)
	{
		try
		{
			return installCaCert(caCertificate);
		}
		catch (final Exception e)
		{
			Log.e(TAG, "Could not install CA certificate " + caCertificate.getAlias(), e);
			return false;
		}
	}

	public synchronized void tryRemove(@NonNull CaCertificate caCertificate)
	{
		try
		{
			uninstallCaCert(caCertificate);
		}
		catch (final Exception e)
		{
			Log.e(TAG, "Could not remove CA certificate " + caCertificate.getAlias(), e);
		}
	}
}
