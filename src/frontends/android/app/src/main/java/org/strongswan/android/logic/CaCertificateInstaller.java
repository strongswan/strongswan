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
		Log.d(TAG, "Install CA certificate " + caCertificate);
		final X509Certificate certificate = Certificates.from(caCertificate);

		KeyStore store = KeyStore.getInstance("LocalCertificateStore");
		store.load(null, null);
		store.setCertificateEntry(caCertificate.getAlias(), certificate);
		String alias = store.getCertificateAlias(certificate);

		Log.w(TAG, "Set effective alias of certificate '" + caCertificate.getConfiguredAlias() + "' to '" + alias + "'");
		caCertificate.setEffectiveAlias(alias);
		return true;
	}

	private void uninstallCaCert(@NonNull CaCertificate caCertificate)
		throws CertificateException, IOException
	{
		Log.d(TAG, "Remove CA certificate " + caCertificate);
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
			Log.e(TAG, "Could not install CA certificate " + caCertificate, e);
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
			Log.e(TAG, "Could not remove CA certificate " + caCertificate, e);
		}
	}
}
