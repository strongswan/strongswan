package org.strongswan.android.data;

import android.database.Cursor;

import org.strongswan.android.logic.TrustedCertificateManager;

import java.security.cert.X509Certificate;

import androidx.annotation.NonNull;
import androidx.annotation.Nullable;

public class CaCertificateRepository extends CertificateRepository<CaCertificate>
{
	private static final DatabaseHelper.DbTable TABLE = DatabaseHelper.TABLE_CA_CERTIFICATE;

	public CaCertificateRepository(
		@NonNull final ManagedConfigurationService managedConfigurationService,
		@NonNull final DatabaseHelper databaseHelper)
	{
		super(managedConfigurationService, databaseHelper, TABLE);
	}

	@Nullable
	@Override
	protected CaCertificate getCertificate(@NonNull ManagedVpnProfile vpnProfile)
	{
		return vpnProfile.getCaCertificate();
	}

	@NonNull
	@Override
	protected CaCertificate createCertificate(@NonNull Cursor cursor)
	{
		return new CaCertificate(cursor);
	}

	@Override
	protected boolean isInstalled(@NonNull CaCertificate certificate)
	{
		TrustedCertificateManager certificateManager = TrustedCertificateManager.getInstance();
		final X509Certificate x509Certificate = certificateManager.getCACertificateFromAlias(certificate.getAlias());

		return x509Certificate != null;
	}
}
