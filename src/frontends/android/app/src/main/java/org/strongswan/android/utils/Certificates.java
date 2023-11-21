
package org.strongswan.android.utils;

import org.strongswan.android.data.CaCertificate;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;

import androidx.annotation.NonNull;

public class Certificates
{
	@NonNull
	public static X509Certificate from(@NonNull final CaCertificate certificate) throws IOException, CertificateException
	{
		final byte[] bytes = android.util.Base64.decode(certificate.getData(), android.util.Base64.DEFAULT);

		try (final ByteArrayInputStream stream = new ByteArrayInputStream(bytes))
		{
			final CertificateFactory certificateFactory = CertificateFactory.getInstance("X.509");
			return (X509Certificate)certificateFactory.generateCertificate(stream);
		}
	}

	private Certificates() {}
}
