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

package org.strongswan.android.utils;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;

import androidx.annotation.NonNull;

public class Certificates
{
	@NonNull
	public static X509Certificate from(@NonNull final String certificateData) throws IOException, CertificateException
	{
		final byte[] bytes = android.util.Base64.decode(certificateData, android.util.Base64.DEFAULT);

		try (final ByteArrayInputStream stream = new ByteArrayInputStream(bytes))
		{
			final CertificateFactory certificateFactory = CertificateFactory.getInstance("X.509");
			return (X509Certificate)certificateFactory.generateCertificate(stream);
		}
	}

	private Certificates() {}
}
