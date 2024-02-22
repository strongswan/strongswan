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
import java.security.Key;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.UnrecoverableKeyException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Enumeration;

import androidx.annotation.NonNull;
import androidx.annotation.Nullable;

public class KeyPairs
{
	private static final String KEYSTORE_INSTANCE = "PKCS12";

	@NonNull
	private static KeyStore toKeyStore(@NonNull byte[] bytes, @NonNull char[] password)
		throws IOException, KeyStoreException, CertificateException, NoSuchAlgorithmException
	{
		try (final ByteArrayInputStream stream = new ByteArrayInputStream(bytes))
		{
			final KeyStore keyStore = KeyStore.getInstance(KEYSTORE_INSTANCE);
			keyStore.load(stream, password);
			return keyStore;
		}
	}

	@Nullable
	private static KeyPair getKeyPair(
		@NonNull final KeyStore keyStore,
		@NonNull final String alias,
		@NonNull final char[] passwordChars)
		throws KeyStoreException, NoSuchAlgorithmException, UnrecoverableKeyException
	{
		final Certificate certificate = keyStore.getCertificate(alias);
		if (!(certificate instanceof X509Certificate))
		{
			return null;
		}

		final Key key = keyStore.getKey(alias, passwordChars);
		if (key == null)
		{
			return null;
		}
		return new KeyPair(certificate, (PrivateKey)key);
	}

	@Nullable
	private static KeyPair getKeyPair(@NonNull KeyStore keyStore, @NonNull char[] passwordChars)
		throws KeyStoreException, NoSuchAlgorithmException, UnrecoverableKeyException
	{
		final Enumeration<String> aliases = keyStore.aliases();
		while (aliases.hasMoreElements())
		{
			final String alias = aliases.nextElement();
			final KeyPair keyPair = getKeyPair(keyStore, alias, passwordChars);
			if (keyPair != null)
			{
				return keyPair;
			}
		}
		return null;
	}

	@Nullable
	public static KeyPair from(@NonNull final String userCertificate, @NonNull final String password)
		throws IOException, KeyStoreException, CertificateException, NoSuchAlgorithmException, UnrecoverableKeyException
	{
		final byte[] bytes = android.util.Base64.decode(userCertificate, android.util.Base64.DEFAULT);
		final char[] passwordChars = password.toCharArray();

		final KeyStore keyStore = toKeyStore(bytes, passwordChars);
		return getKeyPair(keyStore, passwordChars);
	}

	private KeyPairs() {}
}
