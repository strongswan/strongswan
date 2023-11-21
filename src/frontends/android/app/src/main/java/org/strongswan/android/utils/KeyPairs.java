package org.strongswan.android.utils;

import org.strongswan.android.data.UserCertificate;

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
		if (certificate == null)
		{
			return null;
		}

		final Key key = keyStore.getKey(alias, passwordChars);
		return new KeyPair(certificate, (PrivateKey)key);
	}

	@Nullable
	private static KeyPair getKeyPair(@NonNull KeyStore keyStore, @NonNull UserCertificate userCertificate, @NonNull char[] passwordChars)
		throws KeyStoreException, NoSuchAlgorithmException, UnrecoverableKeyException
	{
		final KeyPair keyPair = getKeyPair(keyStore, userCertificate.getConfiguredAlias(), passwordChars);
		if (keyPair != null)
		{
			return keyPair;
		}

		final Enumeration<String> aliases = keyStore.aliases();
		while (aliases.hasMoreElements())
		{
			final String alias = aliases.nextElement();
			final KeyPair fallbackKeyPair = getKeyPair(keyStore, alias, passwordChars);
			if (fallbackKeyPair != null)
			{
				userCertificate.setEffectiveAlias(alias);
				return fallbackKeyPair;
			}
		}

		return null;
	}

	@Nullable
	public static KeyPair from(@NonNull final UserCertificate userCertificate)
		throws IOException, KeyStoreException, CertificateException, NoSuchAlgorithmException, UnrecoverableKeyException
	{
		final String password = userCertificate.getPrivateKeyPassword();
		if (password == null)
		{
			return null;
		}

		final byte[] bytes = android.util.Base64.decode(userCertificate.getData(), android.util.Base64.DEFAULT);
		final char[] passwordChars = password.toCharArray();

		final KeyStore keyStore = toKeyStore(bytes, passwordChars);
		return getKeyPair(keyStore, userCertificate, passwordChars);
	}

	private KeyPairs() {}
}
