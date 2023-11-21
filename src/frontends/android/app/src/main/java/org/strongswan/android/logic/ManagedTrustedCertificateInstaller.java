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

package org.strongswan.android.logic;

import android.content.Context;
import android.util.Log;

import org.strongswan.android.data.ManagedTrustedCertificate;
import org.strongswan.android.utils.Certificates;

import java.io.IOException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;

import androidx.annotation.NonNull;

public class ManagedTrustedCertificateInstaller
{
	private static final String TAG = ManagedTrustedCertificateInstaller.class.getSimpleName();

	public ManagedTrustedCertificateInstaller(@NonNull final Context context)
	{
	}

	private boolean installTrustedCert(@NonNull ManagedTrustedCertificate trustedCertificate)
		throws CertificateException, IOException, KeyStoreException, NoSuchAlgorithmException
	{
		Log.d(TAG, "Install trusted certificate " + trustedCertificate);
		final X509Certificate certificate = Certificates.from(trustedCertificate.getData());

		KeyStore store = KeyStore.getInstance("LocalCertificateStore");
		store.load(null, null);
		store.setCertificateEntry(trustedCertificate.getAlias(), certificate);
		return true;
	}

	private void uninstallTrustedCert(@NonNull ManagedTrustedCertificate trustedCertificate)
		throws CertificateException, IOException, NoSuchAlgorithmException, KeyStoreException
	{
		Log.d(TAG, "Remove trusted certificate " + trustedCertificate);
		KeyStore store = KeyStore.getInstance("LocalCertificateStore");
		store.load(null, null);
		store.deleteEntry(trustedCertificate.getAlias());
	}

	public synchronized boolean tryInstall(@NonNull ManagedTrustedCertificate trustedCertificate)
	{
		try
		{
			return installTrustedCert(trustedCertificate);
		}
		catch (final Exception e)
		{
			Log.e(TAG, "Could not install trusted certificate " + trustedCertificate, e);
			return false;
		}
	}

	public synchronized void tryRemove(@NonNull ManagedTrustedCertificate trustedCertificate)
	{
		try
		{
			uninstallTrustedCert(trustedCertificate);
		}
		catch (final Exception e)
		{
			Log.e(TAG, "Could not remove trusted certificate " + trustedCertificate, e);
		}
	}
}
