/*
 * Copyright (C) 2014 Tobias Brunner
 * Hochschule fuer Technik Rapperswil
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the
 * Free Software Foundation; either version 2 of the License, or (at your
 * option) any later version. See <http://www.fsf.org/copyleft/gpl.txt>.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
 * or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License
 * for more details.
 */

package org.strongswan.android.ui;

import java.io.InputStream;
import java.security.KeyStore;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;

import org.strongswan.android.R;
import org.strongswan.android.logic.TrustedCertificateManager;

import android.annotation.TargetApi;
import android.app.Activity;
import android.content.Intent;
import android.net.Uri;
import android.os.Build;
import android.os.Bundle;
import android.widget.Toast;

public class TrustedCertificateImportActivity extends Activity
{
	private static final int OPEN_DOCUMENT = 0;

	/* same as those listed in the manifest */
	private static final String[] ACCEPTED_MIME_TYPES = {
														 "application/x-x509-ca-cert",
														 "application/x-x509-server-cert",
														 "application/x-pem-file",
														 "application/pkix-cert"
	};

	@TargetApi(Build.VERSION_CODES.KITKAT)
	@Override
	public void onCreate(Bundle savedInstanceState)
	{
		super.onCreate(savedInstanceState);

		Intent intent = getIntent();
		String action = intent.getAction();
		if (Intent.ACTION_VIEW.equals(action))
		{
			importCertificate(intent.getData());
		}
		else if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.KITKAT)
		{
			Intent openIntent = new Intent(Intent.ACTION_OPEN_DOCUMENT);
			openIntent.setType("*/*");
			openIntent.putExtra(Intent.EXTRA_MIME_TYPES, ACCEPTED_MIME_TYPES);
			startActivityForResult(openIntent, OPEN_DOCUMENT);
			return;
		}
		finish();
	}

	@Override
	protected void onActivityResult(int requestCode, int resultCode, Intent data)
	{
		switch (requestCode)
		{
			case OPEN_DOCUMENT:
				if (resultCode == Activity.RESULT_OK && data != null)
				{
					if (importCertificate(data.getData()))
					{
						setResult(Activity.RESULT_OK);
					}
				}
				finish();
				return;
		}
		super.onActivityResult(requestCode, resultCode, data);
	}

	/**
	 * Try to import the file pointed to by the given URI as a certificate.
	 * @param uri
	 * @return whether the import was successful
	 */
	private boolean importCertificate(Uri uri)
	{
		try
		{
			CertificateFactory factory = CertificateFactory.getInstance("X.509");
			InputStream in = getContentResolver().openInputStream(uri);
			X509Certificate certificate = (X509Certificate)factory.generateCertificate(in);
			/* we don't check whether it's actually a CA certificate or not */
			KeyStore store = KeyStore.getInstance("LocalCertificateStore");
			store.load(null, null);
			store.setCertificateEntry(null, certificate);
			TrustedCertificateManager.getInstance().reset();
			Toast.makeText(this, R.string.cert_imported_successfully, Toast.LENGTH_LONG).show();
			return true;
		}
		catch (Exception e)
		{
			Toast.makeText(this, R.string.cert_import_failed, Toast.LENGTH_LONG).show();
			e.printStackTrace();
		}
		return false;
	}
}
