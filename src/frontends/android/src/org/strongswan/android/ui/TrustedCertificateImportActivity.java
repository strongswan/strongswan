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

import android.app.Activity;
import android.content.Intent;
import android.os.Bundle;
import android.widget.Toast;

public class TrustedCertificateImportActivity extends Activity
{
	@Override
	public void onCreate(Bundle savedInstanceState)
	{
		super.onCreate(savedInstanceState);

		Intent intent = getIntent();
		String action = intent.getAction();
		if (Intent.ACTION_VIEW.equals(action))
		{
			try
			{
				CertificateFactory factory = CertificateFactory.getInstance("X.509");
				InputStream in = getContentResolver().openInputStream(intent.getData());
				X509Certificate certificate = (X509Certificate)factory.generateCertificate(in);
				/* we don't check whether it's actually a CA certificate or not */
				KeyStore store = KeyStore.getInstance("LocalCertificateStore");
				store.load(null, null);
				store.setCertificateEntry(null, certificate);
				TrustedCertificateManager.getInstance().reset();
				Toast.makeText(this, R.string.cert_imported_successfully, Toast.LENGTH_LONG).show();
			}
			catch (Exception e)
			{
				Toast.makeText(this, R.string.cert_import_failed, Toast.LENGTH_LONG).show();
				e.printStackTrace();
			}
		}
		finish();
	}
}
