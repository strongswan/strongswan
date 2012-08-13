/*
 * Copyright (C) 2012 Tobias Brunner
 * Copyright (C) 2012 Giuliano Grassi
 * Copyright (C) 2012 Ralf Sager
 * Hochschule fuer Technik Rapperswil
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

package org.strongswan.android.ui.adapter;

import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Hashtable;
import java.util.Map.Entry;

import org.strongswan.android.R;

import android.content.Context;
import android.net.http.SslCertificate;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.BaseAdapter;
import android.widget.TextView;

public class TrustedCertificateAdapter extends BaseAdapter
{
	private final ArrayList<CertEntry> mContent;
	private final Context mContext;

	public class CertEntry implements Comparable<CertEntry>
	{
		public X509Certificate mCert;
		public String mAlias;
		public String mDisplayName;

		public CertEntry(String alias, X509Certificate cert)
		{
			mCert = cert;
			mAlias = alias;
		}

		public String getDisplayText()
		{
			if (mDisplayName == null)
			{
				SslCertificate cert = new SslCertificate(mCert);
				String o = cert.getIssuedTo().getOName();
				String ou = cert.getIssuedTo().getUName();
				String cn = cert.getIssuedTo().getCName();
				if (!o.isEmpty())
				{
					mDisplayName = o;
					if (!cn.isEmpty())
					{
						mDisplayName = mDisplayName + ", " + cn;
					}
					else if (!ou.isEmpty())
					{
						mDisplayName = mDisplayName + ", " + ou;
					}
				}
				else if (!cn.isEmpty())
				{
					mDisplayName = cn;
				}
				else
				{
					mDisplayName = cert.getIssuedTo().getDName();
				}
			}
			return mDisplayName;
		}

		@Override
		public int compareTo(CertEntry another)
		{
			return getDisplayText().compareToIgnoreCase(another.getDisplayText());
		}
	}

	public TrustedCertificateAdapter(Context context,
											Hashtable<String, X509Certificate> content)
	{
		mContext = context;
		mContent = new ArrayList<TrustedCertificateAdapter.CertEntry>();
		for (Entry<String, X509Certificate> entry : content.entrySet())
		{
			mContent.add(new CertEntry(entry.getKey(), entry.getValue()));
		}
		Collections.sort(mContent);
	}

	@Override
	public int getCount()
	{
		return mContent.size();
	}

	@Override
	public Object getItem(int position)
	{
		return mContent.get(position);
	}

	/**
	 * Returns the position (index) of the entry with the given alias.
	 *
	 * @param alias alias of the item to find
	 * @return the position (index) in the list
	 */
	public int getItemPosition(String alias)
	{
		for (int i = 0; i < mContent.size(); i++)
		{
			if (mContent.get(i).mAlias.equals(alias))
			{
				return i;
			}
		}
		return -1;
	}

	@Override
	public long getItemId(int position)
	{
		return position;
	}

	@Override
	public View getView(int position, View convertView, ViewGroup parent)
	{
		LayoutInflater inflater = LayoutInflater.from(mContext);
		final View certView = inflater.inflate(R.layout.trusted_certificates_item, null);
		final TextView certText = (TextView)certView.findViewById(R.id.certificate_name);
		certText.setText(mContent.get(position).getDisplayText());
		return certView;
	}
}
