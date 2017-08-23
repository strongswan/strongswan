/*
 * Copyright (C) 2017 Tobias Brunner
 * HSR Hochschule fuer Technik Rapperswil
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

import android.support.annotation.Keep;

import java.io.BufferedOutputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.URL;

@Keep
public class SimpleFetcher
{
	public static byte[] fetch(String uri, byte[] data, String contentType) throws IOException
	{
		URL url = new URL(uri);
		HttpURLConnection conn = (HttpURLConnection)url.openConnection();
		conn.setConnectTimeout(10000);
		conn.setReadTimeout(10000);
		try
		{
			if (contentType != null)
			{
				conn.setRequestProperty("Content-Type", contentType);
			}
			if (data != null)
			{
				conn.setDoOutput(true);
				conn.setFixedLengthStreamingMode(data.length);
				OutputStream out = new BufferedOutputStream(conn.getOutputStream());
				out.write(data);
				out.close();
			}
			return streamToArray(conn.getInputStream());
		}
		finally
		{
			conn.disconnect();
		}
	}

	private static byte[] streamToArray(InputStream in) throws IOException
	{
		ByteArrayOutputStream out = new ByteArrayOutputStream();
		byte[] buf = new byte[1024];
		int len;

		try
		{
			while ((len = in.read(buf)) != -1)
			{
				out.write(buf, 0, len);
			}
			return out.toByteArray();
		}
		catch (IOException e)
		{
			e.printStackTrace();
		}
		finally
		{
			in.close();
		}
		return null;
	}
}
