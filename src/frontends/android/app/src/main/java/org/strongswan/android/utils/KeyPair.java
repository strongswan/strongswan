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

import java.security.PrivateKey;
import java.security.cert.Certificate;
import java.util.Objects;

import androidx.annotation.NonNull;

/**
 * Represents a key pair, which consists of a certificate (i.e. public key) and its corresponding
 * private key.
 */
public class KeyPair
{
	@NonNull
	public final Certificate certificate;
	@NonNull
	public final PrivateKey privateKey;

	/**
	 * Constructor for a {@link KeyPair}.
	 *
	 * @param certificate the certificate of the key pair.
	 * @param privateKey the private key of the key pair.
	 */
	public KeyPair(@NonNull Certificate certificate, @NonNull PrivateKey privateKey)
	{
		this.certificate = certificate;
		this.privateKey = privateKey;
	}

	@Override
	public boolean equals(Object o)
	{
		if (this == o)
		{
			return true;
		}
		if (o == null || getClass() != o.getClass())
		{
			return false;
		}
		final KeyPair that = (KeyPair)o;
		return Objects.equals(certificate, that.certificate) &&
			   Objects.equals(privateKey, that.privateKey);
	}

	@Override
	public int hashCode()
	{
		return Objects.hash(certificate, privateKey);
	}

	@NonNull
	@Override
	public String toString()
	{
		return "KeyPair{" + certificate + ", " + privateKey + "}";
	}
}
