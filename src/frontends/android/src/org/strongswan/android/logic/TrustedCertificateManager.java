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

package org.strongswan.android.logic;

import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.Enumeration;
import java.util.Hashtable;
import java.util.concurrent.locks.ReentrantReadWriteLock;

import android.util.Log;

public class TrustedCertificateManager
{
	private static final String TAG = TrustedCertificateManager.class.getSimpleName();
	private final ReentrantReadWriteLock mLock = new ReentrantReadWriteLock();
	private Hashtable<String, X509Certificate> mCACerts = new Hashtable<String, X509Certificate>();
	private boolean mLoaded;

	/**
	 * Private constructor to prevent instantiation from other classes.
	 */
	private TrustedCertificateManager()
	{
	}

	/**
	 * This is not instantiated until the first call to getInstance()
	 */
	private static class Singleton {
		public static final TrustedCertificateManager mInstance = new TrustedCertificateManager();
	}

	/**
	 * Get the single instance of the CA certificate manager.
	 * @return CA certificate manager
	 */
	public static TrustedCertificateManager getInstance()
	{
		return Singleton.mInstance;
	}

	/**
	 * Forces a load/reload of the cached CA certificates.
	 * As this takes a while it should be called asynchronously.
	 * @return reference to itself
	 */
	public TrustedCertificateManager reload()
	{
		Log.d(TAG, "Force reload of cached CA certificates");
		this.mLock.writeLock().lock();
		loadCertificates();
		this.mLock.writeLock().unlock();
		return this;
	}

	/**
	 * Ensures that the certificates are loaded but does not force a reload.
	 * As this takes a while if the certificates are not loaded yet it should
	 * be called asynchronously.
	 * @return reference to itself
	 */
	public TrustedCertificateManager load()
	{
		Log.d(TAG, "Ensure cached CA certificates are loaded");
		this.mLock.writeLock().lock();
		if (!this.mLoaded)
		{
			loadCertificates();
		}
		this.mLock.writeLock().unlock();
		return this;
	}

	/**
	 * Opens the CA certificate KeyStore and loads the cached certificates.
	 * The lock must be locked when calling this method.
	 */
	private void loadCertificates()
	{
		Log.d(TAG, "Load cached CA certificates");
		try
		{
			KeyStore store = KeyStore.getInstance("AndroidCAStore");
			store.load(null, null);
			this.mCACerts = fetchCertificates(store);
			this.mLoaded = true;
			Log.d(TAG, "Cached CA certificates loaded");
		}
		catch (Exception ex)
		{
			ex.printStackTrace();
			this.mCACerts = new Hashtable<String, X509Certificate>();
		}
	}

	/**
	 * Load all X.509 certificates from the given KeyStore.
	 * @param store KeyStore to load certificates from
	 * @return Hashtable mapping aliases to certificates
	 */
	private Hashtable<String, X509Certificate> fetchCertificates(KeyStore store)
	{
		Hashtable<String, X509Certificate> certs = new Hashtable<String, X509Certificate>();
		try
		{
			Enumeration<String> aliases = store.aliases();
			while (aliases.hasMoreElements())
			{
				String alias = aliases.nextElement();
				Certificate cert;
				cert = store.getCertificate(alias);
				if (cert != null && cert instanceof X509Certificate)
				{
					certs.put(alias, (X509Certificate)cert);
				}
			}
		}
		catch (KeyStoreException ex)
		{
			ex.printStackTrace();
		}
		return certs;
	}

	/**
	 * Retrieve the CA certificate with the given alias.
	 * @param alias alias of the certificate to get
	 * @return the certificate, null if not found
	 */
	public X509Certificate getCACertificateFromAlias(String alias)
	{
		X509Certificate certificate = null;

		if (this.mLock.readLock().tryLock())
		{
			certificate = this.mCACerts.get(alias);
			this.mLock.readLock().unlock();
		}
		else
		{	/* if we cannot get the lock load it directly from the KeyStore,
			 * should be fast for a single certificate */
			try
			{
				KeyStore store = KeyStore.getInstance("AndroidCAStore");
				store.load(null, null);
				Certificate cert = store.getCertificate(alias);
				if (cert != null && cert instanceof X509Certificate)
				{
					certificate = (X509Certificate)cert;
				}
			}
			catch (Exception e)
			{
				e.printStackTrace();
			}

		}
		return certificate;
	}

	/**
	 * Get all CA certificates (from the system and user keystore).
	 * @return Hashtable mapping aliases to certificates
	 */
	@SuppressWarnings("unchecked")
	public Hashtable<String, X509Certificate> getAllCACertificates()
	{
		Hashtable<String, X509Certificate> certs;
		this.mLock.readLock().lock();
		certs = (Hashtable<String, X509Certificate>)this.mCACerts.clone();
		this.mLock.readLock().unlock();
		return certs;
	}

	/**
	 * Get only the system-wide CA certificates.
	 * @return Hashtable mapping aliases to certificates
	 */
	public Hashtable<String, X509Certificate> getSystemCACertificates()
	{
		Hashtable<String, X509Certificate> certs = new Hashtable<String, X509Certificate>();
		this.mLock.readLock().lock();
		for (String alias : this.mCACerts.keySet())
		{
			if (alias.startsWith("system:"))
			{
				certs.put(alias, this.mCACerts.get(alias));
			}
		}
		this.mLock.readLock().unlock();
		return certs;
	}

	/**
	 * Get only the CA certificates installed by the user.
	 * @return Hashtable mapping aliases to certificates
	 */
	public Hashtable<String, X509Certificate> getUserCACertificates()
	{
		Hashtable<String, X509Certificate> certs = new Hashtable<String, X509Certificate>();
		this.mLock.readLock().lock();
		for (String alias : this.mCACerts.keySet())
		{
			if (alias.startsWith("user:"))
			{
				certs.put(alias, this.mCACerts.get(alias));
			}
		}
		this.mLock.readLock().unlock();
		return certs;
	}
}
