/*
 * Copyright © 2015 FancyFon Software Ltd.
 * All rights reserved.
 */
package org.strongswan.android.security;


import android.content.Context;
import android.text.TextUtils;
import android.util.Log;

import org.strongswan.android.logic.StrongSwanApplication;
import org.strongswan.android.utils.Utils;

import java.io.BufferedInputStream;
import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.UnrecoverableKeyException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Calendar;
import java.util.Enumeration;

/**
 * @author Marcin Waligórski <marcin.waligorski@fancyfon.com>
 */
public class LocalKeystore {

    private static final String TAG = LocalKeystore.class.getSimpleName();
    // change this password before releasing
    private static final String PASSWORD = "TYPE_YOUR_PASSWORD_HERE";
    private static final String KEYSTORE_TYPE = "PKCS12";
    private static final String CA_KEYSTORE_TYPE = "BKS";

    // TODO: Change this string to enum
    private static final String CA_TYPE = "CA_";
    private static final String USER_TYPE = "USER_";
    private static final int NOT_A_SUBJECT_OF_CA_CERTIFICATE = -1;
    private KeyStore userCertKeystore;
    private KeyStore caCertKeystore;

    public LocalKeystore() throws KeyStoreException {
        userCertKeystore = KeyStore.getInstance(KEYSTORE_TYPE);
        caCertKeystore = KeyStore.getInstance(CA_KEYSTORE_TYPE);
    }

    public String addPkcs12(byte[] pkcs12, String password, String certificateId) {
        try {
            userCertKeystore.load(new ByteArrayInputStream(pkcs12), password.toCharArray());
            userCertKeystore.store(StrongSwanApplication.getContext().openFileOutput(USER_TYPE + certificateId, Context
                    .MODE_PRIVATE), PASSWORD.toCharArray());
            return getUserCertificateAlias();
        } catch (IOException e) {
            Log.e(TAG, "Error adding certificate to keystore: " + e);
        } catch (NoSuchAlgorithmException e) {
            Log.e(TAG, "Error adding certificate to keystore: " + e);
        } catch (CertificateException e) {
            Log.e(TAG, "Error adding certificate to keystore: " + e);
        } catch (KeyStoreException e) {
            Log.e(TAG, "Error adding certificate to keystore: " + e);
        }
        return null;
    }

    private String getUserCertificateAlias() throws KeyStoreException {
        String userCertAlias = "";
        Enumeration<String> aliases = userCertKeystore.aliases();
        while (aliases.hasMoreElements()) {
            String alias = aliases.nextElement();
            X509Certificate cert = (X509Certificate) userCertKeystore.getCertificate(alias);
            if (isNotACaCertificate(cert)) {
                userCertAlias = alias;
                break;
            }
        }
        return userCertAlias;
    }

    private boolean isNotACaCertificate(X509Certificate cert) {
        return cert != null && cert.getBasicConstraints() == NOT_A_SUBJECT_OF_CA_CERTIFICATE;
    }

    public String addCaCertificate(byte[] caCertificate, String certificateId) {
        try {
            caCertKeystore.load(null, null);
            Certificate ca = getCaCertificateFromBytes(caCertificate);
            if (ca != null) {
                caCertKeystore.setCertificateEntry(certificateId, ca);
                caCertKeystore.store(StrongSwanApplication.getContext().openFileOutput(CA_TYPE + certificateId, Context
                        .MODE_PRIVATE), PASSWORD.toCharArray());
                return caCertKeystore.aliases().nextElement();
            }
        } catch (IOException e) {
            Log.e(TAG, "Error adding certificate to keystore: " + e);
        } catch (NoSuchAlgorithmException e) {
            Log.e(TAG, "Error adding certificate to keystore: " + e);
        } catch (CertificateException e) {
            Log.e(TAG, "Error adding certificate to keystore: " + e);
        } catch (KeyStoreException e) {
            Log.e(TAG, "Error adding certificate to keystore: " + e);
        }
        return null;
    }

    private Certificate getCaCertificateFromBytes(byte[] caCertificate) throws CertificateException, IOException {
        CertificateFactory cf = CertificateFactory.getInstance("X.509");
        InputStream caInput = new BufferedInputStream(new ByteArrayInputStream(caCertificate));
        Certificate ca = null;
        try {
            ca = cf.generateCertificate(caInput);
        } finally {
            caInput.close();
        }
        return ca;
    }

    public X509Certificate[] getCertificateChain(String certificateId, String alias) {
        try {
            Certificate[] certs = getCertificates(certificateId, alias);
            return convertToX509Certificates(certs);
        } catch (KeyStoreException e) {
            Log.e(TAG, "Error reading certificate chain from keystore: " + e);
        } catch (CertificateException e) {
            Log.e(TAG, "Error reading certificate chain from keystore: " + e);
        } catch (NoSuchAlgorithmException e) {
            Log.e(TAG, "Error reading certificate chain from keystore: " + e);
        } catch (FileNotFoundException e) {
            Log.e(TAG, "Error reading certificate chain from keystore: " + e);
        } catch (IOException e) {
            Log.e(TAG, "Error reading certificate chain from keystore: " + e);
        }
        return null;
    }

    private X509Certificate[] convertToX509Certificates(Certificate[] certs) {
        X509Certificate[] x509Certs = new X509Certificate[certs.length];
        for (int i = 0; i < certs.length; i++) {
            x509Certs[i] = (X509Certificate) certs[i];
        }
        return x509Certs;
    }

    private Certificate[] getCertificates(String certificateId, String alias) throws IOException, NoSuchAlgorithmException, CertificateException, KeyStoreException {
        userCertKeystore.load(StrongSwanApplication.getContext().openFileInput(USER_TYPE + certificateId), PASSWORD
                .toCharArray());
        return userCertKeystore.getCertificateChain(alias);
    }

    public X509Certificate getCertificate(String certificateId, String alias) {
        try {
            caCertKeystore.load(StrongSwanApplication.getContext().openFileInput(CA_TYPE + certificateId), PASSWORD
                    .toCharArray());
            return (X509Certificate) caCertKeystore.getCertificate(alias);
        } catch (KeyStoreException e) {
            Log.e(TAG, "Error reading certificate from keystore: " + e);
        } catch (CertificateException e) {
            Log.e(TAG, "Error reading certificate from keystore: " + e);
        } catch (NoSuchAlgorithmException e) {
            Log.e(TAG, "Error reading certificate from keystore: " + e);
        } catch (FileNotFoundException e) {
            Log.e(TAG, "Error reading certificate from keystore: " + e);
        } catch (IOException e) {
            Log.e(TAG, "Error reading certificate from keystore: " + e);
        }
        return null;
    }

    public PrivateKey getPrivateKey(String certificateId, String alias) {
        try {
            userCertKeystore.load(StrongSwanApplication.getContext().openFileInput(USER_TYPE + certificateId), PASSWORD
                    .toCharArray());
            return (PrivateKey) userCertKeystore.getKey(alias, PASSWORD.toCharArray());
        } catch (UnrecoverableKeyException e) {
            Log.e(TAG, "Error reading private key from keystore: " + e);
        } catch (NoSuchAlgorithmException e) {
            Log.e(TAG, "Error reading private key from keystore: " + e);
        } catch (KeyStoreException e) {
            Log.e(TAG, "Error reading private key from keystore: " + e);
        } catch (CertificateException e) {
            Log.e(TAG, "Error reading private key from keystore: " + e);
        } catch (FileNotFoundException e) {
            Log.e(TAG, "Error reading private key from keystore: " + e);
        } catch (IOException e) {
            Log.e(TAG, "Error reading private key from keystore: " + e);
        }
        return null;
    }

    /**
     * Calculates the SHA-1 hash of the current timestamp.
     *
     * @return hex encoded SHA-1 hash of the current timestamp or null if failed
     */
    public String generateId() {
        MessageDigest md;
        try {
            md = MessageDigest.getInstance("SHA1");
            byte[] hash = md.digest(Calendar.getInstance().getTime().toString()
                    .getBytes());
            return Utils.bytesToHex(hash);
        } catch (NoSuchAlgorithmException e) {
            Log.e(TAG, "Error generating id: " + e);
        }
        return null;
    }

    public boolean removePkcs12AndCaCertificate(String certificateId) {
        try {
            if(!TextUtils.isEmpty(certificateId)) {
                File[] certificateFiles = StrongSwanApplication.getContext().getFilesDir().listFiles();
                for (File certificate : certificateFiles) {
                    if (certificate.getName().contains(certificateId)) {
                        certificate.delete();
                    }
                }
            }
            return true;
        } catch (Throwable t) {
            Log.e(TAG, "Error when removing certificate files: " + t);
        }
        return false;
    }
}