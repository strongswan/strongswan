/*
 * Copyright © 2015 FancyFon Software Ltd.
 * All rights reserved.
 */
package org.strongswan.android.apiclient;

import android.os.Environment;
import android.util.Base64;
import com.google.inject.Inject;

import org.apache.commons.io.FileUtils;


import java.io.File;

/**
 * @author Marcin Waligórski <marcin.waligorski@fancyfon.com>
 */
public class CertificateReader {
    private static final String TAG = CertificateReader.class.getSimpleName();
    private static final String CA_PEM = "ca.pem";
    private static final String USER_P12 = "user.p12";

    @Inject
    Logger logger;

    public String getCaCertificate() {
        try {
            return getCertificateBase64String(Environment.getExternalStorageDirectory() + File.separator + CA_PEM);
        } catch ( Exception e) {
            logger.logAndToast(TAG, "Error when parsing Ca Certificate", e);
            return null;
        }
    }

    public String getUserCertificate() {
        try {
            return getCertificateBase64String(Environment.getExternalStorageDirectory() + File.separator + USER_P12);
        } catch ( Exception e) {
            logger.logAndToast(TAG, "Error when parsing user certificate", e);
            return null;
        }
    }

    //  Max bundle size is 1 MB, some checking later
    private String getCertificateBase64String(String  path) throws Exception {
        File file = new File(path);
        return Base64.encodeToString(FileUtils.readFileToByteArray(file),Base64.DEFAULT);
    }
}