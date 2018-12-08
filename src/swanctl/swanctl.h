/*
 * Copyright (C) 2014 Martin Willi
 * Copyright (C) 2014 revosec AG
 *
 * Copyright (C) 2016 Tobias Brunner
 * Copyright (C) 2015 Andreas Steffen
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

/**
 * @defgroup swanctl swanctl
 * @{
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <unistd.h>

#ifndef SWANCTL_H_
#define SWANCTL_H_

extern char *swanctl_dir;

/**
 * Configuration file for connections, etc.
 */
static inline char *swanctl_conf() {
  static char *path;
  if (path == NULL && asprintf(&path, "%s/swanctl.conf", swanctl_dir) == -1) {
    exit(1);
  }
  return path;
}

/**
 * Directory for X.509 end entity certs
 */
static inline char *swanctl_x509_dir() {
  static char *path;
  if (path == NULL && asprintf(&path, "%s/x509", swanctl_dir) == -1) {
    exit(1);
  }
  return path;
}

/**
 * Directory for X.509 CA certs
 */
static inline char *swanctl_x509ca_dir() {
  static char *path;
  if (path == NULL && asprintf(&path, "%s/x509ca", swanctl_dir) == -1) {
    exit(1);
  }
  return path;
}

/**
 * Directory for X.509 Attribute Authority certs
 */
static inline char *swanctl_x509aa_dir() {
  static char *path;
  if (path == NULL && asprintf(&path, "%s/x509aa", swanctl_dir) == -1) {
    exit(1);
  }
  return path;
}

/**
 * Directory for X.509 OCSP Signer certs
 */
static inline char *swanctl_x509ocsp_dir() {
  static char *path;
  if (path == NULL && asprintf(&path, "%s/x509ocsp", swanctl_dir) == -1) {
    exit(1);
  }
  return path;
}

/**
 * Directory for X.509 CRLs
 */
static inline char *swanctl_x509crl_dir() {
  static char *path;
  if (path == NULL && asprintf(&path, "%s/x509crl", swanctl_dir) == -1) {
    exit(1);
  }
  return path;
}

/**
 * Directory for X.509 Attribute certificates
 */
static inline char *swanctl_x509ac_dir() {
  static char *path;
  if (path == NULL && asprintf(&path, "%s/x509ac", swanctl_dir) == -1) {
    exit(1);
  }
  return path;
}

/**
 * Directory for raw public keys
 */
static inline char *swanctl_pubkey_dir() {
  static char *path;
  if (path == NULL && asprintf(&path, "%s/pubkey", swanctl_dir) == -1) {
    exit(1);
  }
  return path;
}

/**
 * Directory for private keys
 */
static inline char *swanctl_private_dir() {
  static char *path;
  if (path == NULL && asprintf(&path, "%s/private", swanctl_dir) == -1) {
    exit(1);
  }
  return path;
}

/**
 * Directory for RSA private keys
 */
static inline char *swanctl_rsa_dir() {
  static char *path;
  if (path == NULL && asprintf(&path, "%s/rsa", swanctl_dir) == -1) {
    exit(1);
  }
  return path;
}

/**
 * Directory for ECDSA private keys
 */
static inline char *swanctl_ecdsa_dir() {
  static char *path;
  if (path == NULL && asprintf(&path, "%s/ecdsa", swanctl_dir) == -1) {
    exit(1);
  }
  return path;
}

/**
 * Directory for BLISS private keys
 */
static inline char *swanctl_bliss_dir() {
  static char *path;
  if (path == NULL && asprintf(&path, "%s/bliss", swanctl_dir) == -1) {
    exit(1);
  }
  return path;
}

/**
 * Directory for PKCS#8 encoded private keys
 */
static inline char *swanctl_pkcs8_dir() {
  static char *path;
  if (path == NULL && asprintf(&path, "%s/pkcs8", swanctl_dir) == -1) {
    exit(1);
  }
  return path;
}

/**
 * Directory for PKCS#12 containers
 */
static inline char *swanctl_pkcs12_dir() {
  static char *path;
  if (path == NULL && asprintf(&path, "%s/pkcs12", swanctl_dir) == -1) {
    exit(1);
  }
  return path;
}

#endif /** SWANCTL_H_ @}*/
