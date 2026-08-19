package com.duosecurity.client;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Collection;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.TrustManager;
import javax.net.ssl.TrustManagerFactory;
import javax.net.ssl.X509TrustManager;

public class CertificateUtils {

  private static final String DEFAULT_BUNDLE_PATH = "duo-ca-certs/ca_certs.pem";

  /**
   * Create a TrustManagerFactory loaded with the default Duo CA bundle.
   *
   * @return TrustManagerFactory initialized with bundled Duo root CAs
   */
  public static TrustManagerFactory createDefaultTrustManagerFactory() {
    InputStream pemStream = CertificateUtils.class.getClassLoader()
        .getResourceAsStream(DEFAULT_BUNDLE_PATH);
    if (pemStream == null) {
      throw new IllegalStateException(
          "Cannot find bundled CA certificates at " + DEFAULT_BUNDLE_PATH);
    }
    try {
      return createTrustManagerFactory(pemStream);
    } finally {
      try {
        pemStream.close();
      } catch (IOException e) {
        // ignore close error
      }
    }
  }

  /**
   * Create a TrustManagerFactory from PEM certificate content.
   *
   * @param pemContent PEM-encoded certificates as a String
   * @return TrustManagerFactory initialized with the provided certificates
   */
  public static TrustManagerFactory createTrustManagerFactory(String pemContent) {
    InputStream stream = new ByteArrayInputStream(pemContent.getBytes(StandardCharsets.UTF_8));
    return createTrustManagerFactory(stream);
  }

  /**
   * Create a TrustManagerFactory from a PEM certificate InputStream.
   *
   * @param pemStream InputStream containing PEM-encoded certificates
   * @return TrustManagerFactory initialized with the provided certificates
   */
  public static TrustManagerFactory createTrustManagerFactory(InputStream pemStream) {
    try {
      CertificateFactory cf = CertificateFactory.getInstance("X.509");
      Collection<? extends Certificate> certs = cf.generateCertificates(pemStream);

      if (certs.isEmpty()) {
        throw new IllegalArgumentException("No certificates found in PEM input");
      }

      KeyStore keyStore = KeyStore.getInstance(KeyStore.getDefaultType());
      keyStore.load(null, null);

      int index = 0;
      for (Certificate cert : certs) {
        keyStore.setCertificateEntry("duo-ca-" + index, cert);
        index++;
      }

      TrustManagerFactory tmf = TrustManagerFactory.getInstance(
          TrustManagerFactory.getDefaultAlgorithm());
      tmf.init(keyStore);
      return tmf;
    } catch (CertificateException | KeyStoreException | NoSuchAlgorithmException
        | IOException e) {
      throw new IllegalStateException("Failed to initialize trust store", e);
    }
  }

  /**
   * Create an SSLSocketFactory from a TrustManagerFactory.
   *
   * @param tmf the TrustManagerFactory to use
   * @return SSLSocketFactory configured with the trust manager
   */
  public static SSLSocketFactory createSslSocketFactory(TrustManagerFactory tmf) {
    try {
      SSLContext sslContext = SSLContext.getInstance("TLS");
      sslContext.init(null, tmf.getTrustManagers(), null);
      return sslContext.getSocketFactory();
    } catch (Exception e) {
      throw new IllegalStateException("Failed to create SSLSocketFactory", e);
    }
  }

  /**
   * Extract the X509TrustManager from a TrustManagerFactory.
   *
   * @param tmf the TrustManagerFactory
   * @return the X509TrustManager
   */
  public static X509TrustManager getX509TrustManager(TrustManagerFactory tmf) {
    for (TrustManager tm : tmf.getTrustManagers()) {
      if (tm instanceof X509TrustManager) {
        return (X509TrustManager) tm;
      }
    }
    throw new IllegalStateException("No X509TrustManager found in TrustManagerFactory");
  }

  /**
   * Get a TrustManagerFactory initialized with the system default trust store.
   *
   * @return TrustManagerFactory using system cacerts
   */
  public static TrustManagerFactory getSystemTrustManagerFactory() {
    try {
      TrustManagerFactory tmf = TrustManagerFactory.getInstance(
          TrustManagerFactory.getDefaultAlgorithm());
      tmf.init((KeyStore) null);
      return tmf;
    } catch (NoSuchAlgorithmException | KeyStoreException e) {
      throw new IllegalStateException("Failed to initialize system trust store", e);
    }
  }
}
