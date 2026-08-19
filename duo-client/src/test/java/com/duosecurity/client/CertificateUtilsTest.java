package com.duosecurity.client;

import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.security.cert.X509Certificate;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.TrustManagerFactory;
import javax.net.ssl.X509TrustManager;
import org.junit.Test;

public class CertificateUtilsTest {

  @Test
  public void testCreateDefaultTrustManagerFactory() {
    TrustManagerFactory tmf = CertificateUtils.createDefaultTrustManagerFactory();
    assertNotNull("TrustManagerFactory should not be null", tmf);
  }

  @Test
  public void testDefaultBundleContainsCertificates() {
    TrustManagerFactory tmf = CertificateUtils.createDefaultTrustManagerFactory();
    X509TrustManager trustManager = CertificateUtils.getX509TrustManager(tmf);
    X509Certificate[] acceptedIssuers = trustManager.getAcceptedIssuers();
    assertTrue("Bundle should contain certificates", acceptedIssuers.length > 0);
  }

  @Test
  public void testCreateSslSocketFactory() {
    TrustManagerFactory tmf = CertificateUtils.createDefaultTrustManagerFactory();
    SSLSocketFactory factory = CertificateUtils.createSslSocketFactory(tmf);
    assertNotNull("SSLSocketFactory should not be null", factory);
  }

  @Test
  public void testGetX509TrustManager() {
    TrustManagerFactory tmf = CertificateUtils.createDefaultTrustManagerFactory();
    X509TrustManager trustManager = CertificateUtils.getX509TrustManager(tmf);
    assertNotNull("X509TrustManager should not be null", trustManager);
  }

  @Test
  public void testGetSystemTrustManagerFactory() {
    TrustManagerFactory tmf = CertificateUtils.getSystemTrustManagerFactory();
    assertNotNull("System TrustManagerFactory should not be null", tmf);
    X509TrustManager trustManager = CertificateUtils.getX509TrustManager(tmf);
    assertNotNull("System X509TrustManager should not be null", trustManager);
  }

  @Test(expected = IllegalArgumentException.class)
  public void testEmptyPemThrowsException() {
    InputStream emptyStream = new ByteArrayInputStream(
        "".getBytes(StandardCharsets.UTF_8));
    CertificateUtils.createTrustManagerFactory(emptyStream);
  }

  @Test(expected = IllegalStateException.class)
  public void testInvalidPemThrowsException() {
    InputStream invalidStream = new ByteArrayInputStream(
        "not a certificate".getBytes(StandardCharsets.UTF_8));
    CertificateUtils.createTrustManagerFactory(invalidStream);
  }
}
